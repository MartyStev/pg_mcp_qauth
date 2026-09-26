from __future__ import annotations

import re
from collections import Counter

import sqlglot
from sqlglot import exp
from sqlglot.tokens import TokenType

DIALECT = "postgres"

# A token whose text is pure symbols (no word chars) is an operator token:
# `@@`, `||`, `<->`, `::` ... Comparing by TokenType (not text) keeps equivalent
# spellings (e.g. `!=` re-rendered as `<>`) equal.
_PURE_SYMBOL = re.compile(r"[^\w\s]+")

# Structural punctuation: the serializer legitimately adds/drops redundant
# parens etc. without changing semantics; only real operators must round-trip.
_STRUCTURAL = {
    TokenType.L_PAREN,
    TokenType.R_PAREN,
    TokenType.COMMA,
    TokenType.DOT,
    TokenType.SEMICOLON,
    # `x::int` legitimately re-renders as `CAST(x AS int)` — same semantics.
    TokenType.DCOLON,
    # Keyword operators have symbolic SQL spellings (`!~~` == NOT LIKE, `~~` == LIKE,
    # `!~` == NOT `~`); sqlglot normalizes spelling but keeps the same AST node type.
    TokenType.NOT,
    TokenType.LIKE,
    TokenType.ILIKE,
}


def _operator_signature(sql: str) -> tuple[Counter, Counter]:
    """(operator-type multiset, `$`/`@`-parameter text multiset) for comparison.

    Types are compared for normalizable operators (`!=` vs `<>`); PARAMETER is
    compared by text because sqlglot maps ParadeDB's `@@@` to `@@` + a stray
    `@` that re-renders as the `$`-prefixed escape string `$'...'` — same token
    type, dangerous text change.
    """
    try:
        tokens = sqlglot.tokenize(sql, read=DIALECT)
    except sqlglot.errors.SqlglotError:
        return Counter(), Counter()
    ops: Counter = Counter()
    params: Counter = Counter()
    for t in tokens:
        if not _PURE_SYMBOL.fullmatch(t.text):
            continue
        if t.token_type is TokenType.PARAMETER:
            params[t.text] += 1
        elif t.token_type not in _STRUCTURAL:
            ops[t.token_type] += 1
    return ops, params

DEFAULT_BLOCKED_SCHEMAS = frozenset({"pg_catalog", "information_schema"})

# Node types that must never appear anywhere in the accepted AST.
FORBIDDEN_NODES: tuple[type[exp.Expression], ...] = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Drop,
    exp.Create,
    exp.Alter,
    exp.Merge,
    exp.Command,
    exp.Copy,
    exp.Into,
    exp.Lock,
    exp.TruncateTable,
    exp.Grant,
    exp.Set,
    exp.Transaction,
    exp.Commit,
    exp.Rollback,
)

# Functions with side effects, filesystem/network access, locking/DoS potential.
# Defense-in-depth only: the primary controls are the READ ONLY transaction, the
# non-superuser/non-owner PG_USER and table GRANTs (see SECURITY.md).
FORBIDDEN_FUNCTIONS = frozenset(
    {
        "pg_sleep",
        "pg_sleep_for",
        "pg_sleep_until",
        "pg_read_file",
        "pg_read_binary_file",
        "pg_write_file",
        "pg_stat_file",
        "pg_ls_dir",
        "pg_ls_tmpdir",
        "pg_ls_logdir",
        "pg_ls_waldir",
        "pg_ls_archive_statusdir",
        "lo_import",
        "lo_export",
        "lo_get",
        "lo_put",
        "lo_unlink",
        "dblink",
        "dblink_exec",
        "dblink_connect",
        "dblink_send_query",
        "copy",
        "set_config",
        "setval",
        "nextval",
        "pg_terminate_backend",
        "pg_cancel_backend",
        "pg_reload_conf",
        "pg_rotate_logfile",
        "pg_switch_wal",
        "pg_create_restore_point",
        "pg_advisory_lock",
        "pg_advisory_lock_shared",
        "pg_try_advisory_lock",
        "pg_try_advisory_lock_shared",
        "pg_advisory_unlock",
        "pg_advisory_unlock_shared",
        "query_to_xml",
        "query_to_xmlschema",
    }
)

ALLOWED_TOP_LEVEL = (exp.Select, exp.Union, exp.Intersect, exp.Except, exp.Subquery)


class GuardError(ValueError):
    """Raised when an SQL statement is rejected by the guard."""


def _iter_nodes(tree: exp.Expression):
    for item in tree.walk():
        yield item[0] if isinstance(item, tuple) else item


def _function_name(node: exp.Expression) -> str:
    name = getattr(node, "name", "") or ""
    if name:
        return name.lower()
    return type(node).__name__.lower()


def validate(
    sql: str,
    *,
    max_rows: int,
    allow_system_schemas: bool = False,
    blocked_schemas: frozenset[str] = DEFAULT_BLOCKED_SCHEMAS,
) -> str:
    """Validate an LLM-supplied query and return a safe, LIMIT-capped SQL string.

    Only a single read-only SELECT (optionally with CTEs / set operations) is allowed.
    Raises GuardError otherwise.
    """
    if not sql or not sql.strip():
        raise GuardError("empty query")

    try:
        parsed = sqlglot.parse(sql, read=DIALECT)
    except sqlglot.errors.SqlglotError as exc:
        raise GuardError(f"SQL parse error: {exc}") from exc

    statements = [p for p in parsed if p is not None]
    if len(statements) != 1:
        raise GuardError("exactly one statement is allowed")

    tree = statements[0]
    if not isinstance(tree, ALLOWED_TOP_LEVEL):
        raise GuardError("only SELECT queries are allowed")

    for node in _iter_nodes(tree):
        if isinstance(node, FORBIDDEN_NODES):
            raise GuardError(f"forbidden SQL operation: {type(node).__name__}")
        if isinstance(node, (exp.Anonymous, exp.Func)):
            fname = _function_name(node)
            if fname in FORBIDDEN_FUNCTIONS:
                raise GuardError(f"forbidden function: {fname}")
        if isinstance(node, exp.Table):
            schema = (node.db or "").lower()
            if schema in blocked_schemas and not allow_system_schemas:
                raise GuardError(f"access to system schema is not allowed: {schema}")

    rebuilt = _check_roundtrip(sql, tree)
    return _apply_limit(rebuilt, tree, max_rows)


def _check_roundtrip(sql: str, tree: exp.Expression) -> str:
    """Serialize the validated AST and refuse queries the parser corrupts.

    sqlglot maps some Postgres/extension operators onto wrong AST nodes (e.g.
    ParadeDB's @@@ becomes `@@` + a dropped `@` token). Execution always uses
    the re-serialized SQL, so a silent operator change would alter semantics —
    fail loudly instead.
    """
    try:
        rebuilt = tree.sql(dialect=DIALECT)
    except sqlglot.errors.SqlglotError as exc:
        raise GuardError(f"SQL re-render failed: {exc}") from exc
    raw_ops, raw_params = _operator_signature(sql)
    out_ops, out_params = _operator_signature(rebuilt)
    if raw_ops != out_ops or raw_params != out_params:
        changed = sorted(
            {tt.name for tt in (raw_ops - out_ops) + (out_ops - raw_ops)}
            | {f"PARAMETER({p!r})" for p in (raw_params - out_params) + (out_params - raw_params)}
        )
        raise GuardError(
            "query contains operators that cannot be round-tripped losslessly by the "
            f"parser (operator tokens differ: {changed}); rewrite without exotic operators"
        )
    return rebuilt


def _apply_limit(rebuilt: str, tree: exp.Expression, max_rows: int) -> str:
    if isinstance(tree, exp.Select) and tree.args.get("limit") is None:
        return f"{rebuilt} LIMIT {int(max_rows)}"
    return f"SELECT * FROM (\n{rebuilt}\n) AS _mcp_guard LIMIT {int(max_rows)}"
