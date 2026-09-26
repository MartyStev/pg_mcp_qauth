from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import time
from typing import Any

import asyncpg

from .config import Settings

logger = logging.getLogger("pg_mcp_qauth")

IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_QUALIFIED_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(?:\.([A-Za-z_][A-Za-z0-9_]*))?$")
_ROLE_CACHE_MAX = 1024

LIST_TABLES_SQL = """
    SELECT n.nspname AS schema, c.relname AS name,
           CASE c.relkind
                WHEN 'r' THEN 'table'
                WHEN 'p' THEN 'table'
                WHEN 'v' THEN 'view'
                WHEN 'm' THEN 'materialized_view'
                WHEN 'f' THEN 'foreign_table'
           END AS kind,
           obj_description(c.oid) AS comment
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND has_table_privilege(c.oid, 'SELECT')
      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
    ORDER BY 1, 2
"""


class AccessError(Exception):
    """Raised when a request cannot be mapped to a valid DB role or access is denied."""


# Raw Postgres errors can echo catalog facts (role/table names) into the MCP
# client. These classes get a neutral message; the full error stays in the
# server-side audit log. Unknown errors pass through so agents can self-correct.
_NEUTRAL_PG_ERRORS: dict[type[BaseException], str] = {
    asyncpg.exceptions.InsufficientPrivilegeError:
        "not enough privileges for this operation under the current role",
    asyncpg.exceptions.UndefinedTableError:
        "table not found or not accessible under the current role",
    asyncpg.exceptions.UndefinedColumnError:
        "column not found or not accessible under the current role",
    asyncpg.exceptions.UndefinedFunctionError:
        "function not found or not executable under the current role",
    asyncpg.exceptions.UndefinedObjectError:
        "database object not found or not accessible under the current role",
    asyncpg.exceptions.InvalidCatalogNameError:
        "database unavailable (check PG_DATABASE configuration)",
}


def _neutralize(exc: Exception) -> Exception:
    for base in type(exc).__mro__:
        if base in _NEUTRAL_PG_ERRORS:
            return AccessError(_NEUTRAL_PG_ERRORS[base])
    return exc


class Database:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._pool: asyncpg.Pool | None = None
        self._lock = asyncio.Lock()
        self._role_cache: dict[str, tuple[str, float]] = {}

    async def ensure_init(self) -> None:
        if self._pool is not None:
            return
        async with self._lock:
            if self._pool is None:
                s = self.settings
                self._pool = await asyncpg.create_pool(
                    host=s.pg_host,
                    port=s.pg_port,
                    database=s.pg_database,
                    user=s.pg_user,
                    password=s.pg_password,
                    min_size=s.pool_min,
                    max_size=s.pool_max,
                    timeout=10,
                )

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    @property
    def pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("database pool is not initialized")
        return self._pool

    async def health(self) -> bool:
        """True only when the pool exists AND Postgres actually answers a query."""
        pool = self._pool
        if pool is None or pool.is_closing():
            return False
        try:
            async with pool.acquire(timeout=2) as conn:
                await asyncio.wait_for(conn.fetchval("SELECT 1"), timeout=2)
        except Exception:  # noqa: BLE001 - any failure means "not healthy"
            return False
        return True

    # --- role resolution -------------------------------------------------

    def _groups(self, claims: dict[str, Any]) -> list[str]:
        return groups_for(self.settings, claims)

    def resolve_role(self, claims: dict[str, Any]) -> str:
        groups = self._groups(claims)
        cache_key = "\x00".join(sorted(groups))
        now = time.monotonic()
        cached = self._role_cache.get(cache_key)
        if cached and cached[1] > now:
            return cached[0]

        role, _matched = resolve_role_for(self.settings, groups)

        if len(self._role_cache) >= _ROLE_CACHE_MAX:
            self._prune_role_cache(now)
        self._role_cache[cache_key] = (role, now + self.settings.grant_cache_ttl)
        return role

    def _prune_role_cache(self, now: float) -> None:
        expired = [k for k, (_, exp_ts) in self._role_cache.items() if exp_ts <= now]
        for k in expired:
            del self._role_cache[k]
        if len(self._role_cache) >= _ROLE_CACHE_MAX:
            # Still saturated with unexpired entries; drop all rather than grow unbounded.
            self._role_cache.clear()

    # --- transactional helpers -------------------------------------------

    async def _enter_role_context(
        self, conn: asyncpg.Connection, role: str, claims: dict[str, Any]
    ) -> None:
        # `role` is validated as an identifier by resolve_role(); still quote it.
        await conn.execute(f'SET LOCAL ROLE "{role}"')
        user_value = str(
            claims.get(self.settings.rls_user_claim) or claims.get("sub") or ""
        )
        groups_value = json.dumps(self._groups(claims))
        await conn.execute("SELECT set_config('app.user_email', $1, true)", user_value)
        await conn.execute("SELECT set_config('app.groups', $1, true)", groups_value)
        await conn.execute(
            f"SET LOCAL statement_timeout = {int(self.settings.statement_timeout_ms)}"
        )

    # --- tools -----------------------------------------------------------

    async def _read_txn(self, role: str, claims: dict[str, Any], label: str, fn, *, detail: str = ""):
        """Run fn(conn) inside a READ ONLY txn scoped to `role`; emit audit lines."""
        who = principal(claims)
        started = time.monotonic()
        try:
            async with self.pool.acquire() as conn:
                tx = conn.transaction(readonly=True)
                await tx.start()
                try:
                    await self._enter_role_context(conn, role, claims)
                    result = await fn(conn)
                    await tx.commit()
                except BaseException:
                    await tx.rollback()
                    raise
        except Exception as exc:
            logger.warning(
                "audit %s DENIED principal=%s role=%s%s err=%r",
                label, who, role, f" {detail}" if detail else "", exc,
            )
            raise _neutralize(exc) from exc
        elapsed_ms = int((time.monotonic() - started) * 1000)
        count = len(result) if isinstance(result, (list, dict)) else 0
        logger.info(
            "audit %s OK principal=%s role=%s%s rows=%d ms=%d",
            label, who, role, f" {detail}" if detail else "", count, elapsed_ms,
        )
        return result

    async def run_query(self, sql: str, claims: dict[str, Any]) -> list[dict[str, Any]]:
        role = self.resolve_role(claims)
        normalized = " ".join(sql.split())
        rows = await self._read_txn(
            role, claims, "run_query", lambda conn: conn.fetch(sql),
            detail=f"sql={normalized[:500]!r}",
        )
        return [_row_to_dict(r) for r in rows]

    async def list_tables(self, claims: dict[str, Any]) -> list[dict[str, Any]]:
        role = self.resolve_role(claims)
        rows = await self._read_txn(
            role, claims, "list_tables", lambda conn: conn.fetch(LIST_TABLES_SQL)
        )
        return [_row_to_dict(r) for r in rows]

    async def describe_table(
        self, table_name: str, claims: dict[str, Any]
    ) -> dict[str, Any]:
        role = self.resolve_role(claims)
        schema, name = _split_table_name(table_name)
        qualified = f'"{schema}"."{name}"' if schema else f'"{name}"'

        columns_sql = """
            SELECT a.attname AS column,
                   format_type(a.atttypid, a.atttypmod) AS type,
                   a.attnotnull AS not_null,
                   col_description(a.attrelid, a.attnum) AS comment
            FROM pg_attribute a
            WHERE a.attrelid = to_regclass($1)
              AND a.attnum > 0
              AND NOT a.attisdropped
            ORDER BY a.attnum
        """
        meta_sql = """
            SELECT obj_description(to_regclass($1)) AS comment,
                   (to_regclass($1) IS NULL) AS missing,
                   (to_regclass($1) IS NOT NULL
                    AND has_table_privilege(to_regclass($1), 'SELECT')) AS can_select
        """
        async def _fetch_meta_and_columns(conn: asyncpg.Connection):
            meta = await conn.fetchrow(meta_sql, qualified)
            columns = await conn.fetch(columns_sql, qualified)
            if meta is None or meta["missing"] or not meta["can_select"]:
                raise AccessError(f"table not found or not accessible to role: {table_name}")
            return meta, columns

        meta, columns = await self._read_txn(
            role, claims, "describe_table", _fetch_meta_and_columns,
            detail=f"table={table_name!r}",
        )
        return {
            "table": table_name,
            "comment": meta["comment"],
            "columns": [_row_to_dict(c) for c in columns],
        }


def groups_for(settings: Settings, claims: dict[str, Any]) -> list[str]:
    raw = claims.get(settings.roles_claim) or []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, (list, tuple, set)):
        return [str(x) for x in raw]
    return []


def resolve_role_for(settings: Settings, groups: list[str]) -> tuple[str, str]:
    """Map token groups to a DB role. Returns (role, matched_group).

    Precedence follows ROLE_MAP declaration order, not token claim order,
    so a user in several mapped groups resolves deterministically.
    """
    group_set = set(groups)
    matched, role = next(((g, r) for g, r in settings.role_map.items() if g in group_set), ("", ""))
    if not role:
        role, matched = settings.default_role, ""
    if not role:
        raise AccessError("no DB role mapped for the authenticated principal")
    if not IDENT_RE.match(role):
        raise AccessError(f"resolved DB role is not a valid identifier: {role!r}")
    return role, matched


def principal(claims: dict[str, Any]) -> str:
    return str(claims.get("sub") or claims.get("email") or "unknown")


def _split_table_name(table_name: str) -> tuple[str | None, str]:
    if not table_name or not isinstance(table_name, str):
        raise AccessError("table_name must be a non-empty string")
    match = _QUALIFIED_RE.match(table_name.strip())
    if not match:
        raise AccessError(f"invalid table identifier: {table_name!r}")
    first, second = match.group(1), match.group(2)
    if second is None:
        return None, first
    return first, second


def _row_to_dict(row: asyncpg.Record) -> dict[str, Any]:
    return {k: _jsonable(v) for k, v in dict(row).items()}


def _jsonable(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        # base64 keeps bytea round-trippable (str(b'..') was an unparseable repr)
        return base64.b64encode(bytes(value)).decode()
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    return str(value)
