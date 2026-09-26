import pytest

from pg_mcp_qauth.sql_guard import GuardError, validate

MAX_ROWS = 100


def ok(sql: str) -> str:
    return validate(sql, max_rows=MAX_ROWS)


def test_plain_select_gets_limit():
    out = ok("SELECT id, name FROM users")
    assert "LIMIT" in out
    assert str(MAX_ROWS) in out


def test_cte_select_allowed():
    out = ok("WITH t AS (SELECT 1 AS x) SELECT x FROM t")
    assert "LIMIT" in out


def test_existing_limit_preserved_and_capped():
    out = ok("SELECT * FROM users ORDER BY id LIMIT 5000")
    # wrapped in an outer cap subquery
    assert "_mcp_guard" in out
    assert str(MAX_ROWS) in out


def test_set_operation_allowed():
    out = ok("SELECT id FROM a UNION SELECT id FROM b")
    assert "LIMIT" in out


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO users (id) VALUES (1)",
        "UPDATE users SET name='x'",
        "DELETE FROM users",
        "DROP TABLE users",
        "CREATE TABLE t (id int)",
        "ALTER TABLE users ADD COLUMN x int",
        "TRUNCATE users",
        "GRANT SELECT ON users TO public",
    ],
)
def test_dml_ddl_rejected(sql):
    with pytest.raises(GuardError):
        ok(sql)


def test_multiple_statements_rejected():
    with pytest.raises(GuardError):
        ok("SELECT 1; SELECT 2")


def test_select_then_dml_rejected():
    with pytest.raises(GuardError):
        ok("SELECT 1; DELETE FROM users")


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT pg_sleep(10)",
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT lo_import('/etc/passwd')",
        "SELECT dblink('host=evil', 'select 1')",
        "SELECT set_config('role', 'postgres', false)",
        "SELECT nextval('some_seq')",
    ],
)
def test_dangerous_functions_rejected(sql):
    with pytest.raises(GuardError):
        ok(sql)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT pg_sleep_for('10s')",
        "SELECT pg_sleep_until('2030-01-01')",
        "SELECT lo_get(1234)",
        "SELECT lo_put(1234, 'x')",
        "SELECT pg_ls_logdir()",
        "SELECT query_to_xml('select 1', true, false, '')",
    ],
)
def test_extended_dangerous_functions_rejected(sql):
    with pytest.raises(GuardError):
        ok(sql)


def test_select_into_rejected():
    with pytest.raises(GuardError):
        ok("SELECT * INTO new_table FROM users")


def test_locking_clause_rejected():
    with pytest.raises(GuardError):
        ok("SELECT * FROM users FOR UPDATE")
    with pytest.raises(GuardError):
        ok("SELECT * FROM users FOR SHARE")


def test_data_modifying_cte_rejected():
    with pytest.raises(GuardError):
        ok("WITH x AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM x")


def test_system_schema_blocked_by_default():
    with pytest.raises(GuardError):
        ok("SELECT * FROM pg_catalog.pg_roles")


def test_system_schema_allowed_when_enabled():
    out = validate(
        "SELECT * FROM pg_catalog.pg_tables",
        max_rows=MAX_ROWS,
        allow_system_schemas=True,
    )
    assert "LIMIT" in out


def test_empty_rejected():
    with pytest.raises(GuardError):
        ok("   ")


def test_garbage_rejected():
    with pytest.raises(GuardError):
        ok("not sql at all $$$")


# --- round-trip integrity ---------------------------------------------------


def test_paradedb_hammer_operator_rejected_not_silently_rewritten():
    # sqlglot maps `@@@` to `@@ $'...'` (wrong operator + invalid escape string).
    # The guard must refuse loudly instead of executing corrupted SQL.
    with pytest.raises(GuardError, match="round-tripped"):
        ok("SELECT t FROM film f WHERE f @@@ 'description:amazing'")


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM t WHERE meta @> '{\"a\":1}'::jsonb",
        "SELECT meta->'a'->>1 AS v FROM t",
        "SELECT 1 WHERE 'a'::tsvector @@ 'a'::tsquery",
        "SELECT * FROM t WHERE a ~ '^x' AND b !~~ 'y%'",
        "SELECT a || b AS c FROM t",
        "SELECT * FROM t WHERE x <-> y < 3",
        "SELECT * FROM t WHERE a <> 1 AND b != 2",
        "SELECT COUNT(DISTINCT a)::float / NULLIF(COUNT(*), 0) FROM t",
        "SELECT now() - INTERVAL '7 days' AS w",
    ],
)
def test_standard_symbolic_operators_survive(sql):
    ok(sql)
