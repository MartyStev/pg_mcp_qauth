import pytest

from pg_mcp_qauth.config import Settings
from pg_mcp_qauth.db import _jsonable
from pg_mcp_qauth.sql_guard import GuardError, validate

BASE = {
    "auth_issuer": "https://issuer",
    "jwks_uri": "https://issuer/jwks",
    "pg_database": "db",
    "pg_user": "u",
    "default_role": "read_only",
}


def make(**over) -> Settings:
    return Settings(**{**BASE, **over})


def test_check_accepts_valid_minimal_config():
    make(required_audience="pg-mcp").check()


def test_check_requires_audience():
    # Empty audience would disable the `aud` check -> token passthrough.
    with pytest.raises(ValueError, match="required_audience"):
        make(required_audience="").check()


@pytest.mark.parametrize("alg", ["HS256", "HS512", "none"])
def test_check_rejects_symmetric_or_none_algorithms(alg):
    with pytest.raises(ValueError, match="asymmetric"):
        make(required_audience="a", algorithms=alg).check()


def test_check_rejects_algorithm_list_verifier_only_uses_first():
    with pytest.raises(ValueError, match="exactly one"):
        make(required_audience="a", algorithms="RS256,RS512").check()


def test_role_map_json_must_be_object():
    s = make(required_audience="a", role_map_json='["not","an","object"]')
    with pytest.raises(TypeError, match="ROLE_MAP_JSON"):
        _ = s.role_map


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT pg_advisory_lock(1)",
        "SELECT pg_try_advisory_lock(42)",
        "SELECT pg_advisory_lock(1, 2)",
        "SELECT pg_catalog.pg_advisory_lock_shared(7)",
        "SELECT * FROM (SELECT pg_advisory_lock(1)) t",
    ],
)
def test_advisory_lock_functions_rejected(sql):
    with pytest.raises(GuardError):
        validate(sql, max_rows=10)


def test_advisory_unlock_functions_rejected():
    with pytest.raises(GuardError):
        validate("SELECT pg_advisory_unlock(1)", max_rows=10)


def test_bytea_serialised_as_base64():
    import base64

    assert _jsonable(b"\x00\xffab") == base64.b64encode(b"\x00\xffab").decode()
    assert _jsonable([memoryview(b"x")]) == ["eA=="]
