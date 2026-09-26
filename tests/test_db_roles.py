import pytest

from pg_mcp_qauth.config import Settings
from pg_mcp_qauth.db import AccessError, Database


def make_db(role_map: dict[str, str], default_role: str = "") -> Database:
    settings = Settings(
        auth_issuer="https://issuer",
        jwks_uri="https://issuer/jwks",
        pg_database="db",
        pg_user="u",
        role_map_json=__import__("json").dumps(role_map),
        default_role=default_role,
        roles_claim="groups",
    )
    return Database(settings)


def claims(*groups: str) -> dict:
    return {"groups": list(groups), "email": "u@example.com"}


def test_single_group_maps_to_role():
    db = make_db({"analysts": "read_analyst"})
    assert db.resolve_role(claims("analysts")) == "read_analyst"


def test_precedence_follows_role_map_order_not_token_order():
    # ROLE_MAP declares marketing before analysts -> marketing wins even though
    # the token lists analysts first.
    db = make_db({"marketing": "read_marketing", "analysts": "read_analyst"})
    assert db.resolve_role(claims("analysts", "marketing")) == "read_marketing"


def test_falls_back_to_default_role():
    db = make_db({"analysts": "read_analyst"}, default_role="read_only")
    assert db.resolve_role(claims("unknown")) == "read_only"


def test_no_role_raises():
    db = make_db({"analysts": "read_analyst"})
    with pytest.raises(AccessError):
        db.resolve_role(claims("unknown"))


def test_invalid_role_identifier_rejected():
    db = make_db({"analysts": 'bad"role'})
    with pytest.raises(AccessError):
        db.resolve_role(claims("analysts"))
