import json

import jwt
import pytest

from pg_mcp_qauth.config import Settings
from pg_mcp_qauth.db import AccessError
from pg_mcp_qauth.preview import preview


def make_settings(**over) -> Settings:
    base = {
        "auth_issuer": "https://issuer",
        "jwks_uri": "https://issuer/jwks",
        "required_audience": "pg-mcp",
        "pg_database": "db",
        "pg_user": "u",
        "pg_password": "p",
        "role_map_json": json.dumps({"analysts": "read_analyst", "hr": "read_hr"}),
        "default_role": "read_only",
    }
    return Settings(**{**base, **over})


def signed_token(claims: dict) -> str:
    # signature irrelevant for the preview (mapping debug only)
    return jwt.encode(claims, key="test-hmac-key-long-enough-32-bytes!!", algorithm="HS256")


def test_preview_maps_group_and_rls_identity():
    settings = make_settings()
    out = preview(settings, {"email": "a@b", "groups": ["analysts", "hr"]})
    assert out["db_role"] == "read_analyst"  # declaration order wins
    assert out["matched_group"] == "analysts"
    assert out["source"] == "role_map"
    assert out["rls_user_value"] == "a@b"


def test_preview_falls_back_to_default():
    settings = make_settings()
    out = preview(settings, {"sub": "x", "groups": ["nope"]})
    assert out["db_role"] == "read_only"
    assert out["source"] == "default_role"
    assert out["matched_group"] is None


def test_preview_raises_without_role():
    settings = make_settings(default_role="")
    with pytest.raises(AccessError):
        preview(settings, {"sub": "x", "groups": []})


def test_cli_accepts_positional_token(capsys):
    settings = make_settings()
    from pg_mcp_qauth import preview as mod

    tok = signed_token({"email": "e@x", "groups": ["hr"]})
    # monkeypatch settings loading to our test config
    mod.get_settings = lambda: settings  # type: ignore[assignment]
    assert mod.main([tok]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["db_role"] == "read_hr"
