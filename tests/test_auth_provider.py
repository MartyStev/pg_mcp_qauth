"""Resource-server provider wiring: RFC 9728 metadata + 401 challenge.

Regression guard: a bare JWTVerifier advertises `resource_metadata=` in the
401 challenge but never serves the metadata route itself (FastMCP 4.x only
creates those routes on RemoteAuthProvider), which silently breaks OAuth
discovery in clients like VS Code / Claude Code.
"""

import pytest
from starlette.testclient import TestClient

from pg_mcp_qauth.auth import build_verifier
from pg_mcp_qauth.config import Settings

BASE = {
    "auth_issuer": "http://localhost:8081/realms/test",
    "jwks_uri": "http://localhost:8081/realms/test/protocol/openid-connect/certs",
    "required_audience": "pg-mcp",
    "algorithms": "RS256",
    "roles_claim": "groups",
    "pg_database": "db",
    "pg_user": "u",
    "default_role": "read_only",
    "mcp_base_url": "http://localhost:8000",
}


def make(**over) -> Settings:
    return Settings(**{**BASE, **over})


@pytest.fixture()
def app():
    from fastmcp import FastMCP

    settings = make()
    settings.check()
    mcp = FastMCP(name="test", auth=build_verifier(settings))
    return mcp.http_app(path="/mcp")


def test_provider_is_remote_auth_wrapping_jwt_verifier():
    from fastmcp.server.auth import RemoteAuthProvider
    from fastmcp.server.auth.providers.jwt import JWTVerifier

    provider = build_verifier(make())
    assert isinstance(provider, RemoteAuthProvider)
    verifier = provider.token_verifier
    assert isinstance(verifier, JWTVerifier)
    # audience check must stay enabled (token passthrough protection)
    assert verifier.audience == "pg-mcp"


def test_protected_resource_metadata_served(app):
    client = TestClient(app)
    resp = client.get("/.well-known/oauth-protected-resource/mcp")
    assert resp.status_code == 200
    meta = resp.json()
    assert meta["resource"] == "http://localhost:8000/mcp"
    assert meta["authorization_servers"] == ["http://localhost:8081/realms/test"]


def test_metadata_url_matches_www_authenticate_challenge(app):
    client = TestClient(app)
    resp = client.post("/mcp")
    assert resp.status_code == 401
    challenge = resp.headers["www-authenticate"]
    assert 'resource_metadata="http://localhost:8000/.well-known/oauth-protected-resource/mcp"' in challenge
    # the advertised URL must actually resolve (the original bug: 404 here)
    url = challenge.split('resource_metadata="')[1].rstrip('"')
    assert client.get(url.replace("http://localhost:8000", "")).status_code == 200


def test_scopes_supported_propagated_when_required_scope_set():
    provider = build_verifier(make(required_scope="mcp:read"))
    assert provider.scopes_supported == ["mcp:read"]
