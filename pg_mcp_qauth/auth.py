from __future__ import annotations

from .config import Settings


def build_verifier(settings: Settings):
    """Create the FastMCP auth provider acting as the OAuth 2.1 resource server.

    Token verification is delegated to a `JWTVerifier` (JWKS signature + `iss`/`aud`/
    `exp`). It is wrapped in a `RemoteAuthProvider` because a bare `JWTVerifier` only
    emits the `401 + WWW-Authenticate` challenge but does NOT serve RFC 9728 protected
    resource metadata routes; `RemoteAuthProvider` additionally publishes
    `/.well-known/oauth-protected-resource<mcp-path>` pointing at the Authorization
    Server, which is what enables OAuth discovery in clients like VS Code / Claude Code.
    """
    from fastmcp.server.auth import RemoteAuthProvider
    from fastmcp.server.auth.providers.jwt import JWTVerifier

    algorithms = settings.algorithm_list
    scopes = [s for s in settings.required_scope.split() if s] if settings.required_scope else None
    # check() guarantees: exactly one pinned asymmetric algorithm and a non-empty
    # audience (empty audience would disable the `aud` claim check -> token passthrough).
    jwt_verifier = JWTVerifier(
        jwks_uri=settings.jwks_uri,
        issuer=settings.auth_issuer,
        audience=settings.required_audience,
        algorithm=algorithms[0],
        required_scopes=scopes,
        base_url=settings.mcp_base_url,
    )
    return RemoteAuthProvider(
        token_verifier=jwt_verifier,
        authorization_servers=[settings.auth_issuer],
        base_url=settings.mcp_base_url,
        scopes_supported=scopes,
    )


def current_claims() -> dict:
    """Return the JWT claims of the access token bound to the current request."""
    from fastmcp.server.dependencies import get_access_token

    token = get_access_token()
    if token is None:
        raise PermissionError("no authenticated access token in request context")
    claims = getattr(token, "claims", None)
    if not isinstance(claims, dict):
        raise PermissionError("access token carries no claims")
    return dict(claims)
