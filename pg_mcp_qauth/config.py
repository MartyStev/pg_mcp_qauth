from __future__ import annotations

import json
from functools import lru_cache

from pydantic import PrivateAttr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_ASYMMETRIC_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    _role_map_cache: dict[str, str] | None = PrivateAttr(default=None)

    # MCP / OAuth resource server
    mcp_name: str = "pg_mcp_qauth"
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8000
    mcp_base_url: str = "http://localhost:8000"
    mcp_path: str = "/mcp"

    # Authorization server (Keycloak / Authentik)
    auth_issuer: str = ""
    jwks_uri: str = ""
    required_audience: str = ""
    required_scope: str = ""
    algorithms: str = "RS256"
    roles_claim: str = "groups"
    rls_user_claim: str = "email"

    # group -> postgres role mapping (JSON object), plus fallback role
    role_map_json: str = "{}"
    default_role: str = ""

    # Postgres
    pg_host: str = "localhost"
    pg_port: int = 5432
    pg_database: str = ""
    pg_user: str = ""
    pg_password: str = ""

    # Limits / pool
    max_rows: int = 1000
    statement_timeout_ms: int = 30000
    grant_cache_ttl: int = 60
    pool_min: int = 1
    pool_max: int = 10
    allow_system_schemas: bool = False

    @field_validator("mcp_path")
    @classmethod
    def _normalize_path(cls, v: str) -> str:
        return v if v.startswith("/") else "/" + v

    @property
    def role_map(self) -> dict[str, str]:
        if self._role_map_cache is not None:
            return self._role_map_cache
        try:
            data = json.loads(self.role_map_json or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError(f"ROLE_MAP_JSON is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise TypeError("ROLE_MAP_JSON must be a JSON object {group: db_role}")
        self._role_map_cache = {str(k): str(v) for k, v in data.items()}
        return self._role_map_cache

    @property
    def algorithm_list(self) -> list[str]:
        return [a.strip() for a in self.algorithms.split(",") if a.strip()]

    def check(self) -> None:
        missing = [
            name
            for name in ("auth_issuer", "jwks_uri", "required_audience", "pg_database", "pg_user")
            if not getattr(self, name)
        ]
        if missing:
            raise ValueError(f"Missing required settings: {', '.join(missing)}")
        algs = self.algorithm_list
        # Only asymmetric algorithms are accepted: an HS* setting would let an
        # attacker self-sign with public JWKS material. build_verifier pins the
        # verifier to algs[0]; extra entries are ignored, so warn instead of
        # silently accepting a misleading list.
        bad = [a for a in algs if a not in _ASYMMETRIC_ALGORITHMS]
        if bad:
            raise ValueError(
                f"ALGORITHMS must be asymmetric (one of {sorted(_ASYMMETRIC_ALGORITHMS)}); got: {', '.join(bad)}"
            )
        if not algs:
            raise ValueError("ALGORITHMS must specify at least one signing algorithm")
        if len(algs) > 1:
            raise ValueError(
                "ALGORITHMS must contain exactly one pinned algorithm "
                f"(the verifier uses the first); got: {', '.join(algs)}"
            )
        if not self.role_map and not self.default_role:
            raise ValueError(
                "Either ROLE_MAP_JSON or DEFAULT_ROLE must be configured to resolve a DB role"
            )
        if self.max_rows <= 0:
            raise ValueError("MAX_ROWS must be positive")
        if self.statement_timeout_ms <= 0:
            raise ValueError("STATEMENT_TIMEOUT_MS must be positive")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
