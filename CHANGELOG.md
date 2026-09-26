# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-26

### Added
- RFC 9728 Protected Resource Metadata endpoints: the JWT verifier is wrapped in
  FastMCP's `RemoteAuthProvider`, so OAuth-capable clients (VS Code, Claude Code) can
  discover the Authorization Server from the `401` challenge and complete browser
  sign-in (PKCE) end-to-end. Verified against a real Keycloak 26.
- `pg-mcp-preview` CLI: dry-run resolution of a token into group → DB role → visible
  tables (`--check-db`), for debugging `ROLE_MAP_JSON` without running the server.
- CI: unit tests on Python 3.11–3.13, ruff, `pip-audit` job and a lockfile drift check.
- Keycloak "combat" integration run (`integration/run_keycloak.py`) with an importable
  test realm, and a `DVD Rental`-based manual-test sandbox recipe (ParadeDB + pg_search).

### Changed
- Auth config is hard-validated at startup: `REQUIRED_AUDIENCE` is mandatory and
  `ALGORITHMS` must be exactly one asymmetric algorithm (HS*/`none` rejected).
- Neutralized catalog-leaking database errors; removed global singletons in favor of
  explicit dependency wiring.
- Runtime dependencies are pinned via `requirements.lock` (used by Docker and CI).
- Documentation split: `README.md` (English) + `README.ru.md` (Russian).

## 0.1.0 — initial release

### Added
- Initial release: Postgres MCP server as an OAuth 2.1 resource server
  (JWKS validation, `SET LOCAL ROLE` + RLS three-tier access model, AST-based
  read-only SQL guard, audit logging, `/health`, non-root Docker image).

[Unreleased]: https://github.com/MartyStev/pg_mcp_qauth/commits/main
[0.2.0]: https://github.com/MartyStev/pg_mcp_qauth/releases/tag/v0.2.0
