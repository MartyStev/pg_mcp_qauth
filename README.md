# pg_mcp_qauth

[![CI](https://github.com/MartyStev/pg_mcp_qauth/actions/workflows/ci.yml/badge.svg)](https://github.com/MartyStev/pg_mcp_qauth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

A Postgres **MCP server** (Model Context Protocol) with OAuth 2.1 authorization for
Claude Code, VS Code and any other MCP client. The server acts as an **OAuth Resource
Server**: it validates JWTs issued by an external **Authorization Server** (Keycloak /
Authentik) and executes only safe read-only queries against PostgreSQL, with privileges
isolated by database roles and Row Level Security.

> **Status:** beta. Verified end-to-end against a real Keycloak 26 + Postgres 16,
> including browser-based OAuth (PKCE) flows from VS Code.
>
> **Features:** OAuth 2.1 resource server (RFC 9728) · multi-provider login via AS
> brokering (Google / Entra ID / AD / Okta / GitHub) · three-tier access model
> (schema → table → row/RLS) · AST-based SQL guard · audit logging · health endpoint ·
> non-root Docker image.

🇷🇺 Русская версия документации: [README.ru.md](README.ru.md)

## Architecture

- **MCP client** (Claude Code, VS Code, …) — an OAuth 2.1 client: obtains an access
  token from the Authorization Server using PKCE.
- **Keycloak / Authentik** — the single Authorization Server and identity broker.
  Multi-provider login (Google, Microsoft Entra ID, on-prem AD, Okta, GitHub, …) is
  configured via identity brokering on the AS side; the server code always validates
  **one issuer**.
- **pg_mcp_qauth** — Resource Server (FastMCP, Streamable HTTP): serves RFC 9728
  Protected Resource Metadata, returns `401 + WWW-Authenticate` without a token, and
  validates signature / `iss` / `aud` / `exp` via JWKS.
- **PostgreSQL** — every query runs in a `READ ONLY` transaction under
  `SET LOCAL ROLE <role>` with a session GUC for RLS.

```
MCP client --(OAuth PKCE)--> Keycloak/Authentik --(JWT)--> pg_mcp_qauth --> Postgres
                                 |  brokering
                                 +-> Google / Entra ID / AD / Okta / GitHub ...
```

## Access model (three tiers)

| Tier    | Mechanism                      | Who configures |
|---------|--------------------------------|----------------|
| Schema  | `GRANT USAGE ON SCHEMA`        | DBA            |
| Table   | `GRANT SELECT` (or on views)   | DBA            |
| Row     | RLS driven by a session GUC    | DBA            |

JWT group claims (`ROLES_CLAIM`) are mapped to a **DB role** through `ROLE_MAP_JSON`
(otherwise `DEFAULT_ROLE` applies). If a user belongs to several mapped groups,
**precedence follows the declaration order of keys** in `ROLE_MAP_JSON` (first match
wins), not the order of groups in the token. The role decides *which tables are
visible*; RLS decides *which rows a specific user can see*.

> **Keycloak:** roles live in nested claims (`realm_access.roles` /
> `resource_access.<client>.roles`) by default. The server reads a **flat** claim, so
> configure a protocol mapper that emits groups/roles into a flat claim (e.g.
> `groups`) and point `ROLES_CLAIM` at it.

`list_tables`, `describe_table` and `run_query` all execute under `SET LOCAL ROLE` and
additionally check `has_table_privilege(..., 'SELECT')` — the structure of tables the
role cannot access is never disclosed.

### DBA runbook (example)

```sql
-- 1. Pool login user: NOT a superuser, NOT the table owner.
CREATE ROLE mcp_gateway LOGIN PASSWORD 'change-me';

-- 2. Privilege-bearing roles.
CREATE ROLE read_analyst NOLOGIN;
CREATE ROLE read_marketing NOLOGIN;

-- 3. mcp_gateway must be able to SET ROLE to the target roles.
GRANT read_analyst, read_marketing TO mcp_gateway;

-- 4. Schema / tables.
GRANT USAGE ON SCHEMA analytics TO read_analyst;
GRANT SELECT ON ALL TABLES IN SCHEMA analytics TO read_analyst;
ALTER DEFAULT PRIVILEGES IN SCHEMA analytics GRANT SELECT ON TABLES TO read_analyst;

-- 5. Row Level Security driven by a session variable the MCP server sets.
ALTER TABLE analytics.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE analytics.orders FORCE ROW LEVEL SECURITY;
CREATE POLICY orders_by_region ON analytics.orders
  USING (region = current_setting('app.user_email', true));
```

> `current_setting('app.user_email', true)` / `app.groups` are set by the server via
> `set_config(..., true)` inside the transaction and never leak into pooled connections.

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"        # or: pip install -r requirements.lock for exact versions
cp .env.example .env   # fill in values
python -m pg_mcp_qauth.server
```

Docker (installs runtime deps from the pinned `requirements.lock`;
regenerate with `pip-compile pyproject.toml -o requirements.lock --strip-extras`):

```bash
docker build -t pg_mcp_qauth .
docker run --env-file .env -p 8000:8000 pg_mcp_qauth
```

## Configuration

See `.env.example`. Key parameters:

- `AUTH_ISSUER`, `JWKS_URI`, `REQUIRED_AUDIENCE`, `ALGORITHMS` — token validation.
  `REQUIRED_AUDIENCE` is mandatory to prevent token passthrough.
- `ROLES_CLAIM`, `RLS_USER_CLAIM` — which JWT claims to read.
- `ROLE_MAP_JSON`, `DEFAULT_ROLE` — group → DB role mapping.
- `PG_*` — database connection (`PG_USER` requirements: see the runbook above).
- `MAX_ROWS`, `STATEMENT_TIMEOUT_MS`, `POOL_*`, `ALLOW_SYSTEM_SCHEMAS`.

Auth configuration is hard-validated at startup (`Settings.check()`):
`REQUIRED_AUDIENCE` is required (an unchecked `aud` claim enables token passthrough)
and `ALGORITHMS` must be exactly one asymmetric algorithm (HS*/`none` are rejected).
`MCP_BASE_URL` participates in RFC 9728 resource metadata — behind a reverse proxy, set
the externally reachable URL. `/health` executes a real `SELECT 1` (503 when the DB is
down).

## Supported Authorization Servers

The server validates exactly **one issuer** — any OAuth 2.1 / OIDC Authorization
Server that can meet these requirements works:

- JWKS endpoint with an **asymmetric** signing algorithm (RS*/ES*/PS*/EdDSA, pinned in
  `ALGORITHMS`);
- access tokens with a stable `aud` matching `REQUIRED_AUDIENCE`;
- a **flat** claim carrying user groups/roles (via protocol mappers / claims policies)
  for `ROLES_CLAIM`, and the identity claim used for RLS (`RLS_USER_CLAIM`).

| Setup | Examples | Notes |
|-------|----------|-------|
| Self-hosted AS (recommended) | Keycloak, Authentik, Zitadel | full control over mappers; identity brokering gives social/corporate logins |
| Cloud AS directly | Okta, Auth0, Microsoft Entra ID | Entra: configure `groups`/app-roles via claims policy; pin the app `aud` |
| Logins via AS brokering | Google, GitHub, Microsoft accounts, AD FS / on-prem AD, any OIDC/SAML | users authenticate upstream; your AS remains the single issuer |
| Not usable directly | bare "Sign in with Google" | Google ID tokens lack groups and custom `aud` — broker them through your AS |

```
users -> your AS (Keycloak/Authentik/…) --brokering--> Google / Microsoft / GitHub / AD / …
                |
                +-- issues JWT (single issuer) --> pg_mcp_qauth
```

## Connecting MCP clients

Because the server publishes RFC 9728 metadata (advertised in the `401`
`WWW-Authenticate: Bearer resource_metadata="…"` challenge), OAuth-capable clients
discover the Authorization Server automatically and open the browser sign-in themselves.

**VS Code** (`.vscode/mcp.json`) — browser sign-in via your Keycloak realm:

```json
{
  "servers": {
    "pg_mcp_qauth": {
      "type": "http",
      "url": "http://localhost:8000/mcp",
      "oauth": { "clientId": "pg-mcp" }
    }
  }
}
```

Set `standardFlowEnabled` on the client and configure its redirect URIs to whatever the
client uses (VS Code/Claude Code register `http://127.0.0.1:<port>/callback` style URIs;
a `*` pattern is acceptable for local testing only).

**Claude Code** — the same OAuth discovery, or a static token for scripted/CI use:

```bash
claude mcp add --transport http pgmcp https://mcp.example.com/mcp \
  --header "Authorization: Bearer $ACCESS_TOKEN"
```

> **DCR caveat:** with Dynamic Client Registration the AS issues tokens for a
> *dynamically created client*, which usually lacks your audience/group protocol
> mappers. Pin the client with `oauth.clientId` (or your AS's equivalent) so issued
> tokens keep the claims the access model depends on.

## Security (SQL guard)

`run_query` accepts a single `SELECT` only (including `WITH … SELECT` and set
operations), validated by parsing into an AST (`sqlglot`, postgres dialect):

- DML/DDL (`INSERT`/`UPDATE`/`DELETE`/`CREATE`/`ALTER`/`DROP`/`TRUNCATE`/`GRANT`),
  multi-statement input, `SET`/`COMMIT` etc. are rejected;
- a denylist of dangerous functions is blocked (`pg_sleep`, `pg_read_file`, `lo_import`,
  `dblink`, `set_config`, `nextval`, advisory locks `pg_advisory_lock`/`pg_try_advisory_lock`, …);
- system schemas (`pg_catalog`, `information_schema`) are closed unless explicitly allowed;
- results are capped at `MAX_ROWS` (auto-`LIMIT`);
- **round-trip integrity**: since the *re-serialized* SQL is what executes, the guard
  compares the operator-token multiset before/after re-serialization and explicitly
  rejects queries the parser could silently mangle (e.g. the ParadeDB `@@@` operator,
  which sqlglot turns into `@@ $'..'`). Plain `@@ to_tsquery(...)` works fine.

### Defense in depth (recommended for the runbook)

The function denylist is incomplete by nature, so the primary guarantees come from
Postgres itself: `PG_USER` is neither superuser nor table owner, transactions are
`READ ONLY`, target roles have no `CREATE`. Additionally revoke execution of dangerous
functions from `PUBLIC`:

```sql
REVOKE EXECUTE ON FUNCTION
    pg_sleep(float8), pg_sleep_for(interval), pg_sleep_until(timestamptz),
    pg_read_file(text), pg_ls_dir(text), lo_import(text), lo_export(oid, text)
FROM PUBLIC;
```

## MCP tools

- `list_tables()` — tables/views visible to the current role.
- `describe_table(table_name)` — columns, types, nullability, comments (catalog read).
- `run_query(sql)` — safe read-only query.

### Dry-run permission preview (no server needed)

`pg-mcp-preview` shows what a token resolves to on the access side: the matched group,
the DB role, the mapping source and — with `--check-db` — the real list of visible
tables under that role. JWT signatures are **not** verified: this debugs
`ROLE_MAP_JSON`, not auth.

```bash
echo "$ACCESS_TOKEN" | pg-mcp-preview -            # mapping only
echo "$ACCESS_TOKEN" | pg-mcp-preview - --check-db # + visible tables from the DB
```

## Testing

Unit tests for the SQL guard and config validation (no DB required):

```bash
pytest
```

Integration end-to-end run (real Postgres + locally signed JWTs + local JWKS + a live
MCP client over Streamable HTTP):

```bash
docker run -d --name pgmcp_test -e POSTGRES_DB=analytics \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -p 55432:5432 \
  -v "$PWD/integration/init.sql:/docker-entrypoint-initdb.d/init.sql:ro" postgres:16-alpine
IT_PG_PORT=55432 python integration/run_integration.py
docker rm -f pgmcp_test
```

Exercised: JWT authorization (iss/aud/signature via JWKS), group→role mapping and
`SET LOCAL ROLE` (schema/table isolation via GRANTs), per-row RLS (same role, different
users → different rows), DML and system-schema rejection, catalog reads. For production
it is enough to point `AUTH_ISSUER`/`JWKS_URI` at a real Keycloak/Authentik — no code
changes.

A "combat" run against a **real Keycloak** (actual OAuth token endpoint, JWKS, groups,
audience mapper) lives in `integration/run_keycloak.py`; see [CONTRIBUTING.md](CONTRIBUTING.md).

### Manual-test data: DVD Rental + pg_search

The integration fixture (`integration/init.sql`) is synthetic (4 rows), so for join /
aggregate / full-text-search experiments a real dataset is more convenient. No auth
plumbing (Keycloak, roles, RLS) is needed here — just Postgres with data.

```bash
curl -sL -o /tmp/dvdrental.tar \
  https://raw.githubusercontent.com/ferry8/dvdrental.tar/master/dvdrental.tar   # ~2.8 MB, pg_dump -F c

docker run -d --name pgmcp_sample -e POSTGRES_DB=analytics \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -p 55432:5432 \
  paradedb/paradedb:0.25.10-pg17

docker exec -i pgmcp_sample pg_restore -U postgres -d analytics --no-owner < /tmp/dvdrental.tar
docker rm -f pgmcp_sample   # remove when done (data lives in an anonymous volume)
```

Connect: `localhost:55432`, database `analytics`, `postgres`/`postgres`. The image ships
`pg_search` (BM25/Tantivy, extension pre-installed):

```sql
CREATE INDEX film_bm25 ON film USING bm25 (film_id, title, description)
WITH (key_field='film_id',
      text_fields='{"title":{"tokenizer":{"type":"icu"}},"description":{"tokenizer":{"type":"icu"}}}');

-- Index search + JOIN with a regular filter (1000 films, 16k rentals):
SELECT f.film_id, f.title, c.name AS category, paradedb.score(f.film_id) AS score
FROM film f
JOIN film_category fc USING (film_id)
JOIN category c USING (category_id)
WHERE f @@@ 'description:documentary'
  AND f.release_year = 2006
ORDER BY score DESC
LIMIT 10;
```

> **`run_query` limitation:** the `@@@` operator does not survive sqlglot
> re-serialization and is explicitly rejected by the guard. In MCP queries use standard
> FTS `@@` (e.g. `fulltext @@ to_tsquery('english','amazing')`); `@@@`/BM25 remain
> available when talking to the database directly (psql).

## Installing as a package

```bash
pip install .            # or: pip install -e ".[dev]" for development
pg-mcp-qauth             # console script (equivalent to python -m pg_mcp_qauth.server)
```

## Notes

- Verified on **FastMCP 4.x** (`RemoteAuthProvider` wrapping
  `fastmcp.server.auth.providers.jwt.JWTVerifier`,
  `fastmcp.server.dependencies.get_access_token`, `http` transport). Important: a bare
  `JWTVerifier` does not publish RFC 9728 metadata routes — only the `RemoteAuthProvider`
  wrapper does.
- Dynamic Client Registration (RFC 7591) is deprecated in the latest MCP spec and is
  not the primary onboarding mechanism here.

## Security

Do **not** report vulnerabilities via public issues — see [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — setup, running tests (unit / integration /
Keycloak), PR requirements.

## License

[MIT](LICENSE) © 2026 martystev
