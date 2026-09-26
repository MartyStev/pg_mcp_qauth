# Contributing

Thanks for your interest in improving `pg_mcp_qauth`!

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # fill in values for local runs
```

## Running tests

Unit tests (no external services required):

```bash
pytest
```

### Integration tests (local JWKS, no Keycloak)

These spin up the real server, sign JWTs locally, and serve JWKS from a local endpoint.
They need a Postgres with the fixture loaded:

```bash
docker run -d --name pgmcp_test -e POSTGRES_DB=analytics \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -p 55432:5432 \
  -v "$PWD/integration/init.sql:/docker-entrypoint-initdb.d/init.sql:ro" postgres:16-alpine

IT_PG_PORT=55432 python integration/run_integration.py
docker rm -f pgmcp_test
```

### "Combat" tests (real Keycloak)

Full production-style OAuth flow against a real Authorization Server:

```bash
# 1. Postgres (as above) on :55432
# 2. Keycloak with the test realm:
docker run -d --name kc_test -p 8081:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v "$PWD/integration/keycloak/realm.json:/opt/keycloak/data/import/realm.json:ro" \
  quay.io/keycloak/keycloak:26.0 start-dev --import-realm

# wait until http://localhost:8081/realms/test returns 200, then:
IT_PG_PORT=55432 python integration/run_keycloak.py

docker rm -f pgmcp_test kc_test
```

> All credentials in `integration/` (Keycloak users, `mcp_pass`, etc.) are **test fixtures
> only**. Never reuse them in a real deployment.

> Third-party database dumps (DVD Rental, Chinook, Pagila, …) must **never be committed**.
> Download them to `/tmp` or another ignored path, and use the throwaway `pgmcp_sample`
> container described in the README ("Данные для ручных тестов") — it is not part of CI.

## Pull request guidelines

- Keep changes focused; add or update tests for behavior changes.
- Security-sensitive changes (auth, SQL guard, role resolution) must include tests and
  a note on the threat they address.
- Run `pytest` and, where relevant, the integration scripts before opening a PR.
- Run `ruff check pg_mcp_qauth tests integration` (CI enforces both).
- Follow the existing style (see `[tool.ruff]` in `pyproject.toml`).

## Reporting security issues

Do **not** open a public issue. See [SECURITY.md](SECURITY.md).
