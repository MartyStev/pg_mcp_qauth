"""Production-style ("боевые") end-to-end run against a REAL Keycloak AS.

Prerequisites (already running):
  - Keycloak at http://localhost:8081 with realm integration/keycloak/realm.json imported
    (client pg-mcp, users alice@eu / bob@us in group `analysts`, carol with no groups)
  - Postgres at 127.0.0.1:55432 with fixture integration/init.sql

The MCP server (OAuth resource server) is launched as a subprocess validating real
Keycloak-signed tokens via JWKS. Tokens are obtained through the real OAuth token
endpoint (direct grant). Verifies the full production auth path + PG isolation.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

KC = os.environ.get("IT_KC_URL", "http://localhost:8081")
REALM = "test"
CLIENT_ID = "pg-mcp"
TOKEN_URL = f"{KC}/realms/{REALM}/protocol/openid-connect/token"
PG_PORT = os.environ.get("IT_PG_PORT", "55432")

results: list[tuple[bool, str]] = []


def check(cond: bool, label: str) -> None:
    results.append((bool(cond), label))
    print(f"[{'PASS' if cond else 'FAIL'}] {label}")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get_token(username: str, password: str) -> str:
    data = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": CLIENT_ID,
        "username": username,
        "password": password,
        "scope": "openid email",
    }).encode()
    with urllib.request.urlopen(TOKEN_URL, data=data, timeout=10) as resp:
        return json.loads(resp.read().decode())["access_token"]


def decode(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def wait_port(host: str, port: int, timeout: float = 40.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def unwrap(res):
    for attr in ("structured_content", "data"):
        try:
            v = getattr(res, attr, None)
        except Exception:
            v = None
        if v is not None:
            return v
    return getattr(res, "content", res)


def _rows(payload):
    if isinstance(payload, dict):
        for key in ("result", "rows"):
            if key in payload and isinstance(payload[key], list):
                return payload[key]
        return [payload]
    if isinstance(payload, list):
        return payload
    return []


async def drive(url: str, token: str) -> set:
    from fastmcp import Client

    async with Client(url, auth=token) as client:
        listed = unwrap(await client.call_tool("list_tables", {}))
        names = {r.get("name") for r in _rows(listed)}
        check("orders" in names, "list_tables sees analytics.orders")
        check("vault" not in names, "list_tables hides secret.vault")

        rows = unwrap(await client.call_tool(
            "run_query", {"sql": "SELECT region, amount FROM analytics.orders ORDER BY amount"}))
        return {r.get("region") for r in _rows(rows)}


async def expect_error(url: str, token: str, tool: str, args: dict, label: str) -> None:
    from fastmcp import Client

    try:
        async with Client(url, auth=token) as client:
            await client.call_tool(tool, args)
        check(False, label + " (no error raised)")
    except Exception as e:
        check(True, f"{label} [{type(e).__name__}]")


def main() -> int:
    # 1. Real OAuth tokens from Keycloak.
    alice = get_token("alice", "alice-pass")
    bob = get_token("bob", "bob-pass")
    carol = get_token("carol", "carol-pass")
    a_claims = decode(alice)
    print(f"token alice: iss={a_claims.get('iss')} aud={a_claims.get('aud')} "
          f"email={a_claims.get('email')} groups={a_claims.get('groups')}")
    check(a_claims.get("aud") == "pg-mcp", "keycloak: token audience is pg-mcp")
    check(a_claims.get("groups") == ["analysts"], "keycloak: groups claim present")
    check(a_claims.get("email") == "alice@eu", "keycloak: email claim present")

    mcp_port = free_port()
    env = os.environ.copy()
    env.update({
        "AUTH_ISSUER": a_claims["iss"],
        "JWKS_URI": f"{a_claims['iss']}/protocol/openid-connect/certs",
        "REQUIRED_AUDIENCE": "pg-mcp",
        "ALGORITHMS": "RS256",
        "ROLES_CLAIM": "groups",
        "RLS_USER_CLAIM": "email",
        "ROLE_MAP_JSON": json.dumps({"analysts": "read_analyst"}),  # no DEFAULT_ROLE
        "PG_HOST": "127.0.0.1",
        "PG_PORT": PG_PORT,
        "PG_DATABASE": "analytics",
        "PG_USER": "mcp_gateway",
        "PG_PASSWORD": "mcp_pass",
        "MCP_HOST": "127.0.0.1",
        "MCP_PORT": str(mcp_port),
        "MCP_PATH": "/mcp",
        "MAX_ROWS": "100",
    })

    proc = subprocess.Popen(
        [sys.executable, "-m", "pg_mcp_qauth.server"],
        cwd=ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    url = f"http://127.0.0.1:{mcp_port}/mcp"

    try:
        if not wait_port("127.0.0.1", mcp_port, 45):
            print("SERVER FAILED TO START:\n", (proc.stdout.read() or "")[-3000:])
            return 2
        print(f"server up at {url}")

        import asyncio

        # health is public
        with urllib.request.urlopen(f"http://127.0.0.1:{mcp_port}/health", timeout=5) as r:
            check(r.status == 200, "health: /health public 200")

        alice_regions = asyncio.run(drive(url, alice))
        check(alice_regions == {"eu"}, f"RLS: alice@eu sees only eu (got {alice_regions})")

        bob_regions = asyncio.run(drive(url, bob))
        check(bob_regions == {"us"}, f"RLS: bob@us sees only us (got {bob_regions})")

        # carol has NO mapped group and there is no DEFAULT_ROLE -> authorization denied
        asyncio.run(expect_error(url, carol, "list_tables", {}, "authz: carol (no group) denied"))

        # guard + grant isolation under a real token
        asyncio.run(expect_error(url, alice, "run_query", {"sql": "DELETE FROM analytics.orders"}, "guard: DELETE rejected"))
        asyncio.run(expect_error(url, alice, "run_query", {"sql": "SELECT * FROM secret.vault"}, "grant: secret.vault denied"))
        asyncio.run(expect_error(url, alice, "describe_table", {"table_name": "secret.vault"}, "grant: describe_table secret.vault denied"))
        asyncio.run(expect_error(url, alice, "run_query", {"sql": "SELECT pg_sleep(5)"}, "guard: pg_sleep rejected"))

        # tampered signature must fail JWKS verification
        parts = alice.split(".")
        bad_sig = parts[0] + "." + parts[1] + "." + ("A" * len(parts[2]))
        asyncio.run(expect_error(url, bad_sig, "list_tables", {}, "auth: tampered signature rejected"))

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    passed = sum(1 for ok, _ in results if ok)
    print(f"\n==== {passed}/{len(results)} checks passed ====")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
