"""End-to-end integration run.

Spins up a local JWKS endpoint, launches the real pg_mcp_qauth FastMCP server as a
subprocess (OAuth resource server), and drives it with a real MCP client over
Streamable HTTP using locally-signed JWTs.

Verifies:
  - JWT auth (issuer/audience/signature via JWKS)
  - group -> DB role mapping and SET LOCAL ROLE (schema/table GRANT isolation)
  - RLS per-user row filtering (same role, different identity -> different rows)
  - SQL guard rejects DML and system schemas
  - describe_table / list_tables read from catalog

Requires a running Postgres (see integration/README or docker compose) whose init
fixture is integration/init.sql.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

ISSUER = "https://test.local/realms/test"
AUDIENCE = "pg-mcp"
KID = "testkey"

PG_HOST = os.environ.get("IT_PG_HOST", "127.0.0.1")
PG_PORT = os.environ.get("IT_PG_PORT", "55432")

results: list[tuple[bool, str]] = []


def check(cond: bool, label: str) -> None:
    results.append((bool(cond), label))
    print(f"[{'PASS' if cond else 'FAIL'}] {label}")


def _b64(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_jwks(jwk: dict) -> tuple[ThreadingHTTPServer, str]:
    body = json.dumps({"keys": [jwk]}).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):  # silence
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/jwks"
    return srv, url


def mint_token(private_pem: bytes, email: str, groups: list[str]) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": email,
        "email": email,
        "groups": groups,
        "iat": now,
        "nbf": now,
        "exp": now + 600,
    }
    return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": KID})


def wait_port(host: str, port: int, timeout: float = 30.0) -> bool:
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


async def drive(url: str, token: str):
    from fastmcp import Client

    async with Client(url, auth=token) as client:
        tools = await client.list_tools()
        check(
            {t.name for t in tools} >= {"list_tables", "describe_table", "run_query"},
            f"{token_subject(token)}: server exposes the 3 tools",
        )

        listed = unwrap(await client.call_tool("list_tables", {}))
        names = {row.get("name") for row in _rows(listed)}
        check("orders" in names, f"{token_subject(token)}: list_tables sees analytics.orders")
        check("vault" not in names, f"{token_subject(token)}: list_tables hides secret.vault")

        desc = unwrap(await client.call_tool("describe_table", {"table_name": "analytics.orders"}))
        cols = {c.get("column") for c in _rows(desc.get("columns") if isinstance(desc, dict) else [])}
        check({"id", "region", "amount"} <= cols, f"{token_subject(token)}: describe_table returns columns")

        rows = unwrap(await client.call_tool("run_query", {"sql": "SELECT region, amount FROM analytics.orders ORDER BY amount"}))
        regions = {r.get("region") for r in _rows(rows)}
        return regions


def token_subject(token: str) -> str:
    return jwt.decode(token, options={"verify_signature": False}).get("email", "?")


def _rows(payload):
    if isinstance(payload, dict):
        # fastmcp may wrap under "result"
        for key in ("result", "rows"):
            if key in payload and isinstance(payload[key], list):
                return payload[key]
        return [payload]
    if isinstance(payload, list):
        return payload
    return []


def main() -> int:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub = key.public_key().public_numbers()
    jwk = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID, "n": _b64(pub.n), "e": _b64(pub.e)}

    jwks_srv, jwks_url = start_jwks(jwk)
    mcp_port = free_port()

    env = os.environ.copy()
    env.update({
        "AUTH_ISSUER": ISSUER,
        "JWKS_URI": jwks_url,
        "REQUIRED_AUDIENCE": AUDIENCE,
        "ALGORITHMS": "RS256",
        "ROLES_CLAIM": "groups",
        "RLS_USER_CLAIM": "email",
        "ROLE_MAP_JSON": json.dumps({"analysts": "read_analyst"}),
        "PG_HOST": PG_HOST,
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
        if not wait_port("127.0.0.1", mcp_port, 40):
            out = proc.stdout.read() if proc.stdout else ""
            print("SERVER FAILED TO START:\n", out[-3000:])
            return 2
        print(f"server up at {url}")

        # L5: health endpoint must be reachable WITHOUT a token.
        import urllib.request
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{mcp_port}/health", timeout=5) as resp:
                body = json.loads(resp.read().decode())
                check(resp.status == 200 and body.get("database") == "up",
                      f"health: /health is public and reports db up ({body})")
        except Exception as e:
            check(False, f"health: /health reachable without auth [{type(e).__name__}: {e}]")

        import asyncio
        alice_tok = mint_token(private_pem, "alice@eu", ["analysts"])
        bob_tok = mint_token(private_pem, "bob@us", ["analysts"])

        alice_regions = asyncio.run(drive(url, alice_tok))
        check(alice_regions == {"eu"}, f"RLS: alice@eu sees only eu rows (got {alice_regions})")

        bob_regions = asyncio.run(drive(url, bob_tok))
        check(bob_regions == {"us"}, f"RLS: bob@us sees only us rows (got {bob_regions})")

        # Guard: DML must be rejected.
        from fastmcp import Client

        async def expect_tool_error(token, tool, args, label):
            try:
                async with Client(url, auth=token) as client:
                    await client.call_tool(tool, args)
                check(False, label + " (no error raised)")
            except Exception as e:
                check(True, f"{label} [{type(e).__name__}]")

        asyncio.run(expect_tool_error(alice_tok, "run_query", {"sql": "DELETE FROM analytics.orders"}, "guard: DELETE rejected"))
        asyncio.run(expect_tool_error(alice_tok, "run_query", {"sql": "SELECT * FROM pg_catalog.pg_roles"}, "guard: system schema rejected"))
        asyncio.run(expect_tool_error(alice_tok, "run_query", {"sql": "SELECT * FROM secret.vault"}, "grant: secret.vault denied"))
        asyncio.run(expect_tool_error(alice_tok, "describe_table", {"table_name": "secret.vault"}, "grant: describe_table secret.vault denied"))
        asyncio.run(expect_tool_error(alice_tok, "run_query", {"sql": "SELECT * INTO leaked FROM analytics.orders"}, "guard: SELECT INTO rejected"))

        # Auth: bad audience token must be rejected at connect/call time.
        bad = jwt.encode(
            {"iss": ISSUER, "aud": "someone-else", "sub": "x@eu", "email": "x@eu",
             "groups": ["analysts"], "exp": int(time.time()) + 300},
            private_pem, algorithm="RS256", headers={"kid": KID},
        )

        async def expect_auth_error():
            try:
                async with Client(url, auth=bad) as client:
                    await client.call_tool("list_tables", {})
                check(False, "auth: wrong-audience token rejected (no error)")
            except Exception as e:
                check(True, f"auth: wrong-audience token rejected [{type(e).__name__}]")

        asyncio.run(expect_auth_error())
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        jwks_srv.shutdown()

    passed = sum(1 for ok, _ in results if ok)
    total = len(results)
    print(f"\n==== {passed}/{total} checks passed ====")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
