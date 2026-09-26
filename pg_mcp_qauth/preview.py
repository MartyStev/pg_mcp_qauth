"""Dry-run access preview: which DB role (and which tables) a token resolves to.

Debug helper for ROLE_MAP_JSON / DEFAULT_ROLE wiring — no MCP server or OAuth
stack required. The JWT signature is NOT verified here (there is no reason to
hit JWKS just to inspect a mapping); everything else uses the real code paths:
`db.groups_for`, `db.resolve_role_for` and, with `--check-db`, a live
`SET LOCAL ROLE` + has_table_privilege listing through `Database.list_tables`.

Usage:
    python -m pg_mcp_qauth.preview --token-file /tmp/alice.jwt [--check-db]
    echo "$JWT" | python -m pg_mcp_qauth.preview -
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

import jwt as pyjwt

from . import db
from .config import Settings, get_settings


def preview(settings: Settings, claims: dict[str, Any]) -> dict[str, Any]:
    groups = db.groups_for(settings, claims)
    role, matched = db.resolve_role_for(settings, groups)
    return {
        "principal": db.principal(claims),
        "groups_claim": settings.roles_claim,
        "groups": groups,
        "matched_group": matched or None,
        "source": "role_map" if matched else "default_role",
        "db_role": role,
        "rls_user_value": str(
            claims.get(settings.rls_user_claim) or claims.get("sub") or ""
        ),
    }


async def tables_for_role(settings: Settings, role: str) -> list[dict[str, Any]]:
    """List tables visible under `role` via the same catalog query the tools use."""
    if not db.IDENT_RE.match(role):
        raise ValueError(f"role is not a valid identifier: {role!r}")
    database = db.Database(settings)
    await database.ensure_init()
    try:
        async with database.pool.acquire() as conn:
            tx = conn.transaction(readonly=True)
            await tx.start()
            try:
                await conn.execute(f'SET LOCAL ROLE "{role}"')
                rows = await conn.fetch(db.LIST_TABLES_SQL)
                await tx.commit()
            except BaseException:
                await tx.rollback()
                raise
    finally:
        await database.close()
    return [dict(r) for r in rows]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pg-mcp-preview", description=__doc__)
    parser.add_argument("token_stdin", nargs="?", default=None,
                        help="pass '-' to read the JWT from stdin")
    parser.add_argument("--token-file", help="file containing the access token")
    parser.add_argument("--check-db", action="store_true",
                        help="also connect to Postgres and list tables visible to the role")
    args = parser.parse_args(argv)

    if args.token_file:
        with open(args.token_file, encoding="utf8") as fh:
            raw = fh.read().strip()
    elif args.token_stdin == "-":
        raw = sys.stdin.read().strip()
    elif args.token_stdin:
        raw = args.token_stdin
    else:
        parser.error("provide a JWT argument, --token-file, or '-' for stdin")

    claims = pyjwt.decode(raw, options={"verify_signature": False,
                                        "verify_aud": False, "verify_exp": False})
    settings = get_settings()
    settings.check()

    result = preview(settings, claims)
    if args.check_db:
        try:
            tables = asyncio.run(tables_for_role(settings, result["db_role"]))
            result["visible_tables"] = [f"{t['schema']}.{t['name']}" for t in tables]
        except Exception as exc:  # noqa: BLE001 - CLI report, not a crash
            result["visible_tables_error"] = f"{type(exc).__name__}: {exc}"
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
