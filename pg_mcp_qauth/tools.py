from __future__ import annotations

import logging
from typing import Any

from fastmcp import Context

from . import auth, db, sql_guard
from .config import Settings

logger = logging.getLogger("pg_mcp_qauth")


def _database(ctx: Context) -> db.Database:
    """Resolve the server-scoped Database from the lifespan context (no globals)."""
    lifespan = ctx.lifespan_context or {}
    database = lifespan.get("database") if isinstance(lifespan, dict) else None
    if database is None:
        raise RuntimeError("database is not available in server context (lifespan not started?)")
    return database


def register(mcp: Any, settings: Settings) -> None:
    """Register the read-only Postgres tools on a FastMCP server instance."""

    @mcp.tool()
    async def list_tables(ctx: Context) -> list[dict[str, Any]]:
        """List tables and views the current role can SELECT from (schema, name, kind, comment)."""
        claims = auth.current_claims()
        return await _database(ctx).list_tables(claims)

    @mcp.tool()
    async def describe_table(table_name: str, ctx: Context) -> dict[str, Any]:
        """Describe a table/view: column names, types, nullability and comments.

        `table_name` may be `schema.table` or just `table`.
        """
        claims = auth.current_claims()
        return await _database(ctx).describe_table(table_name, claims)

    @mcp.tool()
    async def run_query(sql: str, ctx: Context) -> list[dict[str, Any]]:
        """Run a single read-only SELECT query and return rows as JSON objects.

        Only SELECT (optionally with CTEs) is permitted; results are capped at the
        configured row limit. Queries run in a READ ONLY transaction scoped to the
        caller's database role and row-level security policies.
        """
        claims = auth.current_claims()
        try:
            safe_sql = sql_guard.validate(
                sql,
                max_rows=settings.max_rows,
                allow_system_schemas=settings.allow_system_schemas,
            )
        except sql_guard.GuardError as exc:
            logger.warning(
                "audit run_query GUARD principal=%s err=%s sql=%.500s",
                claims.get("sub") or claims.get("email") or "unknown",
                exc,
                " ".join((sql or "").split()),
            )
            raise
        return await _database(ctx).run_query(safe_sql, claims)
