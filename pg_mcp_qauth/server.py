from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from . import auth, db, tools
from .config import Settings, get_settings

logger = logging.getLogger("pg_mcp_qauth")


def build_server() -> tuple[object, Settings, db.Database]:
    settings = get_settings()
    settings.check()
    if not settings.pg_password:
        logger.warning("PG_PASSWORD is empty; relying on server-side auth (e.g. peer/trust) — "
                       "usually not what you want for a TCP deployment")

    from fastmcp import FastMCP

    database = db.Database(settings)

    @asynccontextmanager
    async def lifespan(_server):
        # Initialize the pool at startup and close it on shutdown.
        await database.ensure_init()
        try:
            yield {"database": database, "settings": settings}
        finally:
            await database.close()

    mcp = FastMCP(
        name=settings.mcp_name,
        auth=auth.build_verifier(settings),
        lifespan=lifespan,
    )
    tools.register(mcp, settings)
    _register_health(mcp, database)
    return mcp, settings, database


def _register_health(mcp, database: db.Database) -> None:
    from starlette.responses import JSONResponse

    @mcp.custom_route("/health", methods=["GET"])
    async def health(_request):
        db_up = await database.health()
        return JSONResponse(
            {"status": "ok" if db_up else "degraded", "database": "up" if db_up else "down"},
            status_code=200 if db_up else 503,
        )


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    mcp, settings, _database = build_server()
    # Streamable HTTP is the current MCP transport (SSE is legacy).
    mcp.run(
        transport="http",
        host=settings.mcp_host,
        port=settings.mcp_port,
        path=settings.mcp_path,
    )


if __name__ == "__main__":
    main()
