"""FastAPI application: API + built SPA, session auth, security headers."""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from sqlalchemy import text
from sqlmodel import Session
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.sessions import SessionMiddleware

from . import jobs, poller
from .alerts.service import ensure_rules
from .config import get_settings
from .db import get_engine, init_db
from .routers import api as api_router
from .routers import auth as auth_router
from .routers import simulation as simulation_router
from .routers import timeline as timeline_router
from .routers import alerts as alerts_router
from .routers import health as health_router
from .routers import expectations as expectations_router
from .routers import export as export_router
from .routers import fleet_views as fleet_views_router
from .routers import ingest as ingest_router
from .routers import share as share_router
from .version import VERSION

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("dmarcview")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    init_db()
    with Session(get_engine()) as session:
        ensure_rules(session)
    if settings.secret_key == "dev-insecure-secret-change-me" and settings.env == "production":
        log.error("SECRET_KEY is still the development default — set a random SECRET_KEY")
    if not settings.has_credentials:
        log.warning("No admin credentials configured; login will fail until ADMIN_PASSWORD(_HASH) is set")
    stop_event = asyncio.Event()
    app.state.stop_event = stop_event
    if settings.jmap_enabled:
        poller.start(stop_event)
    jobs.start(stop_event)
    yield
    stop_event.set()
    await poller.stop()
    await jobs.stop_scheduler()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="DMARCView",
        version=VERSION,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        root_path=settings.root_path or "",
    )
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        session_cookie="dmarcview_session",
        max_age=settings.session_max_age,
        same_site="lax",
        https_only=settings.cookie_secure,
        path="/",
    )

    @app.middleware("http")
    async def hardening(request: Request, call_next):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            if origin:
                host = request.headers.get("host", "")
                origin_host = origin.split("://", 1)[-1].rstrip("/")
                if origin_host.lower() != host.lower():
                    return JSONResponse({"detail": "Cross-origin request blocked"}, status_code=403)
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; font-src 'self' data:; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        )
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.get("/api/health", include_in_schema=False)
    def health() -> dict:
        database = "ok"
        try:
            with get_engine().connect() as connection:
                connection.execute(text("SELECT 1"))
        except Exception as exc:  # noqa: BLE001
            log.exception("health check failed")
            return JSONResponse({"ok": False, "version": VERSION, "database": str(exc)}, status_code=503)
        return {"ok": True, "version": VERSION, "database": database}

    app.include_router(auth_router.router)
    app.include_router(api_router.router)
    app.include_router(simulation_router.router)
    app.include_router(timeline_router.router)
    app.include_router(expectations_router.router)
    app.include_router(fleet_views_router.router)
    app.include_router(ingest_router.router)
    app.include_router(health_router.router)
    app.include_router(export_router.router)
    app.include_router(alerts_router.router)
    app.include_router(share_router.router)
    app.include_router(share_router.public_router)

    dist = settings.dist_dir

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        if full_path.startswith("api/") or full_path == "api":
            return JSONResponse({"detail": "Not found"}, status_code=404)
        index = dist / "index.html"
        if full_path:
            candidate = (dist / full_path).resolve()
            if dist.resolve() in candidate.parents and candidate.is_file():
                headers = None
                if full_path.startswith("assets/"):
                    headers = {"Cache-Control": "public, max-age=31536000, immutable"}
                return FileResponse(candidate, headers=headers)
            if full_path.startswith("assets/"):
                return JSONResponse({"detail": "Not found"}, status_code=404)
        if index.is_file():
            headers = {"Cache-Control": "no-cache"}
            if full_path.startswith("s/"):
                headers = {
                    "Cache-Control": "no-store",
                    "Referrer-Policy": "no-referrer",
                    "X-Robots-Tag": "noindex, nofollow",
                }
            return FileResponse(index, headers=headers)
        return HTMLResponse(
            """<!doctype html><html><head><title>DMARCView</title></head>
            <body style="font-family:system-ui;padding:3rem;max-width:42rem;margin:auto">
            <h1>DMARCView API is running</h1>
            <p>The frontend has not been built yet. Run <code>cd frontend &amp;&amp; npm run build</code>,
            or use the Docker image which bundles it.</p>
            <p><a href="/api/health">API health</a></p></body></html>""",
            status_code=200,
        )

    return app


app = create_app()
