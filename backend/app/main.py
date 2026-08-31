"""SentinelSOC FastAPI application entrypoint."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .core.errors import register_exception_handlers
from .core.rate_limit import RateLimitMiddleware, RateLimiter
from .database import SessionLocal, init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    from .bootstrap import bootstrap
    db = SessionLocal()
    try:
        bootstrap(db)
    finally:
        db.close()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        description="Defensive Security Information and Event Management platform.",
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        redoc_url="/api/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Global API rate limiting (auth endpoints have their own stricter limit).
    if settings.rate_limit_enabled:
        app.add_middleware(
            RateLimitMiddleware,
            limiter=RateLimiter(
                max_requests=settings.api_rate_limit,
                window_seconds=settings.api_rate_window_seconds,
                name="api",
            ),
        )

    register_exception_handlers(app)

    from .api import alerts, assets, auth, dashboard, events, incidents, organizations, rules, users

    api = app
    api.include_router(auth.router, prefix=settings.api_prefix)
    api.include_router(users.router, prefix=settings.api_prefix)
    api.include_router(organizations.router, prefix=settings.api_prefix)
    api.include_router(assets.router, prefix=settings.api_prefix)
    api.include_router(events.router, prefix=settings.api_prefix)
    api.include_router(rules.router, prefix=settings.api_prefix)
    api.include_router(alerts.router, prefix=settings.api_prefix)
    api.include_router(incidents.router, prefix=settings.api_prefix)
    api.include_router(dashboard.router, prefix=settings.api_prefix)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "app": settings.app_name, "environment": settings.environment}

    return app


app = create_app()
