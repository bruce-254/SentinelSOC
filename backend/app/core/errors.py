"""API exception handlers and error helpers."""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


class AppError(Exception):
    def __init__(self, status_code: int, detail: str, code: str | None = None):
        self.status_code = status_code
        self.detail = detail
        self.code = code or "error"
        super().__init__(detail)


class NotFoundError(AppError):
    def __init__(self, detail: str = "Resource not found"):
        super().__init__(404, detail, "not_found")


class PermissionError(AppError):
    def __init__(self, detail: str = "Insufficient permissions"):
        super().__init__(403, detail, "forbidden")


class BadRequest(AppError):
    def __init__(self, detail: str):
        super().__init__(400, detail, "bad_request")


class Unauthorized(AppError):
    def __init__(self, detail: str = "Authentication required"):
        super().__init__(401, detail, "unauthorized")


class RateLimited(AppError):
    def __init__(self, detail: str = "Too many requests"):
        super().__init__(429, detail, "rate_limited")


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def app_error_handler(_req: Request, exc: AppError):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail, "code": exc.code},
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(_req: Request, exc: StarletteHTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_req: Request, exc: RequestValidationError):
        return JSONResponse(status_code=422, content={"detail": exc.errors()})
