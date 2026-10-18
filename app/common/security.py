import base64
import json
import logging
import os
import secrets
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.body_limit import RequestBodyLimitMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.common.db import StorageUnavailableError

logger = logging.getLogger(__name__)
BAD_REQUEST = "Something went wrong there. Please reload the page and try again."
UNSAFE_HTTP_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

DEFAULT_ALLOWED_HOSTS = (
    "localhost",
    "127.0.0.1",
    "testserver",
)
DEFAULT_JSON_BODY_MAX_BYTES = 128 * 1024


def new_csp_nonce() -> str:
    return base64.b64encode(secrets.token_bytes(16)).decode("ascii")


def _env_csv(name: str, default: tuple[str, ...]) -> list[str]:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return list(default)
    values = [part.strip().lower() for part in raw.split(",") if part.strip()]
    return values or list(default)


def client_ip(request: Request) -> str:
    """Use ASGI's peer, set only by the server's trusted proxy configuration."""
    return str(request.client.host) if request.client else "unknown"


def _csp(nonce: str) -> str:
    return (
        f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-src 'none'; "
        "img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none';"
    )


def install_security(app, write_prefix: str) -> None:
    """Host allow-list, body cap, security headers, same-origin writes, scrubbed errors."""
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=_env_csv("ALLOWED_HOSTS", DEFAULT_ALLOWED_HOSTS),
        www_redirect=False,
    )
    app.add_middleware(RequestBodyLimitMiddleware, max_body_size=6 * 1024 * 1024)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        nonce = new_csp_nonce()
        request.state.csp_nonce = nonce
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = _csp(nonce)
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains"
        )
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        return resp

    @app.middleware("http")
    async def same_origin_writes(request: Request, call_next):
        if (
            request.method in UNSAFE_HTTP_METHODS
            and request.url.path.startswith(write_prefix)
            and not same_origin_write_request(request)
        ):
            return JSONResponse({"detail": "That request was blocked for security reasons. Please reload the page and try again."}, status_code=403)
        return await call_next(request)

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        # Every HTTPException carries a fixed, user-facing message.
        return JSONResponse(
            {"detail": str(exc.detail)}, status_code=exc.status_code, headers=exc.headers
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        return JSONResponse({"detail": BAD_REQUEST}, status_code=400)

    @app.exception_handler(StorageUnavailableError)
    async def storage_unavailable(request: Request, exc: StorageUnavailableError):
        logger.warning("Storage unavailable: %s", exc)
        return JSONResponse({"detail": _PUBLIC_ERRORS[503]}, status_code=503)

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception):
        logger.exception("Unhandled error")
        return JSONResponse({"detail": _PUBLIC_ERRORS[500]}, status_code=500)


_PUBLIC_ERRORS = {
    500: "Sorry, something went wrong on our side. Please try again.",
    503: "We're having trouble reaching the database. Please try again in a moment.",
}


def json_body_max_bytes() -> int:
    raw = (os.environ.get("JSON_BODY_MAX_BYTES") or "").strip()
    if not raw:
        return DEFAULT_JSON_BODY_MAX_BYTES
    try:
        return max(1024, int(raw))
    except ValueError as exc:
        raise RuntimeError("JSON_BODY_MAX_BYTES must be an integer") from exc


def _canonical_netloc(netloc: str, scheme: str = "") -> str:
    try:
        parsed = urlparse(f"//{(netloc or '').strip()}")
        host = (parsed.hostname or "").strip().lower()
        if not host:
            return ""
        port = parsed.port
    except ValueError:
        return ""

    if port is None:
        return host
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return host
    return f"{host}:{port}"


def same_origin_write_request(request: Request) -> bool:
    host = _canonical_netloc(
        (request.headers.get("host") or "").strip() or request.url.netloc,
        request.url.scheme,
    )
    if not host:
        return False

    sec_fetch_site = (request.headers.get("sec-fetch-site") or "").strip().lower()
    if sec_fetch_site and sec_fetch_site not in {"same-origin", "same-site", "none"}:
        return False

    origin = (request.headers.get("origin") or "").strip().rstrip("/")
    if origin:
        parsed = urlparse(origin)
        if parsed.scheme not in {"http", "https"}:
            return False
        return (
            parsed.scheme == request.url.scheme
            and _canonical_netloc(parsed.netloc, parsed.scheme) == host
        )

    referer = (request.headers.get("referer") or "").strip()
    if referer:
        parsed = urlparse(referer)
        if parsed.scheme not in {"http", "https"}:
            return False
        return (
            parsed.scheme == request.url.scheme
            and _canonical_netloc(parsed.netloc, parsed.scheme) == host
        )

    return False


async def json_object_body(
    request: Request, *, max_bytes: int | None = None
) -> dict[str, Any]:
    limit = max_bytes if max_bytes is not None else json_body_max_bytes()
    content_length = (request.headers.get("content-length") or "").strip()
    if content_length:
        try:
            if int(content_length) > limit:
                raise HTTPException(413, "That's more than we can accept in one go.")
        except ValueError as exc:
            raise HTTPException(400, BAD_REQUEST) from exc

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > limit:
            raise HTTPException(413, "That's more than we can accept in one go.")
        body.extend(chunk)
    if not body:
        return {}

    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(400, BAD_REQUEST) from exc

    if not isinstance(data, dict):
        raise HTTPException(400, BAD_REQUEST)
    return data


async def json_body(request: Request) -> dict[str, Any]:
    """Dependency: read the body on the event loop so the endpoint can be a
    plain `def` and run its blocking database work in the threadpool."""
    return await json_object_body(request)
