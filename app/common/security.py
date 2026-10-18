import base64
import json
import os
import secrets
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from starlette.middleware.trustedhost import TrustedHostMiddleware

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


def install_trusted_host_middleware(app) -> None:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=_env_csv("ALLOWED_HOSTS", DEFAULT_ALLOWED_HOSTS),
        www_redirect=False,
    )


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
                raise HTTPException(413, "Request body too large")
        except ValueError as exc:
            raise HTTPException(400, "Invalid Content-Length") from exc

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > limit:
            raise HTTPException(413, "Request body too large")
        body.extend(chunk)
    if not body:
        return {}

    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(400, "Invalid JSON body") from exc

    if not isinstance(data, dict):
        raise HTTPException(400, "JSON object required")
    return data
