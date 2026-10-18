import csv
import io
import json
import logging
import os
import re
import secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.body_limit import RequestBodyLimitMiddleware

from app.common.auth import (
    ADMIN_SESSION_COOKIE,
    create_admin_session,
    delete_admin_session,
    require_admin_session,
    load_user_context,
    require_any_role,
    require_route_in_scope,
    require_scope_for_area,
    route_scope_where,
)
from app.common.email_auth import request_code, verify_code
from app.common.crypto import decrypt_text, encrypt_text
from app.common.db import (
    StorageUnavailableError,
    get_answers_admin,
    get_ops,
    init_pools,
    put_answers_admin,
    put_ops,
)
from app.common.ratelimit import RateLimiter, client_ip
from app.common.security import (
    UNSAFE_HTTP_METHODS,
    install_trusted_host_middleware,
    json_object_body,
    new_csp_nonce,
    same_origin_write_request,
)
from app.common.survey import load_survey, change_survey
from app.common.util import fetchall_dict, fetchone_dict

logger = logging.getLogger(__name__)

# 10 login attempts per IP per 5 minutes
_admin_login_limiter = RateLimiter(max_calls=10, window_seconds=300)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
install_trusted_host_middleware(app)
app.add_middleware(RequestBodyLimitMiddleware, max_body_size=6 * 1024 * 1024)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory=["app/admin/templates", "app/templates"])

ALLOWED_MANAGEMENT_ROLES = ["GLOBAL_ADMIN", "BOROUGH_ADMIN", "AREA_USER"]


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())


_ADDRESS_STREET_SFXS = {
    "avenue",
    "canal",
    "close",
    "crescent",
    "cut",
    "drive",
    "gate",
    "gardens",
    "grove",
    "hill",
    "lane",
    "mews",
    "place",
    "quay",
    "road",
    "row",
    "square",
    "street",
    "terrace",
    "terraces",
    "walk",
    "walks",
    "way",
    "wharf",
}

_ADDRESS_STREET_SFX_ABBREVS = {
    "rd": "road",
    "st": "street",
    "ave": "avenue",
    "av": "avenue",
    "cl": "close",
    "ct": "court",
    "gdns": "gardens",
}

_ADDRESS_BUILDING_SFXS = {
    "house",
    "court",
    "courts",
    "building",
    "buildings",
    "tower",
    "towers",
    "block",
    "blocks",
    "lodge",
    "hall",
    "mansions",
    "mansion",
    "heights",
    "wharves",
    "cottages",
    "cottage",
    "moorings",
    "centre",
    "center",
    "arms",
    "apartments",
    "home",
    "homes",
    "vicarage",
    "works",
    "lock",
    "quarter",
    "village",
}


def _norm_flat_label(s: str) -> str:
    cleaned = re.sub(
        r"^(?:flat|apartment|apt|unit)\s+", "", _norm(s), flags=re.IGNORECASE
    )
    cleaned = cleaned.lower()
    return re.sub(r"(?<!\d)0+(\d)", r"\1", cleaned)


def _has_export_flat_label(s: str) -> bool:
    return _norm_flat_label(s) not in {"", "0", "none", "n/a", "na", "-"}


def _leading_address_num(s: str) -> str:
    m = re.match(r"^(\d+[A-Za-z]?(?:-\d+[A-Za-z]?)?)", _norm(s))
    return m.group(1) if m else ""


def _address_last_word(s: str) -> str:
    words = re.findall(r"[A-Za-z]+", _norm(s))
    last = words[-1].lower() if words else ""
    return _ADDRESS_STREET_SFX_ABBREVS.get(last, last)


def _split_house_flat_label(label: str) -> tuple[str, str]:
    m = re.match(
        r"^(\d+[A-Za-z]?(?:-\d+[A-Za-z]?)?)\s+"
        r"(?:flat|apartment|apt|unit)\s+(.+)$",
        _norm(label),
        flags=re.IGNORECASE,
    )
    if not m:
        return "", ""
    flat = m.group(2).strip()
    return (m.group(1), flat) if _has_export_flat_label(flat) else ("", "")


def _extract_leading_flat(full_address: str) -> tuple[str, str]:
    text = _norm(full_address)
    m = re.match(
        r"^(?:flat|apartment|apt|unit)\s+([^,]+),\s*(.+)$", text, flags=re.IGNORECASE
    )
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return "", text


def _flat_display(flat: str) -> str:
    flat = _norm(flat)
    if re.match(r"^(?:flat|apartment|apt|unit)\b", flat, flags=re.IGNORECASE):
        return flat
    if re.search(
        r"\b(?:floor|floors|maisonette|basement)\b", flat, flags=re.IGNORECASE
    ):
        return flat
    return f"Flat {flat}"


def _looks_like_pure_street(s: str) -> bool:
    if _leading_address_num(s):
        return False
    words = re.findall(r"[A-Za-z]+", _norm(s).lower())
    non_street_words = _ADDRESS_BUILDING_SFXS | {
        "flat",
        "flats",
        "apartment",
        "apartments",
        "apt",
        "unit",
    }
    return bool(
        words
        and _address_last_word(s) in _ADDRESS_STREET_SFXS
        and not (set(words[:-1]) & non_street_words)
    )


def _looks_like_address_label(s: str) -> bool:
    return bool(
        _leading_address_num(s) and _address_last_word(s) in _ADDRESS_STREET_SFXS
    )


def _full_address_with_flat(full_address: str, flat_label: str) -> str:
    base = _norm(full_address)
    flat = _norm(flat_label)
    if _looks_like_address_label(flat):
        return flat if _looks_like_pure_street(base) else base
    if not _has_export_flat_label(flat):
        return base

    embedded_flat, _ = _extract_leading_flat(base)
    if embedded_flat and _norm_flat_label(embedded_flat) == _norm_flat_label(flat):
        return base

    leading_num = _leading_address_num(base)
    if leading_num and _norm_flat_label(flat) == _norm_flat_label(leading_num):
        return base

    house_num, unit = _split_house_flat_label(flat)
    if house_num and unit:
        return f"{_flat_display(unit)}, {house_num} {base}".strip()

    if _looks_like_pure_street(base):
        return f"{flat} {base}".strip()

    return f"{_flat_display(flat)}, {base}".strip(", ")


def _include_flat_in_full_address(rows: list[dict]) -> list[dict]:
    for row in rows:
        if "full_address" in row and "flat_label" in row:
            row["full_address"] = _full_address_with_flat(
                row.get("full_address", ""),
                row.get("flat_number") or row.get("flat_label", ""),
            )
    return rows


def _env_int_local(name: str, default: int) -> int:
    raw = (os.environ.get(name, "") or "").strip()
    if not raw:
        return default
    return int(raw)


def _max_csv_upload_bytes() -> int:
    return max(1024, _env_int_local("ADMIN_CSV_UPLOAD_MAX_BYTES", 5 * 1024 * 1024))


def _export_row_cap() -> int:
    return max(1000, _env_int_local("ADMIN_EXPORT_MAX_ROWS", 50000))


def _new_route_id(area_id: str) -> str:
    # Example: LOCAL_CENTRAL_20260221_204500_ABC
    date = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    suffix = secrets.token_hex(2).upper()
    return f"{area_id}_{date}_{suffix}"


def _validate_route_number(route_number: Optional[int]) -> Optional[int]:
    if route_number is None:
        return None
    value = int(route_number)
    if value < 1 or value > 999999:
        raise HTTPException(400, "route_number must be between 1 and 999999")
    return value


def _route_code_status(active: bool, expires_at) -> str:
    if not active:
        return "revoked"
    if expires_at is not None and expires_at <= datetime.now(timezone.utc):
        return "expired"
    return "working"


def _route_code_payload(row: dict, route_id: str, route_number: Optional[int]) -> dict:
    return {
        "route_id": route_id,
        "route_number": route_number,
        "code_plain": decrypt_text(row["code_ciphertext"]),
        "active": row["active"],
        "expires_at": row["expires_at"],
        "created_at": row["created_at"],
        "status": _route_code_status(row["active"], row["expires_at"]),
    }


@app.on_event("startup")
def _startup():
    init_pools()


@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    nonce = new_csp_nonce()
    request.state.csp_nonce = nonce
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'unsafe-inline'; "
        f"connect-src 'self'; "
        f"frame-src 'none'; "
        f"img-src 'self' data:; "
        f"font-src 'self'; "
        f"object-src 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self'; "
        f"frame-ancestors 'none';"
    )
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    )
    return resp


@app.middleware("http")
async def csrf_same_origin_guard(request: Request, call_next):
    if request.method in UNSAFE_HTTP_METHODS and request.url.path.startswith("/admin/"):
        if not same_origin_write_request(request):
            return JSONResponse({"detail": "Access denied"}, status_code=403)
    return await call_next(request)


@app.exception_handler(StorageUnavailableError)
async def storage_unavailable_handler(request: Request, exc: StorageUnavailableError):
    return JSONResponse({"detail": "Service temporarily unavailable"}, status_code=503)


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error")
    return JSONResponse({"detail": "Internal server error"}, status_code=500)


def _login_page(request: Request, detail: Optional[str] = None, status_code: int = 200):
    return templates.TemplateResponse(
        request,
        "signin.html",
        {
            "detail": detail,
            "is_admin": True,
        },
        status_code=status_code,
    )


def _ctx(req: Request):
    email = (require_admin_session(req).get("email") or "").strip().lower()
    u = load_user_context(email)
    require_any_role(u, ALLOWED_MANAGEMENT_ROLES)
    return email, u


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    """
    Minimal landing page. You can keep your existing admin.html template or replace it.
    """
    try:
        _, u = _ctx(request)
    except HTTPException as e:
        if e.status_code == 401:
            return _login_page(request)
        raise
    return templates.TemplateResponse(request, "admin.html", {"user": u})


@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page(request: Request):
    try:
        _ctx(request)
        return RedirectResponse("/", status_code=302)
    except HTTPException as e:
        if e.status_code == 401:
            return _login_page(request)
        raise


@app.post("/admin/api/login")
async def admin_login(request: Request):
    if not _admin_login_limiter.is_allowed(client_ip(request)):
        raise HTTPException(429, "Too many requests")
    body = await json_object_body(request)
    email = verify_code(body, "admin", client_ip(request))

    u = load_user_context(email)
    require_any_role(u, ALLOWED_MANAGEMENT_ROLES)
    session_token = create_admin_session(email)

    resp = JSONResponse({"ok": True, "email": email, "role": u["role"]})
    resp.set_cookie(
        key=ADMIN_SESSION_COOKIE,
        value=session_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=60 * 60 * 12,
    )
    return resp


@app.post("/admin/api/logout")
def admin_logout(request: Request):
    delete_admin_session(request.cookies.get(ADMIN_SESSION_COOKIE) or "")
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(
        key=ADMIN_SESSION_COOKIE, secure=True, httponly=True, samesite="lax"
    )
    return resp


@app.get("/admin/whoami")
def whoami(request: Request):
    email, u = _ctx(request)
    return {"email": email, **u}


@app.post("/admin/routes/upload.csv")
async def upload_routes_csv(
    request: Request,
    area_id: str,
    route_number: Optional[int] = None,
    file: UploadFile = File(...),
):
    """
    Upload electoral registry CSV (resident CSV format) or legacy street/house CSV.
    Registry format headers: elector_id, street_name, building, flat_number, postcode, resident_name
    Legacy format headers: street[, house]
    Creates: routes row, addresses rows, flats/elector rows.
    """
    email, u = _ctx(request)
    require_scope_for_area(u, area_id)
    route_number = _validate_route_number(route_number)

    max_upload_bytes = _max_csv_upload_bytes()
    try:
        file.file.seek(0, io.SEEK_END)
        upload_size = file.file.tell()
        file.file.seek(0)
    except Exception:
        upload_size = None
    if upload_size is not None and upload_size > max_upload_bytes:
        raise HTTPException(413, f"CSV too large (max {max_upload_bytes} bytes)")

    text_stream = io.TextIOWrapper(file.file, encoding="utf-8-sig", newline="")
    reader = csv.DictReader(text_stream)
    if not reader.fieldnames:
        raise HTTPException(400, "Empty CSV")

    headers = {h.strip().lower() for h in (reader.fieldnames or [])}
    is_registry = {
        "elector_id",
        "street_name",
        "building",
        "postcode",
        "resident_name",
    }.issubset(headers)
    if not is_registry and "street" not in headers:
        raise HTTPException(
            400,
            "CSV must have registry headers (elector_id, street_name, building, postcode, resident_name) or legacy header: street",
        )

    conn = get_ops()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT borough_id FROM areas WHERE area_id=%s", (area_id,))
                a = fetchone_dict(cur)
                if not a:
                    raise HTTPException(400, "Unknown area_id")
                borough_id = a["borough_id"]

                route_id = _new_route_id(area_id)
                cur.execute(
                    """
                    INSERT INTO routes(route_id, name, active, borough_id, area_id, route_number, uploaded_by_email, created_at)
                    VALUES (%s, %s, true, %s, %s, %s, %s, now())
                    """,
                    (
                        route_id,
                        f"Upload {route_id}",
                        borough_id,
                        area_id,
                        route_number,
                        email,
                    ),
                )

                inserted_addresses = 0
                inserted_flats = 0
                skipped = 0
                addr_id_cache: dict[tuple, str] = {}

                for row in reader:
                    row_norm = {
                        str(k).strip().lower(): v
                        for k, v in (row or {}).items()
                        if k is not None
                    }

                    if is_registry:
                        street = _norm(row_norm.get("street_name"))
                        house = _norm(row_norm.get("building") or "")
                        postcode = _norm(row_norm.get("postcode") or "")
                        resident_name = (
                            _norm(row_norm.get("resident_name") or "") or None
                        )
                        elector_id = _norm(row_norm.get("elector_id") or "") or None
                        flat_number = _norm(row_norm.get("flat_number") or "") or None
                        flat_label = elector_id or resident_name
                    else:
                        street = _norm(row_norm.get("street"))
                        house = _norm(row_norm.get("house") or "")
                        postcode = _norm(row_norm.get("postcode") or "")
                        resident_name = None
                        elector_id = None
                        flat_number = None
                        flat_label = None

                    if not street:
                        skipped += 1
                        continue

                    full_address = f"{house} {street}".strip()
                    if postcode:
                        full_address = f"{full_address}, {postcode}"

                    addr_key = (postcode.lower(), street.lower(), house.lower())
                    if addr_key not in addr_id_cache:
                        cur.execute(
                            """
                            INSERT INTO addresses(route_id, street, house, postcode, full_address, source)
                            VALUES (%s,%s,%s,%s,%s,'uploaded')
                            ON CONFLICT (route_id, lower(postcode), lower(street), lower(house)) DO NOTHING
                            """,
                            (route_id, street, house, postcode, full_address),
                        )
                        if cur.rowcount == 1:
                            inserted_addresses += 1
                        cur.execute(
                            """
                            SELECT address_id FROM addresses
                            WHERE route_id=%s AND lower(postcode)=lower(%s)
                              AND lower(street)=lower(%s) AND lower(house)=lower(%s)
                            """,
                            (route_id, postcode, street, house),
                        )
                        addr_row = fetchone_dict(cur)
                        if not addr_row:
                            skipped += 1
                            continue
                        addr_id_cache[addr_key] = str(addr_row["address_id"])

                    address_id = addr_id_cache[addr_key]

                    if flat_label:
                        cur.execute(
                            """
                            INSERT INTO flats(address_id, flat_label, status, resident_name, elector_id, flat_number)
                            VALUES (%s,%s,'unvisited',%s,%s,%s)
                            ON CONFLICT (address_id, lower(flat_label))
                            DO UPDATE SET resident_name=EXCLUDED.resident_name,
                                          elector_id=EXCLUDED.elector_id,
                                          flat_number=EXCLUDED.flat_number
                            """,
                            (
                                address_id,
                                flat_label,
                                resident_name,
                                elector_id,
                                flat_number,
                            ),
                        )
                        if cur.rowcount == 1:
                            inserted_flats += 1

        return {
            "ok": True,
            "route_id": route_id,
            "route_number": route_number,
            "inserted_addresses": inserted_addresses,
            "inserted_flats": inserted_flats,
            "skipped": skipped,
            "uploaded_by": email,
        }
    except UnicodeDecodeError:
        raise HTTPException(400, "CSV must be UTF-8 encoded")
    finally:
        put_ops(conn)


@app.post("/admin/routes/{route_id}/number")
def set_route_number(
    request: Request, route_id: str, route_number: Optional[int] = None
):
    _, u = _ctx(request)
    _ = require_route_in_scope(u, route_id)
    route_number = _validate_route_number(route_number)

    conn = get_ops()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE routes
                    SET route_number=%s
                    WHERE route_id=%s
                    RETURNING route_id, route_number
                    """,
                    (route_number, route_id),
                )
                row = fetchone_dict(cur)
                if not row:
                    raise HTTPException(404, "Route not found")
        return {
            "ok": True,
            "route_id": row["route_id"],
            "route_number": row["route_number"],
        }
    finally:
        put_ops(conn)


@app.post("/admin/routes/{route_id}/codes/generate")
def generate_codes(
    request: Request,
    route_id: str,
    n: int = 1,
    ttl_hours: int = 24,
    replace_active: bool = False,
):
    """
    Generate join codes for a route within your scope.
    """
    _, u = _ctx(request)
    n = max(1, min(int(n), 500))
    ttl_hours = max(1, min(int(ttl_hours), 24 * 30))

    r = require_route_in_scope(u, route_id)

    conn = get_ops()
    try:
        generated_codes: list[dict] = []
        revoked_before_generate = 0
        with conn:
            with conn.cursor() as cur:
                if replace_active:
                    cur.execute(
                        """
                        UPDATE route_codes
                        SET active=false
                        WHERE route_id=%s
                          AND active=true
                        """,
                        (route_id,),
                    )
                    revoked_before_generate = cur.rowcount or 0
                for _ in range(n):
                    token = (
                        secrets.token_urlsafe(9)
                        .replace("-", "")
                        .replace("_", "")[:10]
                        .upper()
                    )
                    code_plain = f"{route_id}-{token}"
                    cipher = encrypt_text(code_plain)
                    cur.execute(
                        """
                        INSERT INTO route_codes(route_id, code_hash, code_ciphertext, active, expires_at)
                        VALUES (%s, crypt(%s, gen_salt('bf', 12)), %s, true, now() + (%s * interval '1 hour'))
                        RETURNING expires_at, created_at
                        """,
                        (route_id, code_plain, cipher, ttl_hours),
                    )
                    ins = fetchone_dict(cur) or {}
                    generated_codes.append(
                        {
                            "code_plain": code_plain,
                            "expires_at": ins.get("expires_at"),
                            "created_at": ins.get("created_at"),
                        }
                    )
        return {
            "ok": True,
            "route_id": route_id,
            "route_number": r.get("route_number"),
            "generated": n,
            "ttl_hours": ttl_hours,
            "revoked_before_generate": revoked_before_generate,
            "borough_id": r["borough_id"],
            "area_id": r["area_id"],
            "codes": generated_codes,
        }
    finally:
        put_ops(conn)


@app.get("/admin/routes/{route_id}/codes/active")
def list_active_codes(request: Request, route_id: str):
    _, u = _ctx(request)
    route = require_route_in_scope(u, route_id)
    conn = get_ops()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT rc.code_ciphertext, rc.active, rc.expires_at, rc.created_at, r.route_number
                FROM route_codes rc
                JOIN routes r ON r.route_id = rc.route_id
                WHERE rc.route_id=%s
                  AND rc.active=true
                  AND (rc.expires_at IS NULL OR rc.expires_at > now())
                ORDER BY rc.expires_at ASC NULLS LAST, rc.created_at DESC
                """,
                (route_id,),
            )
            rows = fetchall_dict(cur)
        out = [_route_code_payload(r, route_id, r["route_number"]) for r in rows]
        return {
            "ok": True,
            "route_id": route_id,
            "route_number": route.get("route_number"),
            "count": len(out),
            "codes": out,
        }
    finally:
        put_ops(conn)


@app.get("/admin/routes/{route_id}/codes")
def list_route_codes(request: Request, route_id: str):
    _, u = _ctx(request)
    route = require_route_in_scope(u, route_id)
    conn = get_ops()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT rc.code_ciphertext, rc.active, rc.expires_at, rc.created_at, r.route_number
                FROM route_codes rc
                JOIN routes r ON r.route_id = rc.route_id
                WHERE rc.route_id=%s
                ORDER BY rc.created_at DESC, rc.expires_at DESC NULLS LAST
                """,
                (route_id,),
            )
            rows = fetchall_dict(cur)
        out = [_route_code_payload(r, route_id, r["route_number"]) for r in rows]
        return {
            "ok": True,
            "route_id": route_id,
            "route_number": route.get("route_number"),
            "count": len(out),
            "codes": out,
        }
    finally:
        put_ops(conn)


@app.get("/admin/routes/codes")
def list_route_codes_all(request: Request, limit: int = 500):
    _, u = _ctx(request)
    limit = max(1, min(int(limit), 2000))
    conn = get_ops()
    try:
        where, params = route_scope_where(u, route_alias="r")
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT rc.route_id, r.route_number, rc.code_ciphertext, rc.active, rc.expires_at, rc.created_at
                FROM route_codes rc
                JOIN routes r ON r.route_id = rc.route_id
                WHERE ({where})
                ORDER BY rc.route_id ASC, rc.created_at DESC, rc.expires_at DESC NULLS LAST
                LIMIT %s
                """,
                (*params, limit),
            )
            rows = fetchall_dict(cur)
        out = [_route_code_payload(r, r["route_id"], r["route_number"]) for r in rows]
        return {"ok": True, "count": len(out), "codes": out}
    finally:
        put_ops(conn)


@app.get("/admin/routes/codes/active")
def list_active_codes_all(request: Request, limit: int = 500):
    _, u = _ctx(request)
    limit = max(1, min(int(limit), 2000))
    conn = get_ops()
    try:
        where, params = route_scope_where(u, route_alias="r")
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT rc.route_id, r.route_number, rc.code_ciphertext, rc.active, rc.expires_at, rc.created_at
                FROM route_codes rc
                JOIN routes r ON r.route_id = rc.route_id
                WHERE ({where})
                  AND rc.active=true
                  AND (rc.expires_at IS NULL OR rc.expires_at > now())
                ORDER BY rc.route_id ASC, rc.expires_at ASC NULLS LAST, rc.created_at DESC
                LIMIT %s
                """,
                (*params, limit),
            )
            rows = fetchall_dict(cur)
        out = [_route_code_payload(r, r["route_id"], r["route_number"]) for r in rows]
        return {"ok": True, "count": len(out), "codes": out}
    finally:
        put_ops(conn)


@app.post("/admin/routes/{route_id}/codes/revoke_all")
def revoke_all_codes(request: Request, route_id: str):
    _, u = _ctx(request)
    _ = require_route_in_scope(u, route_id)
    conn = get_ops()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE route_codes
                    SET active=false
                    WHERE route_id=%s
                      AND active=true
                    """,
                    (route_id,),
                )
                revoked = cur.rowcount or 0
        return {"ok": True, "route_id": route_id, "revoked": revoked}
    finally:
        put_ops(conn)


@app.post("/admin/routes/{route_id}/codes/revoke")
async def revoke_route_code(request: Request, route_id: str):
    _, u = _ctx(request)
    route = require_route_in_scope(u, route_id)
    body = await json_object_body(request)
    code_plain = (body.get("code_plain") or "").strip()
    if not code_plain:
        raise HTTPException(400, "code_plain required")
    if not code_plain.startswith(f"{route_id}-"):
        raise HTTPException(400, "Code does not belong to the selected route")

    conn = get_ops()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE route_codes
                    SET active=false
                    WHERE route_id=%s
                      AND active=true
                      AND code_hash = crypt(%s, code_hash)
                    RETURNING code_ciphertext, active, expires_at, created_at
                    """,
                    (route_id, code_plain),
                )
                row = fetchone_dict(cur)
                if not row:
                    cur.execute(
                        """
                        SELECT code_ciphertext, active, expires_at, created_at
                        FROM route_codes
                        WHERE route_id=%s
                          AND code_hash = crypt(%s, code_hash)
                        """,
                        (route_id, code_plain),
                    )
                    existing = fetchone_dict(cur)
                    if existing:
                        raise HTTPException(409, "Code is already revoked")
                    raise HTTPException(404, "Code not found")
        return {
            "ok": True,
            "route_id": route_id,
            "route_number": route.get("route_number"),
            "code": _route_code_payload(row, route_id, route.get("route_number")),
        }
    finally:
        put_ops(conn)


@app.post("/admin/routes/{route_id}/codes/extend_active")
def extend_active_codes(request: Request, route_id: str, ttl_hours: int = 24):
    _, u = _ctx(request)
    route = require_route_in_scope(u, route_id)
    ttl_hours = max(1, min(int(ttl_hours), 24 * 30))

    conn = get_ops()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE route_codes
                    SET expires_at =
                        CASE
                            WHEN expires_at IS NULL OR expires_at < now() THEN now() + (%s * interval '1 hour')
                            ELSE expires_at + (%s * interval '1 hour')
                        END
                    WHERE route_id=%s
                      AND active=true
                    """,
                    (ttl_hours, ttl_hours, route_id),
                )
                extended = cur.rowcount or 0
        return {
            "ok": True,
            "route_id": route_id,
            "route_number": route.get("route_number"),
            "ttl_hours": ttl_hours,
            "extended": extended,
        }
    finally:
        put_ops(conn)


@app.post("/admin/routes/{route_id}/codes/extend")
async def extend_route_code(request: Request, route_id: str):
    _, u = _ctx(request)
    route = require_route_in_scope(u, route_id)
    body = await json_object_body(request)
    code_plain = (body.get("code_plain") or "").strip()
    try:
        ttl_hours = max(1, min(int(body.get("ttl_hours") or 24), 24 * 30))
    except (ValueError, TypeError):
        raise HTTPException(400, "ttl_hours must be an integer")
    if not code_plain:
        raise HTTPException(400, "code_plain required")
    if not code_plain.startswith(f"{route_id}-"):
        raise HTTPException(400, "Code does not belong to the selected route")

    conn = get_ops()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE route_codes
                    SET expires_at =
                        CASE
                            WHEN expires_at IS NULL OR expires_at < now() THEN now() + (%s * interval '1 hour')
                            ELSE expires_at + (%s * interval '1 hour')
                        END
                    WHERE route_id=%s
                      AND active=true
                      AND code_hash = crypt(%s, code_hash)
                    RETURNING code_ciphertext, active, expires_at, created_at
                    """,
                    (ttl_hours, ttl_hours, route_id, code_plain),
                )
                row = fetchone_dict(cur)
                if not row:
                    cur.execute(
                        """
                        SELECT code_ciphertext, active, expires_at, created_at
                        FROM route_codes
                        WHERE route_id=%s
                          AND code_hash = crypt(%s, code_hash)
                        """,
                        (route_id, code_plain),
                    )
                    existing = fetchone_dict(cur)
                    if existing and not existing["active"]:
                        raise HTTPException(409, "Revoked code cannot be extended")
                    raise HTTPException(404, "Code not found")
        return {
            "ok": True,
            "route_id": route_id,
            "route_number": route.get("route_number"),
            "ttl_hours": ttl_hours,
            "code": _route_code_payload(row, route_id, route.get("route_number")),
        }
    finally:
        put_ops(conn)


@app.get("/admin/routes/{route_id}/addresses")
def list_route_addresses(request: Request, route_id: str, limit: int = 2000):
    _, u = _ctx(request)
    route = require_route_in_scope(u, route_id)
    limit = max(1, min(int(limit), 5000))
    conn = get_ops()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    a.address_id,
                    a.route_id,
                    r.route_number,
                    a.street,
                    a.house,
                    a.postcode,
                    a.full_address,
                    a.source,
                    a.created_at,
                    COUNT(f.flat_id)::int AS flats_total,
                    COUNT(*) FILTER (WHERE f.status='answered')::int AS flats_answered,
                    COUNT(*) FILTER (WHERE f.status='in_progress')::int AS flats_in_progress,
                    COUNT(*) FILTER (WHERE f.status='unvisited')::int AS flats_unvisited
                FROM addresses a
                JOIN routes r ON r.route_id = a.route_id
                LEFT JOIN flats f ON f.address_id = a.address_id
                WHERE a.route_id=%s
                GROUP BY a.address_id, a.route_id, r.route_number, a.street, a.house, a.postcode, a.full_address, a.source, a.created_at
                ORDER BY lower(a.street), lower(a.house), a.created_at
                LIMIT %s
                """,
                (route_id, limit),
            )
            rows = fetchall_dict(cur)
        return {
            "ok": True,
            "route_id": route_id,
            "route_number": route.get("route_number"),
            "count": len(rows),
            "addresses": rows,
        }
    finally:
        put_ops(conn)


def _stream_csv(headers: list[str], rows):
    def gen():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(headers)
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate(0)
        for r in rows:
            w.writerow([_csv_cell(r.get(h)) for h in headers])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    return gen()


def _slug_col(s: str) -> str:
    v = re.sub(r"[^a-zA-Z0-9]+", "_", str(s or "").strip().lower()).strip("_")
    return v or "value"


def _flatten_answer_value(prefix: str, value, out: dict[str, object]) -> None:
    if isinstance(value, dict):
        for k in sorted(value.keys(), key=lambda x: str(x)):
            _flatten_answer_value(f"{prefix}__{_slug_col(str(k))}", value[k], out)
        return
    if isinstance(value, list):
        for i, item in enumerate(value, start=1):
            _flatten_answer_value(f"{prefix}_{i}", item, out)
        return
    out[prefix] = value


def _flatten_answers_json(value) -> dict[str, object]:
    if value in (None, ""):
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return {"answers_raw": value}
    if not isinstance(value, dict):
        return {"answers_raw": json.dumps(value, ensure_ascii=False)}

    out: dict[str, object] = {}
    for k in sorted(value.keys(), key=str):
        _flatten_answer_value(str(k), value[k], out)
    return out


def _csv_cell(v):
    if v is None:
        return ""
    if isinstance(v, str):
        if v and v[0] in ("=", "+", "-", "@", "\t", "\r"):
            return "'" + v
        return v
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)
    return v


@app.get("/admin/routes/export.csv")
def export_routes(request: Request, route_id: Optional[str] = None):
    _, u = _ctx(request)
    cap = _export_row_cap()
    conn = get_ops()
    try:
        with conn.cursor() as cur:
            if route_id:
                require_route_in_scope(u, route_id)
                cur.execute(
                    """
                    SELECT route_id, name, active, borough_id, area_id, route_number, created_at
                    FROM routes
                    WHERE route_id=%s
                    LIMIT %s
                    """,
                    (route_id, cap + 1),
                )
            else:
                where, params = route_scope_where(u, route_alias="r")
                cur.execute(
                    f"""
                    SELECT r.route_id, r.name, r.active, r.borough_id, r.area_id, r.route_number, r.created_at
                    FROM routes r
                    WHERE ({where})
                    ORDER BY r.created_at DESC
                    LIMIT %s
                    """,
                    (*params, cap + 1),
                )
            rows = fetchall_dict(cur)
            if len(rows) > cap:
                raise HTTPException(
                    413, f"Export too large. Narrow filters (max {cap} rows)."
                )

        headers = [
            "route_id",
            "name",
            "active",
            "borough_id",
            "area_id",
            "route_number",
            "created_at",
        ]
        return StreamingResponse(
            _stream_csv(headers, rows),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="routes_export.csv"'},
        )
    finally:
        put_ops(conn)


@app.get("/admin/codes/export.csv")
def export_codes(request: Request, route_id: Optional[str] = None):
    _, u = _ctx(request)
    cap = _export_row_cap()
    conn = get_ops()
    try:
        with conn.cursor() as cur:
            if route_id:
                _ = require_route_in_scope(u, route_id)
                cur.execute(
                    """
                    SELECT rc.route_id, r.route_number, rc.code_ciphertext, rc.active, rc.expires_at, rc.created_at
                    FROM route_codes rc
                    JOIN routes r ON r.route_id = rc.route_id
                    WHERE rc.route_id=%s
                    ORDER BY rc.created_at DESC
                    LIMIT %s
                    """,
                    (route_id, cap + 1),
                )
            else:
                where, params = route_scope_where(u, route_alias="r")
                cur.execute(
                    f"""
                    SELECT rc.route_id, r.route_number, rc.code_ciphertext, rc.active, rc.expires_at, rc.created_at
                    FROM route_codes rc
                    JOIN routes r ON r.route_id = rc.route_id
                    WHERE ({where})
                    ORDER BY rc.created_at DESC
                    LIMIT %s
                    """,
                    (*params, cap + 1),
                )
            rows = fetchall_dict(cur)
            if len(rows) > cap:
                raise HTTPException(
                    413, f"Export too large. Narrow filters (max {cap} rows)."
                )

        logger.info(
            "AUDIT: route_codes export by %s: route_id=%r rows=%d",
            u.get("email"),
            route_id,
            len(rows),
        )

        out = []
        for r in rows:
            out.append(
                {
                    "route_id": r["route_id"],
                    "route_number": r["route_number"],
                    "code_plain": decrypt_text(r["code_ciphertext"]),
                    "active": r["active"],
                    "expires_at": r["expires_at"],
                    "created_at": r["created_at"],
                }
            )

        headers = [
            "route_id",
            "route_number",
            "code_plain",
            "active",
            "expires_at",
            "created_at",
        ]
        return StreamingResponse(
            _stream_csv(headers, out),
            media_type="text/csv",
            headers={
                "Content-Disposition": 'attachment; filename="route_codes_export.csv"'
            },
        )
    finally:
        put_ops(conn)


@app.get("/admin/statuses/export.csv")
def export_statuses(request: Request, route_id: Optional[str] = None):
    _, u = _ctx(request)
    cap = _export_row_cap()
    conn = get_ops()
    try:
        with conn.cursor() as cur:
            if route_id:
                _ = require_route_in_scope(u, route_id)
                cur.execute(
                    """
                    SELECT r.route_id, r.route_number, r.borough_id, r.area_id,
                           a.address_id, a.street, a.house, a.postcode, a.full_address,
                           f.flat_id, f.flat_label, f.flat_number, f.resident_name,
                           f.elector_id, f.status, f.updated_at
                    FROM addresses a
                    JOIN routes r ON r.route_id=a.route_id
                    LEFT JOIN flats f ON f.address_id=a.address_id
                    WHERE r.route_id=%s
                    ORDER BY lower(a.street), lower(a.house), lower(COALESCE(f.flat_label, ''))
                    LIMIT %s
                    """,
                    (route_id, cap + 1),
                )
            else:
                where, params = route_scope_where(u, route_alias="r")
                cur.execute(
                    f"""
                    SELECT r.route_id, r.route_number, r.borough_id, r.area_id,
                           a.address_id, a.street, a.house, a.postcode, a.full_address,
                           f.flat_id, f.flat_label, f.flat_number, f.resident_name,
                           f.elector_id, f.status, f.updated_at
                    FROM addresses a
                    JOIN routes r ON r.route_id=a.route_id
                    LEFT JOIN flats f ON f.address_id=a.address_id
                    WHERE ({where})
                    ORDER BY r.area_id, lower(a.street), lower(a.house), lower(COALESCE(f.flat_label, ''))
                    LIMIT %s
                    """,
                    (*params, cap + 1),
                )
            rows = fetchall_dict(cur)
            if len(rows) > cap:
                raise HTTPException(
                    413, f"Export too large. Narrow filters (max {cap} rows)."
                )
            rows = _include_flat_in_full_address(rows)

        headers = [
            "route_id",
            "route_number",
            "borough_id",
            "area_id",
            "address_id",
            "street",
            "house",
            "postcode",
            "full_address",
            "flat_id",
            "flat_label",
            "flat_number",
            "resident_name",
            "elector_id",
            "status",
            "updated_at",
        ]
        return StreamingResponse(
            _stream_csv(headers, rows),
            media_type="text/csv",
            headers={
                "Content-Disposition": 'attachment; filename="statuses_export.csv"'
            },
        )
    finally:
        put_ops(conn)


@app.get("/admin/answers/export.csv")
def export_answers(request: Request, route_id: Optional[str] = None):
    """
    Export answers from ANSWERS DB. Requires responses.borough_id + responses.area_id migration.
    """
    _, u = _ctx(request)

    # Determine scope filters for answers_db.responses
    role = u.get("role")
    borough_id = u.get("borough_id")
    area_ids = u.get("area_ids") or []
    cap = _export_row_cap()

    conn = get_answers_admin()
    try:
        with conn.cursor() as cur:
            if route_id:
                # Route-scoped: ensure allowed via OPS check, then filter by route_id
                _ = require_route_in_scope(u, route_id)
                cur.execute(
                    """
                    SELECT submitted_at, borough_id, area_id, route_id, full_address, flat_label,
                           postcode, elector_id,
                           canvasser_email, canvasser_name, contact_status, answers_json
                    FROM responses
                    WHERE route_id=%s
                    ORDER BY submitted_at DESC
                    LIMIT %s
                    """,
                    (route_id, cap + 1),
                )
            else:
                if role == "GLOBAL_ADMIN":
                    cur.execute(
                        """
                        SELECT submitted_at, borough_id, area_id, route_id, full_address, flat_label,
                               postcode, elector_id,
                               canvasser_email, canvasser_name, contact_status, answers_json
                        FROM responses
                        ORDER BY submitted_at DESC
                        LIMIT %s
                        """,
                        (cap + 1,),
                    )
                elif role == "BOROUGH_ADMIN":
                    if not borough_id:
                        raise HTTPException(403, "Borough admin missing borough_id")
                    cur.execute(
                        """
                        SELECT submitted_at, borough_id, area_id, route_id, full_address, flat_label,
                               postcode, elector_id,
                               canvasser_email, canvasser_name, contact_status, answers_json
                        FROM responses
                        WHERE borough_id=%s
                        ORDER BY submitted_at DESC
                        LIMIT %s
                        """,
                        (borough_id, cap + 1),
                    )
                elif role == "AREA_USER":
                    if not area_ids:
                        # no areas assigned => no rows
                        cur.execute(
                            """
                            SELECT submitted_at, borough_id, area_id, route_id, full_address, flat_label,
                                   postcode, elector_id,
                                   canvasser_email, canvasser_name, contact_status, answers_json
                            FROM responses
                            WHERE FALSE
                            LIMIT %s
                            """,
                            (cap + 1,),
                        )
                    else:
                        cur.execute(
                            """
                            SELECT submitted_at, borough_id, area_id, route_id, full_address, flat_label,
                                   postcode, elector_id,
                                   canvasser_email, canvasser_name, contact_status, answers_json
                            FROM responses
                            WHERE area_id = ANY(%s)
                            ORDER BY submitted_at DESC
                            LIMIT %s
                            """,
                            (area_ids, cap + 1),
                        )
                else:
                    raise HTTPException(403, "Invalid role")

            rows = cur.fetchall()
            if len(rows) > cap:
                raise HTTPException(
                    413, f"Export too large. Narrow filters (max {cap} rows)."
                )
            cols = [d.name for d in cur.description]

        row_dicts = _include_flat_in_full_address([dict(zip(cols, r)) for r in rows])
        base_cols = [c for c in cols if c != "answers_json"]
        answer_cols: list[str] = []
        seen_answer_cols: set[str] = set()

        for row in row_dicts:
            flat = _flatten_answers_json(row.get("answers_json"))
            row.pop("answers_json", None)
            for k, v in flat.items():
                row[k] = v
                if k not in seen_answer_cols:
                    seen_answer_cols.add(k)
                    answer_cols.append(k)

        export_cols = base_cols + answer_cols

        def gen():
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(export_cols)
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)
            for r in row_dicts:
                w.writerow([_csv_cell(r.get(c)) for c in export_cols])
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate(0)

        return StreamingResponse(
            gen(),
            media_type="text/csv",
            headers={
                "Content-Disposition": 'attachment; filename="answers_export.csv"'
            },
        )
    finally:
        put_answers_admin(conn)


@app.get("/admin/survey", response_class=HTMLResponse)
def survey_page(request: Request):
    _, user = _ctx(request)
    require_any_role(user, ["GLOBAL_ADMIN"])
    return templates.TemplateResponse(request, "survey.html", {"user": user})


@app.get("/admin/api/survey")
def survey_get(request: Request):
    _, user = _ctx(request)
    require_any_role(user, ["GLOBAL_ADMIN"])
    return load_survey(archived=True)


@app.post("/admin/api/survey")
async def survey_change(request: Request):
    email, user = _ctx(request)
    require_any_role(user, ["GLOBAL_ADMIN"])
    return change_survey(await json_object_body(request), email)


@app.post("/admin/api/request-code")
async def admin_request_code(request: Request, background_tasks: BackgroundTasks):
    body = await json_object_body(request)
    return request_code(
        body.get("email"), "admin", client_ip(request), background_tasks
    )
