import hashlib
import json
import logging
import uuid
from typing import Any, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.body_limit import RequestBodyLimitMiddleware

from app.common.auth import (
    SESSION_COOKIE,
    require_session_for_route,
    validate_session_token,
)
from app.common.db import (
    POOLS,
    StorageUnavailableError,
    get_answers_write,
    get_ops,
    init_pools,
    put_answers_write,
    put_ops,
)
from app.common.email_auth import request_code, verify_code
from app.common.ratelimit import RateLimiter, client_ip
from app.common.security import (
    UNSAFE_HTTP_METHODS,
    install_trusted_host_middleware,
    json_object_body,
    new_csp_nonce,
    same_origin_write_request,
)
from app.common.survey import load_survey, read_survey, validate_answers
from app.common.util import fetchall_dict, fetchone_dict

# 20 join attempts per IP per 5 minutes — bcrypt makes each one slow regardless
_join_limiter = RateLimiter(max_calls=20, window_seconds=300)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
install_trusted_host_middleware(app)
app.add_middleware(RequestBodyLimitMiddleware, max_body_size=6 * 1024 * 1024)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory=["app/canvasser/templates", "app/templates"])
logger = logging.getLogger(__name__)


def _area_and_borough_from_route_id(
    route_id: str,
) -> tuple[Optional[str], Optional[str]]:
    parts = str(route_id or "").split("_")
    if len(parts) < 4:
        return None, None
    area_id = "_".join(parts[:-3]).strip() or None
    if not area_id:
        return None, None
    borough_id = area_id.split("_", 1)[0].strip() or None
    return area_id, borough_id


@app.on_event("startup")
def _startup():
    init_pools(include_admin_pools=False)
    if POOLS.answers_write is None:
        logger.warning("Answers writer storage unavailable at startup.")


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
    if request.method in UNSAFE_HTTP_METHODS and request.url.path.startswith("/api/"):
        if not same_origin_write_request(request):
            logger.warning(
                "CSRF blocked: path=%s host=%r origin_present=%s referer_present=%s sec-fetch-site=%r",
                request.url.path,
                request.headers.get("host"),
                bool(request.headers.get("origin")),
                bool(request.headers.get("referer")),
                request.headers.get("sec-fetch-site"),
            )
            return JSONResponse({"detail": "Access denied"}, status_code=403)
    return await call_next(request)


def _public_api_error_detail(status_code: int) -> str:
    if status_code == 401:
        return "Authentication required."
    if status_code == 403:
        return "Access denied."
    if status_code == 409:
        return "Request conflict. Please reload and try again."
    if status_code == 503:
        return "Service temporarily unavailable. Please retry."
    if status_code >= 500:
        return "Server error. Please try again."
    return "Request failed."


@app.exception_handler(HTTPException)
async def http_exception_scrubber(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            {
                "detail": str(exc.detail)
                if exc.status_code in (400, 409, 413)
                else _public_api_error_detail(exc.status_code)
            },
            status_code=exc.status_code,
        )
    return JSONResponse({"detail": str(exc.detail)}, status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def request_validation_scrubber(request: Request, exc: RequestValidationError):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": _public_api_error_detail(400)}, status_code=400)
    return JSONResponse({"detail": "Invalid request"}, status_code=400)


@app.exception_handler(Exception)
async def unhandled_exception_scrubber(request: Request, exc: Exception):
    logger.exception("Unhandled exception")
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": _public_api_error_detail(500)}, status_code=500)
    return JSONResponse({"detail": "Server error"}, status_code=500)


@app.exception_handler(StorageUnavailableError)
async def storage_unavailable_handler(request: Request, exc: StorageUnavailableError):
    logger.warning("Storage unavailable: %s", exc)
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": _public_api_error_detail(503)}, status_code=503)
    return JSONResponse({"detail": "Service temporarily unavailable"}, status_code=503)


@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse('<a href="/join">Go to /join</a>')


@app.get("/join", response_class=HTMLResponse)
def join_page(request: Request):
    return templates.TemplateResponse(
        request,
        "signin.html",
        {"is_admin": False},
    )


@app.post("/api/join")
async def api_join(request: Request):
    if not _join_limiter.is_allowed(client_ip(request)):
        raise HTTPException(429, "Too many requests")
    body = await json_object_body(request)
    if not isinstance(body.get("route_code"), str) or not isinstance(
        body.get("display_name"), str
    ):
        raise HTTPException(400, "Enter your name and route code.")
    route_code = body["route_code"].strip()
    display_name = body["display_name"].strip()
    if not route_code or not display_name:
        raise HTTPException(400, "Your name and route code are required")
    if len(route_code) > 512:
        raise HTTPException(400, "route_code too long")
    if len(display_name) > 100:
        raise HTTPException(400, "display_name too long")

    conn = get_ops()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT route_id, code_hash
                    FROM route_codes
                    WHERE active=true
                      AND (expires_at IS NULL OR expires_at > now())
                      AND crypt(%s, code_hash) = code_hash
                    LIMIT 1
                    """,
                    (route_code,),
                )
                r = fetchone_dict(cur)
                if not r:
                    raise HTTPException(403, "Wrong or expired route code")

                route_id = r["route_id"]

                cur.execute("SELECT active FROM routes WHERE route_id=%s", (route_id,))
                rr = fetchone_dict(cur)
                if not rr or not rr["active"]:
                    raise HTTPException(403, "Route not active")

                email = verify_code(body, "canvasser", client_ip(request))
                cur.execute(
                    """
                    INSERT INTO canvasser_sessions(email, display_name, route_id, code_hash, expires_at)
                    VALUES (%s,%s,%s,%s, now() + interval '12 hours')
                    RETURNING session_token
                    """,
                    (email, display_name, route_id, r["code_hash"]),
                )
                session_token = fetchone_dict(cur)["session_token"]

        resp = JSONResponse({"ok": True, "route_id": route_id})
        resp.set_cookie(
            key=SESSION_COOKIE,
            value=str(session_token),
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=60 * 60 * 12,
        )
        return resp
    finally:
        put_ops(conn)


@app.get("/api/me")
def api_me(request: Request, route_id: str):
    sess = require_session_for_route(request, route_id)
    return {
        "email": sess["email"],
        "display_name": sess["display_name"],
        "route_id": sess["route_id"],
    }


@app.get("/r/{route_id}", response_class=HTMLResponse)
def route_page(route_id: str, request: Request):
    sess = require_session_for_route(request, route_id)
    return templates.TemplateResponse(
        request,
        "route.html",
        {
            "route_id": route_id,
            "surveyor_name": sess["display_name"],
        },
    )


@app.post("/api/addresses")
async def addresses_create(request: Request):
    body = await json_object_body(request)
    route_id = (body.get("route_id") or "").strip()
    street = (body.get("street") or "").strip()
    house = (body.get("house") or "").strip()
    postcode = (body.get("postcode") or "").strip()

    if not route_id or not street or not house:
        raise HTTPException(400, "route_id, street, and house required")
    if len(route_id) > 200:
        raise HTTPException(400, "route_id too long")
    if len(street) > 200:
        raise HTTPException(400, "street too long")
    if len(house) > 100:
        raise HTTPException(400, "house too long")
    if len(postcode) > 20:
        raise HTTPException(400, "postcode too long")

    _ = require_session_for_route(request, route_id)

    full_address = f"{house} {street}"
    if postcode:
        full_address += f", {postcode}"

    conn = get_ops()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT route_id FROM routes WHERE route_id=%s AND active=true",
                    (route_id,),
                )
                if not fetchone_dict(cur):
                    raise HTTPException(404, "Route not found")

                cur.execute(
                    """
                    INSERT INTO addresses(route_id, street, house, postcode, full_address, source)
                    VALUES (%s, %s, %s, %s, %s, 'manual')
                    ON CONFLICT (route_id, lower(postcode), lower(street), lower(house))
                    DO UPDATE SET full_address = EXCLUDED.full_address
                    RETURNING address_id, street, house, postcode, full_address
                    """,
                    (route_id, street, house, postcode, full_address),
                )
                return fetchone_dict(cur)
    finally:
        put_ops(conn)


@app.get("/api/addresses/list")
def addresses_list(request: Request, route_id: str, limit: int = 200):
    _ = require_session_for_route(request, route_id)
    limit = max(1, min(int(limit), 5000))
    conn = get_ops()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT address_id, street, house, postcode, full_address
                FROM addresses
                WHERE route_id=%s
                ORDER BY lower(street) ASC, lower(house) ASC, full_address ASC
                LIMIT %s
                """,
                (route_id, limit),
            )
            return fetchall_dict(cur)
    finally:
        put_ops(conn)


HOUSE_UNIT_LABEL = "House / whole address"
SPECIAL_PERSON_LABELS = {"Not known", "Whole household"}


@app.post("/api/flats")
async def flats_create(request: Request):
    body = await json_object_body(request)
    route_id = (body.get("route_id") or "").strip()
    address_id = body.get("address_id")
    flat_label = (body.get("flat_label") or "").strip()
    flat_number = (body.get("flat_number") or body.get("unit_label") or "").strip()
    resident_name = (body.get("resident_name") or "").strip() or None

    if not route_id or not address_id:
        raise HTTPException(400, "route_id and address_id required")
    if len(route_id) > 200:
        raise HTTPException(400, "route_id too long")
    try:
        address_id = str(uuid.UUID(str(address_id)))
    except (ValueError, AttributeError):
        raise HTTPException(400, "address_id must be a valid UUID")
    if flat_label == HOUSE_UNIT_LABEL:
        flat_label = ""
    if flat_number == HOUSE_UNIT_LABEL:
        flat_number = ""
    if flat_label in SPECIAL_PERSON_LABELS and not resident_name:
        resident_name = flat_label
        flat_label = ""
    if not flat_label and not resident_name:
        raise HTTPException(400, "flat_label or resident_name required")
    if resident_name:
        flat_label = f"{flat_number}::{resident_name}" if flat_number else resident_name
    elif not flat_label:
        flat_label = flat_number or HOUSE_UNIT_LABEL
    if len(flat_label) > 200:
        raise HTTPException(400, "flat_label too long")
    if len(flat_number) > 200:
        raise HTTPException(400, "flat_number too long")
    if resident_name and len(resident_name) > 200:
        raise HTTPException(400, "resident_name too long")

    _ = require_session_for_route(request, route_id)

    conn = get_ops()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT route_id FROM addresses WHERE address_id=%s", (address_id,)
                )
                a = fetchone_dict(cur)
                if not a:
                    raise HTTPException(404, "Address not found")
                if a["route_id"] != route_id:
                    raise HTTPException(403, "Address not in this route")

                cur.execute(
                    """
                    INSERT INTO flats(address_id, flat_label, status, resident_name, flat_number)
                    VALUES (%s, %s, 'unvisited', %s, %s)
                    ON CONFLICT (address_id, lower(flat_label))
                    DO UPDATE SET resident_name = COALESCE(flats.resident_name, EXCLUDED.resident_name),
                                  flat_number = COALESCE(NULLIF(flats.flat_number, ''), EXCLUDED.flat_number)
                    RETURNING flat_id, status
                    """,
                    (address_id, flat_label, resident_name, flat_number or None),
                )
                return fetchone_dict(cur)
    finally:
        put_ops(conn)


@app.get("/api/flats")
def flats_list(request: Request, route_id: str, address_id: str):
    _ = require_session_for_route(request, route_id)

    conn = get_ops()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT route_id FROM addresses WHERE address_id=%s", (address_id,)
            )
            a = fetchone_dict(cur)
            if not a:
                raise HTTPException(404, "Address not found")
            if a["route_id"] != route_id:
                raise HTTPException(403, "Address not in this route")

            cur.execute(
                """
                SELECT flat_id, flat_label, flat_number, resident_name, elector_id, status,
                       COALESCE(NULLIF(flat_number, ''), '') AS unit_label,
                       COALESCE(
                         NULLIF(resident_name, ''),
                         NULLIF(elector_id, ''),
                         CASE
                           WHEN COALESCE(flat_number, '') = '' THEN NULLIF(flat_label, '')
                           ELSE NULL
                         END
                       ) AS person_label,
                       COALESCE(
                         NULLIF(resident_name, ''),
                         NULLIF(elector_id, ''),
                         CASE
                           WHEN COALESCE(flat_number, '') = '' THEN NULLIF(flat_label, '')
                           ELSE NULL
                         END
                       ) AS display_label
                FROM flats
                WHERE address_id=%s
                ORDER BY
                  lower(COALESCE(NULLIF(flat_number, ''), '')),
                  CASE status WHEN 'unvisited' THEN 1 WHEN 'answered' THEN 2 ELSE 99 END,
                  lower(COALESCE(resident_name, elector_id, flat_label)) ASC
                """,
                (address_id,),
            )
            return fetchall_dict(cur)
    finally:
        put_ops(conn)


def parse_submission_id(raw: Any) -> str:
    txt = str(raw or "").strip()
    if not txt:
        return str(uuid.uuid4())
    try:
        return str(uuid.UUID(txt))
    except Exception:
        raise HTTPException(400, "submission_id must be a valid UUID")


def submission_payload_sha256(
    route_id: str, flat_id: str, answers: dict, status: str
) -> str:
    payload = {
        "route_id": route_id,
        "flat_id": str(flat_id),
        "answers": answers,
        "contact_status": status,
    }
    blob = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def log_submission_event_best_effort(
    ops_conn,
    *,
    receipt_id: str,
    submission_id: str,
    db_name: str,
    stage: str,
    ok: bool,
    ref_id: Optional[str] = None,
    detail: Optional[str] = None,
) -> None:
    try:
        with ops_conn:
            with ops_conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO submission_receipt_events(receipt_id, submission_id, db_name, stage, ok, ref_id, detail)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        receipt_id,
                        submission_id,
                        db_name,
                        stage,
                        ok,
                        ref_id,
                        (detail or "")[:500] or None,
                    ),
                )
    except Exception:
        # Do not block the submission path if audit event logging fails.
        return


def safe_submission_error_detail(exc: Exception) -> str:
    if isinstance(exc, HTTPException):
        return "http_error"
    return "internal_error"


@app.post("/api/responses")
async def submit_response(request: Request, route_id: str):
    sess = require_session_for_route(request, route_id)
    email = sess["email"]
    name = sess["display_name"]

    body = await json_object_body(request)
    flat_id = body.get("flat_id")
    submission_id = parse_submission_id(body.get("submission_id"))

    if len(route_id) > 200:
        raise HTTPException(400, "route_id too long")
    if not flat_id:
        raise HTTPException(400, "flat_id required")
    try:
        flat_id = str(uuid.UUID(str(flat_id)))
    except (ValueError, AttributeError):
        raise HTTPException(400, "flat_id must be a valid UUID")

    ops = None
    ans = None
    receipt_id = None
    response_id = None
    f = None
    is_duplicate = False
    duplicate_reason = None
    duplicate_already_completed = False
    try:
        ops = get_ops()
        with ops:
            with ops.cursor() as cur:
                contact_status, answers_json = validate_answers(read_survey(cur), body)
                notes = answers_json["notes"]
                payload_sha256 = submission_payload_sha256(
                    route_id, str(flat_id), answers_json, contact_status
                )
                cur.execute(
                    """
                    SELECT f.flat_id, f.flat_label, f.flat_number, f.resident_name,
                           f.address_id, f.elector_id,
                           COALESCE(NULLIF(f.flat_number, ''), '') AS response_flat_label,
                           COALESCE(
                             NULLIF(f.resident_name, ''),
                             NULLIF(f.elector_id, ''),
                             CASE
                               WHEN COALESCE(f.flat_number, '') = '' THEN NULLIF(f.flat_label, '')
                               ELSE NULL
                             END
                           ) AS response_resident_name,
                           a.route_id, a.full_address, a.postcode, r.area_id, r.borough_id
                    FROM flats f
                    JOIN addresses a ON a.address_id=f.address_id
                    JOIN routes r ON r.route_id=a.route_id
                    WHERE f.flat_id=%s
                    FOR UPDATE OF f
                    """,
                    (flat_id,),
                )
                f = fetchone_dict(cur)
                if not f:
                    raise HTTPException(404, "Flat not found")
                if f["route_id"] != route_id:
                    raise HTTPException(403, "Flat not in this route")
                response_flat_label = f.get("response_flat_label") or ""
                response_resident_name = f.get("response_resident_name")
                if response_resident_name:
                    answers_json["resident_name"] = response_resident_name
                answer_keys_count = len(answers_json)

                cur.execute(
                    "SELECT pg_advisory_xact_lock(hashtext(%s))", (submission_id,)
                )

                cur.execute(
                    """
                    SELECT receipt_id, payload_sha256, canvasser_email FROM submission_receipts
                    WHERE submission_id=%s
                    ORDER BY received_at ASC, receipt_id ASC LIMIT 1
                    """,
                    (submission_id,),
                )
                prev_receipt = fetchone_dict(cur)
                if prev_receipt:
                    if (
                        prev_receipt["payload_sha256"] != payload_sha256
                        or prev_receipt["canvasser_email"] != email
                    ):
                        raise HTTPException(
                            409,
                            "This submission ID was already used for a different response.",
                        )
                    is_duplicate = True
                    duplicate_reason = "submission_id_reused"
                    cur.execute(
                        """
                        SELECT EXISTS (
                          SELECT 1
                          FROM submission_receipt_events
                          WHERE submission_id=%s
                            AND stage='ops_status_updated'
                            AND ok=true
                        ) AS completed
                        """,
                        (submission_id,),
                    )
                    duplicate_already_completed = bool(
                        (fetchone_dict(cur) or {}).get("completed")
                    )

                cur.execute(
                    """
                    INSERT INTO submission_receipts(
                      submission_id, route_id, address_id, flat_id,
                      full_address, flat_label, canvasser_email, canvasser_name,
                      contact_status, survey_kind,
                      revisit_requested, notes_present, answer_keys_count,
                      payload_sha256, is_duplicate, duplicate_of_receipt_id, duplicate_reason
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,false,%s,%s,%s,%s,%s,%s)
                    RETURNING receipt_id
                    """,
                    (
                        submission_id,
                        route_id,
                        f["address_id"],
                        flat_id,
                        f["full_address"],
                        response_flat_label,
                        email,
                        name,
                        contact_status,
                        bool(notes),
                        answer_keys_count,
                        payload_sha256,
                        is_duplicate,
                        prev_receipt["receipt_id"] if prev_receipt else None,
                        duplicate_reason,
                    ),
                )
                receipt_id = str(fetchone_dict(cur)["receipt_id"])
                cur.execute(
                    "INSERT INTO submission_receipt_events(receipt_id, submission_id, db_name, stage, ok) VALUES (%s,%s,'ops','received',true)",
                    (receipt_id, submission_id),
                )
                area_id, borough_id = f["area_id"], f["borough_id"]

        if duplicate_already_completed:
            return {
                "ok": True,
                "response_id": None,
                "submission_id": submission_id,
                "is_duplicate": True,
            }

        try:
            ans = get_answers_write()
        except StorageUnavailableError:
            raise HTTPException(503, "Service temporarily unavailable")

        with ans:
            with ans.cursor() as cur2:
                response_id = str(
                    # Stable across renames so retried submissions keep the same ID.
                    uuid.uuid5(uuid.NAMESPACE_URL, "open-canvass:" + submission_id)
                )
                cur2.execute(
                    """
                    INSERT INTO responses(
                      response_id, submission_id, borough_id, area_id,
                      route_id, address_id, flat_id, full_address, flat_label,
                      canvasser_email, canvasser_name,
                      contact_status, answers_json,
                      is_duplicate, duplicate_reason, postcode, elector_id
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s)
                    ON CONFLICT DO NOTHING
                    """,
                    (
                        response_id,
                        submission_id,
                        borough_id,
                        area_id,
                        route_id,
                        f["address_id"],
                        flat_id,
                        f["full_address"],
                        response_flat_label,
                        email,
                        name,
                        contact_status,
                        json.dumps(answers_json),
                        is_duplicate,
                        duplicate_reason,
                        f.get("postcode"),
                        f.get("elector_id"),
                    ),
                )

        if receipt_id is not None:
            log_submission_event_best_effort(
                ops,
                receipt_id=receipt_id,
                submission_id=submission_id,
                db_name="answers",
                stage="answers_written",
                ok=True,
                ref_id=response_id,
            )

        with ops:
            with ops.cursor() as cur3:
                cur3.execute(
                    "UPDATE flats SET status=%s, updated_at=now() WHERE flat_id=%s",
                    (contact_status, flat_id),
                )

        if receipt_id is not None:
            log_submission_event_best_effort(
                ops,
                receipt_id=receipt_id,
                submission_id=submission_id,
                db_name="ops",
                stage="ops_status_updated",
                ok=True,
            )

        return {
            "ok": True,
            "response_id": str(response_id),
            "submission_id": submission_id,
            "is_duplicate": is_duplicate,
        }
    except Exception as e:
        logger.error("submit_response failed")
        if ops is not None and receipt_id is not None:
            log_submission_event_best_effort(
                ops,
                receipt_id=receipt_id,
                submission_id=submission_id,
                db_name="ops",
                stage="failed",
                ok=False,
                detail=safe_submission_error_detail(e),
            )
        raise
    finally:
        if ops is not None:
            put_ops(ops)
        if ans is not None:
            put_answers_write(ans)


@app.get("/api/survey")
def survey_get(request: Request, route_id: str):
    require_session_for_route(request, route_id)
    return load_survey()


@app.post("/api/logout")
def logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        validate_session_token(token)
        conn = get_ops()
        try:
            with conn, conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM canvasser_sessions WHERE session_token=%s", (token,)
                )
        finally:
            put_ops(conn)
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, secure=True, httponly=True, samesite="lax")
    return response


@app.post("/api/request-code")
async def canvasser_request_code(request: Request, background_tasks: BackgroundTasks):
    body = await json_object_body(request)
    return request_code(
        body.get("email"), "canvasser", client_ip(request), background_tasks
    )
