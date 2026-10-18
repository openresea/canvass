import json
import uuid

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.common.auth import (
    SESSION_COOKIE,
    require_session_for_route,
    validate_session_token,
)
from app.common.db import (
    get_answers_write,
    get_ops,
    init_pools,
    put_answers_write,
    put_ops,
)
from app.common.email_auth import enforce_limits, request_code, verify_code
from app.common.security import client_ip, install_security, json_body
from app.common.survey import load_survey, read_survey, validate_answers
from app.common.util import fetchall_dict, fetchone_dict

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
install_security(app, write_prefix="/api/")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory=["app/canvasser/templates", "app/templates"])

HOUSE_UNIT_LABEL = "House / whole address"
SPECIAL_PERSON_LABELS = {"Not known", "Whole household"}


@app.on_event("startup")
def _startup():
    init_pools(include_admin_pools=False)


@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)


@app.get("/")
def home():
    return RedirectResponse("/join")


@app.get("/join", response_class=HTMLResponse)
def join_page(request: Request):
    return templates.TemplateResponse(request, "signin.html", {"is_admin": False})


@app.post("/api/request-code")
def canvasser_request_code(
    request: Request, background_tasks: BackgroundTasks, body: dict = Depends(json_body)
):
    return request_code(
        body.get("email"), "canvasser", client_ip(request), background_tasks
    )


@app.post("/api/join")
def api_join(request: Request, body: dict = Depends(json_body)):
    route_code, display_name = body.get("route_code"), body.get("display_name")
    if not isinstance(route_code, str) or not isinstance(display_name, str):
        raise HTTPException(400, "Please enter your name and route code.")
    route_code, display_name = route_code.strip(), display_name.strip()
    if not route_code or not display_name:
        raise HTTPException(400, "Please enter your name and route code.")
    if len(route_code) > 512 or len(display_name) > 100:
        raise HTTPException(400, "Your name or route code is longer than expected. Could you check them?")

    # Rate-limit before the deliberately slow bcrypt comparison below.
    enforce_limits("canvasser", client_ip(request), verification=True)
    # Codes look like "<route_id>-<token>". Comparing only against that route's
    # codes bounds the bcrypt work per guess instead of scanning every code.
    route_id = route_code.rpartition("-")[0]
    conn = get_ops()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT c.code_hash
                FROM route_codes c
                JOIN routes r ON r.route_id=c.route_id AND r.active
                WHERE c.route_id=%s AND c.active
                  AND (c.expires_at IS NULL OR c.expires_at > now())
                  AND crypt(%s, c.code_hash) = c.code_hash
                LIMIT 1
                """,
                (route_id, route_code),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(403, "That route code didn't work. It may have expired, so check with your organiser.")
            email = verify_code(body, "canvasser")
            cur.execute(
                """
                INSERT INTO canvasser_sessions(email, display_name, route_id, code_hash, expires_at)
                VALUES (%s,%s,%s,%s, now() + interval '12 hours')
                RETURNING session_token
                """,
                (email, display_name, route_id, row[0]),
            )
            session_token = cur.fetchone()[0]
    finally:
        put_ops(conn)

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


@app.get("/r/{route_id}", response_class=HTMLResponse)
def route_page(route_id: str, request: Request):
    sess = require_session_for_route(request, route_id)
    return templates.TemplateResponse(
        request,
        "route.html",
        {"route_id": route_id, "surveyor_name": sess["display_name"]},
    )


@app.post("/api/addresses")
def addresses_create(request: Request, body: dict = Depends(json_body)):
    route_id = str(body.get("route_id") or "").strip()
    street = str(body.get("street") or "").strip()
    house = str(body.get("house") or "").strip()
    postcode = str(body.get("postcode") or "").strip()
    if not route_id or not street or not house:
        raise HTTPException(400, "Please enter a street and a house number or name.")
    if len(street) > 200 or len(house) > 100 or len(postcode) > 20:
        raise HTTPException(400, "That address is a bit too long. Please shorten it.")
    require_session_for_route(request, route_id)

    full_address = f"{house} {street}" + (f", {postcode}" if postcode else "")
    conn = get_ops()
    try:
        with conn, conn.cursor() as cur:
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
    require_session_for_route(request, route_id)
    limit = max(1, min(limit, 5000))
    conn = get_ops()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT address_id, street, house, postcode, full_address
                FROM addresses
                WHERE route_id=%s
                ORDER BY lower(street), lower(house), full_address
                LIMIT %s
                """,
                (route_id, limit),
            )
            return fetchall_dict(cur)
    finally:
        put_ops(conn)


def _uuid(value, name: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except ValueError:
        raise HTTPException(400, "Something went wrong there. Please reload the page and try again.")


def _address_in_route(cur, address_id: str, route_id: str) -> None:
    cur.execute(
        "SELECT 1 FROM addresses WHERE address_id=%s AND route_id=%s",
        (address_id, route_id),
    )
    if not cur.fetchone():
        raise HTTPException(404, "We couldn't find that address on your route. Please reload the page.")


@app.post("/api/flats")
def flats_create(request: Request, body: dict = Depends(json_body)):
    route_id = str(body.get("route_id") or "").strip()
    address_id = _uuid(body.get("address_id"), "address_id")
    flat_label = str(body.get("flat_label") or "").strip()
    flat_number = str(body.get("flat_number") or "").strip()
    resident_name = str(body.get("resident_name") or "").strip() or None

    if flat_label == HOUSE_UNIT_LABEL:
        flat_label = ""
    if flat_number == HOUSE_UNIT_LABEL:
        flat_number = ""
    if flat_label in SPECIAL_PERSON_LABELS and not resident_name:
        resident_name, flat_label = flat_label, ""
    if not flat_label and not resident_name:
        raise HTTPException(400, "Please enter a flat number or a resident's name.")
    if resident_name:
        flat_label = f"{flat_number}::{resident_name}" if flat_number else resident_name
    if max(len(flat_label), len(flat_number), len(resident_name or "")) > 200:
        raise HTTPException(400, "That flat number or name is a bit too long. Please shorten it.")

    require_session_for_route(request, route_id)
    conn = get_ops()
    try:
        with conn, conn.cursor() as cur:
            _address_in_route(cur, address_id, route_id)
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


# Who a flat row represents: a named resident, an elector, or a bare label.
PERSON_LABEL_SQL = """COALESCE(
    NULLIF(f.resident_name, ''),
    NULLIF(f.elector_id, ''),
    CASE WHEN COALESCE(f.flat_number, '') = '' THEN NULLIF(f.flat_label, '') END
)"""


@app.get("/api/flats")
def flats_list(request: Request, route_id: str, address_id: str):
    require_session_for_route(request, route_id)
    address_id = _uuid(address_id, "address_id")
    conn = get_ops()
    try:
        with conn.cursor() as cur:
            _address_in_route(cur, address_id, route_id)
            cur.execute(
                f"""
                SELECT f.flat_id, f.flat_number, f.resident_name, f.elector_id, f.status,
                       COALESCE(f.flat_number, '') AS unit_label,
                       {PERSON_LABEL_SQL} AS person_label
                FROM flats f
                WHERE f.address_id=%s
                ORDER BY lower(COALESCE(f.flat_number, '')),
                         lower(COALESCE(f.resident_name, f.elector_id, f.flat_label))
                """,
                (address_id,),
            )
            return fetchall_dict(cur)
    finally:
        put_ops(conn)


@app.post("/api/responses")
def submit_response(request: Request, route_id: str, body: dict = Depends(json_body)):
    sess = require_session_for_route(request, route_id)
    flat_id = _uuid(body.get("flat_id"), "flat_id")
    submission_id = _uuid(body.get("submission_id"), "submission_id")

    ops = get_ops()
    try:
        with ops, ops.cursor() as cur:
            status, answers = validate_answers(read_survey(cur), body)
            cur.execute(
                f"""
                SELECT f.address_id, f.elector_id,
                       COALESCE(f.flat_number, '') AS flat_label,
                       {PERSON_LABEL_SQL} AS resident_name,
                       a.full_address, a.postcode, r.area_id, r.borough_id
                FROM flats f
                JOIN addresses a ON a.address_id=f.address_id
                JOIN routes r ON r.route_id=a.route_id
                WHERE f.flat_id=%s AND a.route_id=%s
                """,
                (flat_id, route_id),
            )
            f = fetchone_dict(cur)
        if not f:
            raise HTTPException(404, "We couldn't find that person on your route. Please reload the page.")
        if f["resident_name"]:
            answers["resident_name"] = f["resident_name"]

        ans = get_answers_write()
        try:
            with ans, ans.cursor() as cur:
                # submission_id is unique, so a retried request inserts nothing.
                # The writer role is INSERT-only; rowcount is how we see a retry.
                cur.execute(
                    """
                    INSERT INTO responses(
                      submission_id, borough_id, area_id, route_id, address_id, flat_id,
                      full_address, flat_label, canvasser_email, canvasser_name,
                      contact_status, answers_json, postcode, elector_id
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)
                    ON CONFLICT DO NOTHING
                    """,
                    (
                        submission_id,
                        f["borough_id"],
                        f["area_id"],
                        route_id,
                        f["address_id"],
                        flat_id,
                        f["full_address"],
                        f["flat_label"],
                        sess["email"],
                        sess["display_name"],
                        status,
                        json.dumps(answers),
                        f["postcode"],
                        f["elector_id"],
                    ),
                )
                is_duplicate = cur.rowcount == 0
        finally:
            put_answers_write(ans)

        # Runs on retries too, so a status update lost after the answer was
        # written is repaired when the canvasser presses save again.
        with ops, ops.cursor() as cur:
            cur.execute(
                "UPDATE flats SET status=%s, updated_at=now() WHERE flat_id=%s",
                (status, flat_id),
            )
    finally:
        put_ops(ops)
    return {"ok": True, "submission_id": submission_id, "is_duplicate": is_duplicate}


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
