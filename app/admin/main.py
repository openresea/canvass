import csv
import io
import json
import os
import re
import secrets
from datetime import datetime, timezone

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.common.auth import (
    ADMIN_SESSION_COOKIE,
    create_admin_session,
    delete_admin_session,
    load_user_context,
    require_admin_session,
    require_any_role,
    require_route_in_scope,
    require_scope_for_area,
    route_scope_where,
)
from app.common.crypto import decrypt_text, encrypt_text
from app.common.db import (
    get_answers_admin,
    get_ops,
    init_pools,
    put_answers_admin,
    put_ops,
)
from app.common.email_auth import enforce_limits, request_code, verify_code
from app.common.security import client_ip, install_security, json_body
from app.common.survey import change_survey, load_survey
from app.common.util import fetchall_dict, fetchone_dict

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
install_security(app, write_prefix="/admin/")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory=["app/admin/templates", "app/templates"])

ALLOWED_MANAGEMENT_ROLES = ["GLOBAL_ADMIN", "BOROUGH_ADMIN", "AREA_USER"]
# No 0/O or 1/I so codes can be read out over the phone.
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
# Accepted CSV headings for each field, first match wins. The second names
# match the electoral-register style export.
CSV_COLUMNS = {
    "street": ("street", "street_name"),
    "house": ("house", "building", "house_number"),
    "postcode": ("postcode",),
    "flat": ("flat_number", "flat"),
    "name": ("resident_name", "name"),
    "elector_id": ("elector_id",),
}


def _norm(s: str | None) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())


def _with_flat(full_address: str, flat: str | None) -> str:
    flat = _norm(flat)
    if not flat:
        return full_address
    if not re.match(r"(?:flat|apartment|apt|unit)\b", flat, flags=re.IGNORECASE):
        flat = f"Flat {flat}"
    return f"{flat}, {full_address}"


def _export_row_cap() -> int:
    return max(1000, int(os.environ.get("ADMIN_EXPORT_MAX_ROWS") or 50000))


def _new_route_id(area_id: str) -> str:
    # Example: LOCAL_CENTRAL_20260221_204500_ABC
    date = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{area_id}_{date}_{secrets.token_hex(2).upper()}"


def _validate_route_number(route_number: int | None) -> int | None:
    if route_number is not None and not 1 <= route_number <= 999999:
        raise HTTPException(400, "The walk number needs to be between 1 and 999999.")
    return route_number


def _ttl(hours) -> int:
    try:
        return max(1, min(int(hours or 24), 24 * 30))
    except (ValueError, TypeError):
        raise HTTPException(400, "Please enter the number of hours as a whole number.")


def _route_code_payload(row: dict) -> dict:
    if not row["active"]:
        status = "revoked"
    elif row["expires_at"] is not None and row["expires_at"] <= datetime.now(
        timezone.utc
    ):
        status = "expired"
    else:
        status = "working"
    return {
        "route_id": row["route_id"],
        "route_number": row["route_number"],
        "code_plain": decrypt_text(row["code_ciphertext"]),
        "active": row["active"],
        "expires_at": row["expires_at"],
        "created_at": row["created_at"],
        "status": status,
    }


@app.on_event("startup")
def _startup():
    init_pools()


@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)


def _login_page(request: Request):
    return templates.TemplateResponse(request, "signin.html", {"is_admin": True})


def _ctx(req: Request):
    email = (require_admin_session(req).get("email") or "").strip().lower()
    u = load_user_context(email)
    require_any_role(u, ALLOWED_MANAGEMENT_ROLES)
    return email, u


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
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


@app.post("/admin/api/request-code")
def admin_request_code(
    request: Request, background_tasks: BackgroundTasks, body: dict = Depends(json_body)
):
    return request_code(
        body.get("email"), "admin", client_ip(request), background_tasks
    )


@app.post("/admin/api/login")
def admin_login(request: Request, body: dict = Depends(json_body)):
    enforce_limits("admin", client_ip(request), verification=True)
    email = verify_code(body, "admin")
    u = load_user_context(email)
    require_any_role(u, ALLOWED_MANAGEMENT_ROLES)
    resp = JSONResponse({"ok": True, "email": email, "role": u["role"]})
    resp.set_cookie(
        key=ADMIN_SESSION_COOKIE,
        value=create_admin_session(email),
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


@app.post("/admin/routes/upload.csv")
def upload_routes_csv(
    request: Request,
    area_id: str,
    route_number: int | None = None,
    file: UploadFile = File(...),
):
    """
    Needs a street column. House, flat, postcode, resident name and elector ID
    are optional and may be blank on some rows: names are often known for only
    part of a route.
    """
    email, u = _ctx(request)
    require_scope_for_area(u, area_id)
    route_number = _validate_route_number(route_number)

    reader = csv.DictReader(
        io.TextIOWrapper(file.file, encoding="utf-8-sig", newline="")
    )
    try:
        headers = {h.strip().lower() for h in (reader.fieldnames or [])}
    except UnicodeDecodeError:
        raise HTTPException(400, "We couldn't read that file. Please save it as a UTF-8 CSV and try again.")
    if not headers:
        raise HTTPException(400, "That file looks empty.")
    # Which heading the file uses for each field, if any.
    col = {
        field: next((h for h in names if h in headers), None)
        for field, names in CSV_COLUMNS.items()
    }
    if not col["street"]:
        raise HTTPException(
            400,
            "We couldn't find a street column in that file. Please add one called "
            "\"street\". House, flat_number, postcode and resident_name are optional.",
        )

    conn = get_ops()
    try:
        with conn, conn.cursor() as cur:
            cur.execute("SELECT borough_id FROM areas WHERE area_id=%s", (area_id,))
            a = fetchone_dict(cur)
            if not a:
                raise HTTPException(400, "We couldn't find that area. Please check the area ID.")
            route_id = _new_route_id(area_id)
            cur.execute(
                """
                INSERT INTO routes(route_id, name, active, borough_id, area_id, route_number, uploaded_by_email)
                VALUES (%s, %s, true, %s, %s, %s, %s)
                """,
                (
                    route_id,
                    f"Upload {route_id}",
                    a["borough_id"],
                    area_id,
                    route_number,
                    email,
                ),
            )

            address_ids: dict[tuple, str] = {}
            inserted_flats = named_residents = skipped = 0
            for row in reader:
                row = {
                    str(k).strip().lower(): v for k, v in row.items() if k is not None
                }
                street, house, postcode, flat, name, elector_id = (
                    _norm(row.get(col[f]) if col[f] else "")
                    for f in ("street", "house", "postcode", "flat", "name", "elector_id")
                )
                if not street:
                    skipped += 1
                    continue

                # The route is new, so lower-cased keys match the unique index exactly.
                key = (postcode.lower(), street.lower(), house.lower())
                if key not in address_ids:
                    full_address = f"{house} {street}".strip()
                    if postcode:
                        full_address += f", {postcode}"
                    cur.execute(
                        """
                        INSERT INTO addresses(route_id, street, house, postcode, full_address, source)
                        VALUES (%s,%s,%s,%s,%s,'uploaded')
                        RETURNING address_id
                        """,
                        (route_id, street, house, postcode, full_address),
                    )
                    address_ids[key] = str(cur.fetchone()[0])

                if not (flat or name or elector_id):
                    continue  # Address only; volunteers add people at the door.
                # Same labels the volunteer app uses, so two people with the same
                # name in different flats stay separate. A flat with no name still
                # gets a row, so volunteers can see the flat exists.
                if elector_id:
                    flat_label = elector_id
                elif name:
                    flat_label = f"{flat}::{name}" if flat else name
                else:
                    flat_label = flat
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
                        address_ids[key],
                        flat_label,
                        name or None,
                        elector_id or None,
                        flat or None,
                    ),
                )
                inserted_flats += 1
                named_residents += bool(name or elector_id)
    except UnicodeDecodeError:
        raise HTTPException(400, "We couldn't read that file. Please save it as a UTF-8 CSV and try again.")
    finally:
        put_ops(conn)
    return {
        "ok": True,
        "route_id": route_id,
        "route_number": route_number,
        "inserted_addresses": len(address_ids),
        "inserted_flats": inserted_flats,
        "named_residents": named_residents,
        "skipped": skipped,
    }


@app.post("/admin/routes/{route_id}/codes/generate")
def generate_code(request: Request, route_id: str, ttl_hours: int = 24):
    _, u = _ctx(request)
    route = require_route_in_scope(u, route_id)
    token = "".join(secrets.choice(CODE_ALPHABET) for _ in range(10))
    # The route ID prefix lets sign-in check only this route's codes.
    code_plain = f"{route_id}-{token}"
    conn = get_ops()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO route_codes(route_id, code_hash, code_ciphertext, active, expires_at)
                VALUES (%s, crypt(%s, gen_salt('bf', 12)), %s, true, now() + (%s * interval '1 hour'))
                RETURNING expires_at, created_at
                """,
                (route_id, code_plain, encrypt_text(code_plain), _ttl(ttl_hours)),
            )
            row = fetchone_dict(cur)
    finally:
        put_ops(conn)
    return {
        "ok": True,
        "route_id": route_id,
        "route_number": route["route_number"],
        "generated": 1,
        "ttl_hours": _ttl(ttl_hours),
        "codes": [{"code_plain": code_plain, **row}],
    }


def _list_codes(where: str, params: tuple, limit: int) -> dict:
    conn = get_ops()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT rc.route_id, r.route_number, rc.code_ciphertext, rc.active, rc.expires_at, rc.created_at
                FROM route_codes rc
                JOIN routes r ON r.route_id = rc.route_id
                WHERE {where}
                ORDER BY rc.route_id, rc.created_at DESC
                LIMIT %s
                """,
                (*params, limit),
            )
            codes = [_route_code_payload(r) for r in fetchall_dict(cur)]
    finally:
        put_ops(conn)
    return {"ok": True, "count": len(codes), "codes": codes}


@app.get("/admin/routes/codes")
def list_route_codes_all(request: Request, limit: int = 500):
    _, u = _ctx(request)
    where, params = route_scope_where(u)
    return _list_codes(f"({where})", params, max(1, min(limit, 2000)))


@app.get("/admin/routes/{route_id}/codes")
def list_route_codes(request: Request, route_id: str):
    _, u = _ctx(request)
    require_route_in_scope(u, route_id)
    return {"route_id": route_id, **_list_codes("rc.route_id=%s", (route_id,), 2000)}


def _change_code(
    request: Request, route_id: str, body: dict, set_sql: str, extra: tuple
):
    """Apply an UPDATE to one active code, identified by its plaintext value."""
    _, u = _ctx(request)
    require_route_in_scope(u, route_id)
    code_plain = str(body.get("code_plain") or "").strip()
    if not code_plain.startswith(f"{route_id}-"):
        raise HTTPException(400, "That code belongs to a different route.")
    conn = get_ops()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE route_codes rc SET {set_sql}
                FROM routes r
                WHERE r.route_id = rc.route_id AND rc.route_id=%s AND rc.active
                  AND rc.code_hash = crypt(%s, rc.code_hash)
                RETURNING rc.route_id, r.route_number, rc.code_ciphertext, rc.active,
                          rc.expires_at, rc.created_at
                """,
                (*extra, route_id, code_plain),
            )
            row = fetchone_dict(cur)
    finally:
        put_ops(conn)
    if not row:
        raise HTTPException(404, "We couldn't find a working code that matches. It may already be revoked.")
    return {"ok": True, "route_id": route_id, "code": _route_code_payload(row)}


@app.post("/admin/routes/{route_id}/codes/revoke")
def revoke_route_code(request: Request, route_id: str, body: dict = Depends(json_body)):
    return _change_code(request, route_id, body, "active=false", ())


@app.post("/admin/routes/{route_id}/codes/extend")
def extend_route_code(request: Request, route_id: str, body: dict = Depends(json_body)):
    ttl = _ttl(body.get("ttl_hours"))
    return _change_code(
        request,
        route_id,
        body,
        "expires_at = GREATEST(COALESCE(rc.expires_at, now()), now()) + (%s * interval '1 hour')",
        (ttl,),
    )


@app.get("/admin/routes/{route_id}/addresses")
def list_route_addresses(request: Request, route_id: str, limit: int = 2000):
    _, u = _ctx(request)
    require_route_in_scope(u, route_id)
    conn = get_ops()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT a.address_id, a.route_id, r.route_number, a.street, a.house,
                       a.postcode, a.full_address, a.source, a.created_at,
                       COUNT(f.flat_id)::int AS flats_total,
                       COUNT(*) FILTER (WHERE f.status='answered')::int AS flats_answered,
                       COUNT(*) FILTER (WHERE f.status='unvisited')::int AS flats_unvisited
                FROM addresses a
                JOIN routes r ON r.route_id = a.route_id
                LEFT JOIN flats f ON f.address_id = a.address_id
                WHERE a.route_id=%s
                GROUP BY a.address_id, r.route_number
                ORDER BY lower(a.street), lower(a.house), a.created_at
                LIMIT %s
                """,
                (route_id, max(1, min(limit, 5000))),
            )
            rows = fetchall_dict(cur)
    finally:
        put_ops(conn)
    return {"ok": True, "route_id": route_id, "count": len(rows), "addresses": rows}


def _csv_cell(v):
    if v is None:
        return ""
    if isinstance(v, str):
        # Neutralise spreadsheet formulas.
        if v and v[0] in ("=", "+", "-", "@", "\t", "\r"):
            return "'" + v
        return v
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)
    return v


def _csv_response(filename: str, headers: list[str], rows: list[dict]):
    def gen():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(headers)
        for r in rows:
            w.writerow([_csv_cell(r.get(h)) for h in headers])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)
        yield buf.getvalue()

    return StreamingResponse(
        gen(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _scoped_export(conn, u, route_id: str | None, select_sql: str, order_sql: str):
    """Run an export query restricted to one in-scope route or the caller's whole scope.
    `select_sql` must expose the routes-like columns via alias `r`."""
    if route_id:
        require_route_in_scope(u, route_id)
        where, params = "r.route_id=%s", (route_id,)
    else:
        where, params = route_scope_where(u)
    cap = _export_row_cap()
    with conn.cursor() as cur:
        cur.execute(
            f"{select_sql} WHERE ({where}) ORDER BY {order_sql} LIMIT %s",
            (*params, cap + 1),
        )
        rows = fetchall_dict(cur)
    if len(rows) > cap:
        raise HTTPException(413, f"That export is over {cap:,} rows. Please enter a route ID to narrow it down.")
    return rows


@app.get("/admin/routes/export.csv")
def export_routes(request: Request, route_id: str | None = None):
    _, u = _ctx(request)
    headers = [
        "route_id",
        "name",
        "active",
        "borough_id",
        "area_id",
        "route_number",
        "created_at",
    ]
    conn = get_ops()
    try:
        rows = _scoped_export(
            conn,
            u,
            route_id,
            f"SELECT {', '.join('r.' + h for h in headers)} FROM routes r",
            "r.created_at DESC",
        )
    finally:
        put_ops(conn)
    return _csv_response("routes_export.csv", headers, rows)


STATUS_COLUMNS = [
    "r.route_id", "r.route_number", "r.borough_id", "r.area_id",
    "a.address_id", "a.street", "a.house", "a.postcode", "a.full_address",
    "f.flat_id", "f.flat_label", "f.flat_number", "f.resident_name",
    "f.elector_id", "f.status", "f.updated_at",
]  # fmt: skip


@app.get("/admin/statuses/export.csv")
def export_statuses(request: Request, route_id: str | None = None):
    _, u = _ctx(request)
    conn = get_ops()
    try:
        rows = _scoped_export(
            conn,
            u,
            route_id,
            f"""
            SELECT {", ".join(STATUS_COLUMNS)}
            FROM addresses a
            JOIN routes r ON r.route_id=a.route_id
            LEFT JOIN flats f ON f.address_id=a.address_id
            """,
            "r.area_id, lower(a.street), lower(a.house), lower(COALESCE(f.flat_label, ''))",
        )
    finally:
        put_ops(conn)
    for row in rows:
        row["full_address"] = _with_flat(row["full_address"], row["flat_number"])
    headers = [c.split(".", 1)[1] for c in STATUS_COLUMNS]
    return _csv_response("statuses_export.csv", headers, rows)


def _flatten(prefix: str, value, out: dict) -> None:
    if isinstance(value, dict):
        for k in sorted(value, key=str):
            key = re.sub(r"[^a-zA-Z0-9]+", "_", str(k).lower()).strip("_") or "value"
            _flatten(f"{prefix}__{key}" if prefix else key, value[k], out)
    elif isinstance(value, list):
        for i, item in enumerate(value, start=1):
            _flatten(f"{prefix}_{i}", item, out)
    else:
        out[prefix] = value


ANSWER_COLUMNS = [
    "submitted_at", "borough_id", "area_id", "route_id", "full_address",
    "flat_label", "postcode", "elector_id", "canvasser_email", "canvasser_name",
    "contact_status",
]  # fmt: skip


@app.get("/admin/answers/export.csv")
def export_answers(request: Request, route_id: str | None = None):
    _, u = _ctx(request)
    conn = get_answers_admin()
    try:
        # `responses` carries its own route/area/region columns, so it can be
        # aliased `r` and scoped exactly like the routes table.
        rows = _scoped_export(
            conn,
            u,
            route_id,
            f"SELECT {', '.join('r.' + c for c in ANSWER_COLUMNS)}, r.answers_json FROM responses r",
            "r.submitted_at DESC",
        )
    finally:
        put_answers_admin(conn)

    columns = list(ANSWER_COLUMNS)
    seen = set(columns)
    for row in rows:
        row["full_address"] = _with_flat(row["full_address"], row["flat_label"])
        flat: dict = {}
        _flatten("", row.pop("answers_json") or {}, flat)
        row.update(flat)
        columns += [k for k in flat if k not in seen]
        seen.update(flat)
    return _csv_response("answers_export.csv", columns, rows)


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
def survey_change(request: Request, body: dict = Depends(json_body)):
    email, user = _ctx(request)
    require_any_role(user, ["GLOBAL_ADMIN"])
    return change_survey(body, email)
