import uuid
from typing import Any, Dict, List, Tuple

from fastapi import HTTPException, Request

from app.common.db import get_ops, put_ops
from app.common.util import fetchall_dict, fetchone_dict

SESSION_COOKIE = "canvasser_session"
ADMIN_SESSION_COOKIE = "admin_session"


def require_session_for_route(req: Request, route_id: str) -> Dict[str, Any]:
    session_token = (req.cookies.get(SESSION_COOKIE) or "").strip()
    if not session_token:
        raise HTTPException(401, "Missing session cookie")

    validate_session_token(session_token)
    conn = get_ops()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT s.email, s.display_name, s.route_id, s.expires_at
                FROM canvasser_sessions s
                JOIN routes r ON r.route_id=s.route_id AND r.active
                JOIN route_codes c ON c.route_id=s.route_id AND c.code_hash=s.code_hash
                WHERE s.session_token=%s AND s.route_id=%s AND s.expires_at > now()
                  AND c.active AND (c.expires_at IS NULL OR c.expires_at > now())
                """,
                (session_token, route_id),
            )
            sess = fetchone_dict(cur)
            if not sess:
                raise HTTPException(401, "Invalid or expired session")
            return sess
    finally:
        put_ops(conn)


def create_admin_session(email: str) -> str:
    conn = get_ops()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO admin_sessions(email, expires_at)
                    VALUES (%s, now() + interval '12 hours')
                    RETURNING session_token
                    """,
                    (email,),
                )
                row = fetchone_dict(cur)
                if row is None:
                    raise RuntimeError(
                        "INSERT … RETURNING session_token returned no row"
                    )
                return str(row["session_token"])
    finally:
        put_ops(conn)


def require_admin_session(req: Request) -> Dict[str, Any]:
    session_token = (req.cookies.get(ADMIN_SESSION_COOKIE) or "").strip()
    if not session_token:
        raise HTTPException(401, "Missing admin session cookie")

    validate_session_token(session_token)
    conn = get_ops()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT email, expires_at
                FROM admin_sessions
                WHERE session_token=%s
                  AND expires_at > now()
                """,
                (session_token,),
            )
            sess = fetchone_dict(cur)
            if not sess:
                raise HTTPException(401, "Invalid or expired admin session")
            return sess
    finally:
        put_ops(conn)


def delete_admin_session(session_token: str) -> None:
    token = (session_token or "").strip()
    if not token:
        return
    validate_session_token(token)

    conn = get_ops()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM admin_sessions WHERE session_token=%s", (token,)
                )
    finally:
        put_ops(conn)


def load_user_context(email: str) -> Dict[str, Any]:
    """
    Load role + scope from OPS DB.
    Expected tables:
      users(email, role, borough_id)
      user_areas(email, area_id)
    """
    conn = get_ops()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT email, role::text AS role, borough_id FROM users WHERE lower(email)=lower(%s)",
                (email,),
            )
            u = fetchone_dict(cur)
            if not u:
                raise HTTPException(403, "No access")

            cur.execute(
                "SELECT area_id FROM user_areas WHERE lower(email)=lower(%s) ORDER BY area_id",
                (email,),
            )
            u["area_ids"] = [r["area_id"] for r in fetchall_dict(cur)]
            return u
    finally:
        put_ops(conn)


def require_any_role(u: Dict[str, Any], allowed: List[str]) -> None:
    role = u.get("role")
    if role not in set(allowed):
        raise HTTPException(403, "No access")


def require_scope_for_area(u: Dict[str, Any], area_id: str) -> None:
    """
    Enforce:
      GLOBAL_ADMIN: any area
      BOROUGH_ADMIN: any area within their borough
      AREA_USER: only areas explicitly assigned
    """
    role = u.get("role")
    if role == "GLOBAL_ADMIN":
        return

    if role == "AREA_USER":
        if area_id not in set(u.get("area_ids", [])):
            raise HTTPException(403, "No access")
        return

    if role == "BOROUGH_ADMIN":
        borough_id = u.get("borough_id")
        if not borough_id:
            raise HTTPException(403, "No access")
        conn = get_ops()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT borough_id FROM areas WHERE area_id=%s", (area_id,))
                a = fetchone_dict(cur)
                if not a or a["borough_id"] != borough_id:
                    raise HTTPException(403, "No access")
            return
        finally:
            put_ops(conn)

    raise HTTPException(403, "No access")


_ALLOWED_ROUTE_ALIASES = frozenset({"r", "rc", "rt"})


def route_scope_where(
    u: Dict[str, Any], route_alias: str = "r"
) -> Tuple[str, Tuple[Any, ...]]:
    """
    Returns (sql_fragment, params) to restrict routes by scope.
    Assumes routes table has borough_id and area_id columns.
    """
    if route_alias not in _ALLOWED_ROUTE_ALIASES:
        raise ValueError(f"Invalid route_alias: {route_alias!r}")

    role = u.get("role")
    if role == "GLOBAL_ADMIN":
        return ("TRUE", ())

    if role == "BOROUGH_ADMIN":
        borough_id = u.get("borough_id")
        if not borough_id:
            raise HTTPException(403, "No access")
        return (f"{route_alias}.borough_id = %s", (borough_id,))

    if role == "AREA_USER":
        area_ids = u.get("area_ids") or []
        if not area_ids:
            # No areas assigned => no access
            return ("FALSE", ())
        # psycopg2 can adapt Python list to Postgres array with ANY(%s)
        return (f"{route_alias}.area_id = ANY(%s)", (area_ids,))

    raise HTTPException(403, "No access")


def require_route_in_scope(u: Dict[str, Any], route_id: str) -> Dict[str, Any]:
    """
    Fetch route and ensure caller is allowed to operate on it.
    Returns route row with borough_id, area_id, route_number.
    """
    where, params = route_scope_where(u, route_alias="r")
    conn = get_ops()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT r.route_id, r.borough_id, r.area_id, r.route_number, r.active, r.name, r.created_at
                FROM routes r
                WHERE r.route_id = %s AND ({where})
                """,
                (route_id, *params),
            )
            r = fetchone_dict(cur)
            if not r:
                raise HTTPException(404, "Route not found or not in your scope")
            return r
    finally:
        put_ops(conn)


def validate_session_token(token):
    try:
        uuid.UUID(token)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(401, "Invalid or expired session")
