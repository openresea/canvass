from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import HTTPException

from app.common import email_auth
from app.common.db import POOLS


@pytest.fixture
def inbox(monkeypatch):
    messages = []
    monkeypatch.setattr(
        email_auth,
        "send_code",
        lambda email, code, purpose: messages.append((email, code, purpose)),
    )
    return messages


def request(db, inbox, purpose="admin", email="admin@example.test"):
    client = db.admin if purpose == "admin" else db.canvasser
    path = "/admin/api/request-code" if purpose == "admin" else "/api/request-code"
    r = client.post(path, json={"email": email})
    assert r.status_code == 200, r.text
    code = inbox[-1][1]
    return {"email": email, "code": code, "challenge_id": r.json()["challenge_id"]}


def test_admin_email_signin_cookie_and_single_use(db, inbox):
    body = request(db, inbox)
    assert len(body["code"]) == 6
    with db.ops.cursor() as cur:
        cur.execute(
            "SELECT code_digest FROM admin_login_codes WHERE challenge_id=%s",
            (body["challenge_id"],),
        )
        stored = cur.fetchone()[0]
        assert stored != body["code"] and len(stored) == 64
    r = db.admin.post("/admin/api/login", json=body)
    assert r.status_code == 200, r.text
    cookie = r.headers["set-cookie"].lower()
    assert "secure" in cookie and "httponly" in cookie and "samesite=lax" in cookie
    assert db.admin.post("/admin/api/login", json=body).status_code == 401


def test_five_wrong_guesses_lock_code_and_commit_attempts(db, inbox):
    body = request(db, inbox)
    bad = "000000" if body["code"] != "000000" else "111111"
    for _ in range(5):
        assert (
            db.admin.post("/admin/api/login", json={**body, "code": bad}).status_code
            == 401
        )
    assert db.admin.post("/admin/api/login", json=body).status_code == 401
    with db.ops.cursor() as cur:
        cur.execute("SELECT attempts,consumed FROM admin_login_codes")
        assert cur.fetchone() == (5, True)


def test_expired_code(db, inbox):
    body = request(db, inbox)
    with db.ops, db.ops.cursor() as cur:
        cur.execute("UPDATE admin_login_codes SET expires_at=now()-interval '1 second'")
    assert db.admin.post("/admin/api/login", json=body).status_code == 401


def test_admin_request_does_not_register_unknown_email(db, inbox):
    known = db.admin.post(
        "/admin/api/request-code", json={"email": "admin@example.test"}
    )
    count = len(inbox)
    unknown = db.admin.post(
        "/admin/api/request-code", json={"email": "stranger@example.test"}
    )
    assert known.status_code == unknown.status_code == 200
    assert known.json()["detail"] == unknown.json()["detail"]
    assert len(inbox) == count
    body = {
        "email": "stranger@example.test",
        "code": "123456",
        "challenge_id": unknown.json()["challenge_id"],
    }
    assert db.admin.post("/admin/api/login", json=body).status_code == 401


def test_resend_limits_and_old_code_invalidation(db, inbox):
    first = request(db, inbox)
    assert (
        db.admin.post(
            "/admin/api/request-code", json={"email": first["email"]}
        ).status_code
        == 429
    )
    with db.ops, db.ops.cursor() as cur:
        cur.execute("UPDATE email_auth_limits SET resets_at=now()-interval '1 second'")
    second = request(db, inbox)
    assert db.admin.post("/admin/api/login", json=first).status_code == 401
    assert db.admin.post("/admin/api/login", json=second).status_code == 200


def test_code_bound_to_email_and_purpose(db, inbox):
    body = request(db, inbox, "canvasser", "helper@another-provider.test")
    assert db.admin.post("/admin/api/login", json=body).status_code == 401
    wrong = {
        **body,
        "email": "someone-else@example.test",
        "display_name": "Helper",
        "route_code": db.route_code,
    }
    assert db.canvasser.post("/api/join", json=wrong).status_code == 401
    r = db.canvasser.post(
        "/api/join",
        json={**body, "display_name": "Helper", "route_code": db.route_code},
    )
    assert r.status_code == 200, r.text
    assert r.json()["route_id"] == "test-route"


def test_concurrent_verification_consumes_exactly_once(db, inbox):
    body = request(db, inbox)

    def attempt():
        try:
            email_auth.verify_code(body, "admin")
            return True
        except HTTPException:
            return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(lambda _: attempt(), range(2))) == [False, True]


def test_canvasser_db_role_cannot_read_admin_codes(db, inbox):
    import psycopg2

    request(db, inbox)
    db.canvasser.get("/api/survey?route_id=test-route")
    conn = POOLS.ops.getconn()
    try:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            with conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM admin_login_codes")
    finally:
        POOLS.ops.putconn(conn)


def test_signin_pages_have_no_external_identity_scripts(db):
    db.admin.cookies.clear()
    for page in [db.admin.get("/admin/login"), db.canvasser.get("/join")]:
        assert page.status_code == 200
        assert "Email me a sign-in code" in page.text
        assert "accounts.google.com" not in page.text
        assert "connect-src 'self';" in page.headers["content-security-policy"]


def test_join_only_checks_codes_for_the_named_route(db, inbox):
    body = request(db, inbox, "canvasser", "helper@example.test")
    for code in ["other-route-SAMPLE2345", "no-hyphen", db.route_code + "X"]:
        r = db.canvasser.post(
            "/api/join", json={**body, "display_name": "Helper", "route_code": code}
        )
        assert r.status_code == 403
        assert "route code didn't work" in r.json()["detail"]
