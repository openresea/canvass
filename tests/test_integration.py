import uuid
import pytest
import psycopg2
from app.common.db import POOLS


def add(db, **changes):
    current = db.admin.get("/admin/api/survey").json()
    response = db.admin.post(
        "/admin/api/survey",
        json={
            "version": current["version"],
            "action": "add",
            "prompt": "What matters locally?",
            "kind": "single_choice",
            "options": ["Parks", "Transport"],
            "required": True,
            **changes,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def payload(db, survey, **kw):
    return {
        "flat_id": db.flat_id,
        "submission_id": str(uuid.uuid4()),
        "survey_version": survey["version"],
        "answers": {survey["questions"][0]["id"]: "Parks"},
        **kw,
    }


def test_survey_lifecycle_and_scope(db):
    assert db.limited.get("/admin/api/survey").status_code == 403
    assert db.limited.post("/admin/api/survey", json={}).status_code == 403
    assert db.limited.get("/admin/survey").status_code == 403
    survey = add(db)
    q = survey["questions"][0]
    changed = db.admin.post(
        "/admin/api/survey",
        json={
            "version": survey["version"],
            "action": "edit",
            "id": q["id"],
            "prompt": "Updated wording",
            "kind": "text",
            "required": False,
        },
    )
    assert changed.status_code == 200
    assert (
        db.admin.post(
            "/admin/api/survey",
            json={"version": survey["version"], "action": "archive", "id": q["id"]},
        ).status_code
        == 409
    )
    survey = changed.json()
    archived = db.admin.post(
        "/admin/api/survey",
        json={"version": survey["version"], "action": "archive", "id": q["id"]},
    ).json()
    assert not db.canvasser.get("/api/survey?route_id=test-route").json()["questions"]
    restored = db.admin.post(
        "/admin/api/survey",
        json={"version": archived["version"], "action": "restore", "id": q["id"]},
    )
    assert restored.status_code == 200
    assert not restored.json()["questions"][0]["archived"]
    with db.ops.cursor() as cur:
        cur.execute("SELECT count(*) FROM survey_audit")
        assert cur.fetchone()[0] == 4


def test_real_submission_retry_and_historical_snapshot(db):
    survey = add(db)
    body = payload(db, survey, notes="Useful conversation")
    result = db.canvasser.post("/api/responses?route_id=test-route", json=body)
    assert result.status_code == 200, result.text
    assert db.canvasser.post("/api/responses?route_id=test-route", json=body).json()[
        "is_duplicate"
    ]
    assert (
        db.canvasser.post(
            "/api/responses?route_id=test-route", json={**body, "notes": "Different"}
        ).status_code
        == 409
    )
    with db.answers.cursor() as cur:
        cur.execute("SELECT answers_json FROM responses")
        rows = cur.fetchall()
        assert len(rows) == 1
        assert (
            rows[0][0]["questions"][survey["questions"][0]["id"]]["prompt"]
            == "What matters locally?"
        )
    with db.ops.cursor() as cur:
        cur.execute("SELECT status FROM flats WHERE flat_id=%s", (db.flat_id,))
        assert cur.fetchone()[0] == "answered"
    assert (
        db.admin.post(
            "/admin/api/survey",
            json={
                "version": survey["version"],
                "action": "archive",
                "id": survey["questions"][0]["id"],
            },
        ).status_code
        == 200
    )
    export = db.admin.get("/admin/answers/export.csv")
    assert export.status_code == 200
    assert "What matters locally?" in export.text and "Parks" in export.text
    assert (
        db.canvasser.post(
            "/api/responses?route_id=test-route", json=payload(db, survey)
        ).status_code
        == 409
    )


@pytest.mark.parametrize("status", ["no_answer", "refused", "inaccessible"])
def test_non_conversation_outcomes(db, status):
    survey = add(db)
    result = db.canvasser.post(
        "/api/responses?route_id=test-route",
        json=payload(db, survey, answers={}, contact_status=status),
    )
    assert result.status_code == 200, result.text
    with db.ops.cursor() as cur:
        cur.execute("SELECT status FROM flats")
        assert cur.fetchone()[0] == status


def test_route_session_revoked_and_expired(db):
    assert db.canvasser.get("/api/survey?route_id=other-route").status_code == 401
    assert db.canvasser.get("/api/survey?route_id=test-route").status_code == 200
    result = db.admin.post("/admin/routes/test-route/codes/revoke_all")
    assert result.status_code == 200, result.text
    assert db.canvasser.get("/api/survey?route_id=test-route").status_code == 401
    with db.ops, db.ops.cursor() as cur:
        cur.execute(
            "UPDATE route_codes SET active=true,expires_at=now()-interval '1 second'"
        )
    assert db.canvasser.get("/api/survey?route_id=test-route").status_code == 401


def test_writer_cannot_read_answers_or_modify_survey(db):
    conn = POOLS.answers_write.getconn()
    try:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            with conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM responses")
    finally:
        POOLS.answers_write.putconn(conn)
    db.canvasser.get("/api/survey?route_id=test-route")
    conn = POOLS.ops.getconn()
    try:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            with conn, conn.cursor() as cur:
                cur.execute("UPDATE survey_state SET version=99")
    finally:
        POOLS.ops.putconn(conn)


def test_questions_move_and_xss_is_data(db):
    add(db)
    survey = add(db, prompt="<script>alert(1)</script>", kind="text", required=False)
    q = survey["questions"][1]
    result = db.admin.post(
        "/admin/api/survey",
        json={
            "version": survey["version"],
            "action": "move",
            "id": q["id"],
            "direction": "up",
        },
    )
    assert result.status_code == 200
    assert result.json()["questions"][0]["id"] == q["id"]
    page = db.admin.get("/admin/survey")
    assert page.status_code == 200 and "<script>alert(1)</script>" not in page.text
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]


def test_logout_invalidates_session(db):
    assert db.canvasser.post("/api/logout", json={}).status_code == 200
    assert db.canvasser.get("/api/survey?route_id=test-route").status_code == 401


def test_import_route_generate_and_revoke_code(db):
    response = db.admin.post(
        "/admin/routes/upload.csv?area_id=LOCAL_CENTRAL",
        files={
            "file": (
                "route.csv",
                "street,house,postcode\nExample Avenue,12,AB1 2CD\n",
                "text/csv",
            )
        },
    )
    assert response.status_code == 200, response.text
    route = response.json()["route_id"]
    code = db.admin.post(f"/admin/routes/{route}/codes/generate?ttl_hours=24")
    assert code.status_code == 200, code.text
    assert db.admin.get("/admin/routes/codes").status_code == 200
    assert (
        db.limited.get("/admin/answers/export.csv?route_id=" + route).status_code == 404
    )
    assert db.admin.post(f"/admin/routes/{route}/codes/revoke_all").status_code == 200
