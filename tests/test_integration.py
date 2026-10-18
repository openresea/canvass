import uuid

import psycopg2
import pytest

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
    # Reusing a submission ID never overwrites the stored answer.
    reused = db.canvasser.post(
        "/api/responses?route_id=test-route", json={**body, "notes": "Different"}
    )
    assert reused.status_code == 200 and reused.json()["is_duplicate"]
    with db.answers.cursor() as cur:
        cur.execute("SELECT answers_json FROM responses")
        rows = cur.fetchall()
        assert len(rows) == 1
        assert rows[0][0]["notes"] == "Useful conversation"
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
    result = db.admin.post(
        "/admin/routes/test-route/codes/revoke", json={"code_plain": db.route_code}
    )
    assert result.status_code == 200, result.text
    assert result.json()["code"]["status"] == "revoked"
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
    plain = code.json()["codes"][0]["code_plain"]
    assert plain.startswith(route + "-")
    extended = db.admin.post(
        f"/admin/routes/{route}/codes/extend",
        json={"code_plain": plain, "ttl_hours": 2},
    )
    assert extended.status_code == 200, extended.text
    revoke = f"/admin/routes/{route}/codes/revoke"
    assert db.admin.post(revoke, json={"code_plain": plain}).status_code == 200
    assert db.admin.post(revoke, json={"code_plain": plain}).status_code == 404


def test_flat_from_another_route_is_rejected(db):
    survey = add(db)
    with db.ops, db.ops.cursor() as cur:
        cur.execute(
            "INSERT INTO addresses(route_id,street,house,postcode,full_address,source) VALUES ('other-route','Other Street','2','AB1','2 Other Street','manual') RETURNING address_id"
        )
        cur.execute(
            "INSERT INTO flats(address_id,flat_label) VALUES (%s,'Someone') RETURNING flat_id",
            (cur.fetchone()[0],),
        )
        other_flat = str(cur.fetchone()[0])
    r = db.canvasser.post(
        "/api/responses?route_id=test-route",
        json=payload(db, survey, flat_id=other_flat),
    )
    assert r.status_code == 404
    assert (
        db.canvasser.get(
            "/api/flats?route_id=test-route&address_id=not-a-uuid"
        ).status_code
        == 400
    )


def test_exports_are_scoped_and_have_headers(db):
    survey = add(db)
    db.canvasser.post("/api/responses?route_id=test-route", json=payload(db, survey))
    statuses = db.admin.get("/admin/statuses/export.csv").text.splitlines()
    assert statuses[0].startswith("route_id,route_number")
    assert any("Flat 1, 1 Example Street" in line for line in statuses)
    # The area user has no areas, so every export is empty apart from the header.
    for path in ["/admin/statuses/export.csv", "/admin/answers/export.csv"]:
        lines = db.limited.get(path).text.splitlines()
        assert len(lines) == 1 and lines[0].startswith(("route_id", "submitted_at"))


def test_sample_route_imports_flats_and_residents(db):
    with open("docs/sample-route.csv", "rb") as f:
        r = db.admin.post(
            "/admin/routes/upload.csv?area_id=LOCAL_CENTRAL",
            files={"file": ("sample-route.csv", f, "text/csv")},
        )
    assert r.status_code == 200, r.text
    assert r.json()["inserted_addresses"] == 5
    assert r.json()["named_residents"] == 7
    assert r.json()["inserted_flats"] == 9  # includes the two flats with no name


def import_csv(db, text):
    r = db.admin.post(
        "/admin/routes/upload.csv?area_id=LOCAL_CENTRAL",
        files={"file": ("route.csv", text, "text/csv")},
    )
    assert r.status_code == 200, r.text
    return r.json()["route_id"]


def test_names_on_some_rows_only(db):
    # No elector_id column, names on some rows, and the same name in two flats.
    route = import_csv(
        db,
        "street,house,flat_number,postcode,resident_name\n"
        "Example Street,3,A,AB1,Sam Example\n"
        "Example Street,3,B,AB1,Sam Example\n"
        "Example Street,3,C,AB1,\n"
        "Example Street,5,,AB1,\n",
    )
    with db.ops.cursor() as cur:
        cur.execute(
            """SELECT a.house, f.flat_number, f.resident_name
               FROM addresses a LEFT JOIN flats f USING (address_id)
               WHERE a.route_id=%s ORDER BY a.house, f.flat_number""",
            (route,),
        )
        assert cur.fetchall() == [
            ("3", "A", "Sam Example"),
            ("3", "B", "Sam Example"),
            ("3", "C", None),
            ("5", None, None),
        ]


def test_old_register_headings_still_work(db):
    route = import_csv(
        db,
        "elector_id,street_name,building,flat_number,postcode,resident_name\n"
        "EX-1,Example Street,7,,AB1,Alex Example\n"
        ",Example Street,8,,AB1,\n",
    )
    with db.ops.cursor() as cur:
        cur.execute(
            "SELECT count(*), count(f.flat_id) FROM addresses a "
            "LEFT JOIN flats f USING (address_id) WHERE a.route_id=%s",
            (route,),
        )
        assert cur.fetchone() == (2, 1)


def test_csv_without_street_column_is_explained(db):
    r = db.admin.post(
        "/admin/routes/upload.csv?area_id=LOCAL_CENTRAL",
        files={"file": ("route.csv", "house,postcode\n1,AB1\n", "text/csv")},
    )
    assert r.status_code == 400 and "street column" in r.json()["detail"]
