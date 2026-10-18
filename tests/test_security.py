import asyncio
import pytest
from fastapi import HTTPException
from starlette.requests import Request
from fastapi.testclient import TestClient
from app.common.security import same_origin_write_request, json_object_body
from app.common.auth import validate_session_token
from app.common.ratelimit import client_ip
from app.common.survey import question_data, validate_answers
from app.admin.main import app as admin_app, _csv_cell
from app.canvasser.main import app as canvasser_app


def request(headers=(), scheme="https"):
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "scheme": scheme,
            "server": ("example.test", 443),
            "headers": [(b"host", b"example.test"), *headers],
            "client": ("127.0.0.1", 1),
            "query_string": b"",
        }
    )


@pytest.mark.parametrize(
    "headers,expected",
    [
        ([], False),
        ([(b"origin", b"https://example.test")], True),
        ([(b"origin", b"http://example.test")], False),
        ([(b"origin", b"https://evil.test")], False),
        ([(b"origin", b"null")], False),
        ([(b"origin", b"https://example.test:443")], True),
        (
            [(b"origin", b"https://example.test"), (b"sec-fetch-site", b"cross-site")],
            False,
        ),
        ([(b"referer", b"https://example.test/form")], True),
    ],
)
def test_csrf(headers, expected):
    assert same_origin_write_request(request(headers)) is expected


def test_spoofed_identity_and_ip_are_not_trusted(monkeypatch):
    r = request(
        [
            (b"x-goog-authenticated-user-email", b"admin@example.test"),
            (b"x-forwarded-for", b"1.2.3.4"),
        ]
    )
    assert client_ip(r) == "127.0.0.1"


def test_invalid_session_is_auth_failure():
    with pytest.raises(HTTPException) as e:
        validate_session_token("' OR 1=1")
    assert e.value.status_code == 401


def test_streaming_body_limit():
    chunks = iter([{"type": "http.request", "body": b"x" * 8, "more_body": True}] * 3)

    async def receive():
        return next(chunks)

    r = Request(request().scope, receive)
    with pytest.raises(HTTPException) as e:
        asyncio.run(json_object_body(r, max_bytes=10))
    assert e.value.status_code == 413


@pytest.mark.parametrize(
    "app,path",
    [(admin_app, "/admin/api/survey"), (canvasser_app, "/api/responses?route_id=x")],
)
def test_anonymous_and_cross_origin_writes(app, path):
    client = TestClient(app, base_url="https://testserver")
    assert client.post(path, json={}).status_code == 403
    assert (
        client.post(path, json={}, headers={"Origin": "https://evil.test"}).status_code
        == 403
    )
    assert (
        client.post(path, json={}, headers={"Origin": "https://testserver"}).status_code
        == 401
    )
    assert (
        client.get(
            "/static/app.css", headers={"Host": "evil.test"}
        ).status_code
        == 400
    )


def test_choice_validation_and_answer_limits():
    with pytest.raises(HTTPException):
        question_data(
            {"prompt": "Hello", "kind": "single_choice", "options": ["One", "one"]}
        )
    q = dict(
        id="q1",
        **question_data(
            {
                "prompt": "Your priority?",
                "kind": "single_choice",
                "options": ["Parks", "Buses"],
                "required": True,
            }
        ),
    )
    s = {"version": 1, "questions": [q]}
    for body in [
        {"survey_version": 0},
        {"survey_version": 1},
        {"survey_version": 1, "answers": {"q1": "Unknown"}},
        {"survey_version": 1, "answers": {"alien": "x"}},
    ]:
        with pytest.raises(HTTPException):
            validate_answers(s, body)
    status, snapshot = validate_answers(
        s, {"survey_version": 1, "answers": {"q1": "Parks"}}
    )
    assert snapshot["questions"]["q1"]["prompt"] == "Your priority?"
    assert status == "answered"
    assert (
        validate_answers(s, {"survey_version": 1, "contact_status": "refused"})[0]
        == "refused"
    )


@pytest.mark.parametrize("value", ["=1+2", "+SUM(A1:A2)", "@cmd", "-1", "\t=1", "\r=1"])
def test_csv_formula_escaping(value):
    assert _csv_cell(value).startswith("'")
