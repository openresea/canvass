"""Integration tests create and remove their own databases on an isolated PG cluster."""

import os
import secrets
import uuid
from pathlib import Path
from types import SimpleNamespace

import psycopg2
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from psycopg2 import sql
from psycopg2.pool import ThreadedConnectionPool

from app.admin.main import app as admin_app
from app.canvasser.main import app as canvasser_app
from app.common.db import POOLS

ROUTE_CODE = "test-route-SAMPLE2345"


@pytest.fixture
def db(monkeypatch):
    dsn = os.environ.get("TEST_DATABASE_DSN")
    if not dsn:
        pytest.skip("Set TEST_DATABASE_DSN to an isolated PostgreSQL cluster.")
    from app.common import crypto

    monkeypatch.setattr(crypto, "_fernet_instance", None)
    key = Fernet.generate_key()
    monkeypatch.setenv("ROUTE_CODE_FERNET_KEY", key.decode())
    ciphertext = Fernet(key).encrypt(ROUTE_CODE.encode()).decode()
    root = psycopg2.connect(dsn)
    root.autocommit = True
    suffix = uuid.uuid4().hex[:12]
    names = ["test_ops_" + suffix, "test_answers_" + suffix]
    settings = psycopg2.extensions.parse_dsn(dsn)
    connections = []
    pools = []
    try:
        for name in names:
            with root.cursor() as cur:
                cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        ops = psycopg2.connect(**{**settings, "dbname": names[0]})
        connections.append(ops)
        ans = psycopg2.connect(**{**settings, "dbname": names[1]})
        connections.append(ans)
        for conn, filename in [(ops, "ops.sql"), (ans, "answers.sql")]:
            with conn, conn.cursor() as cur:
                cur.execute((Path("app/sql") / filename).read_text())
        with ops, ops.cursor() as cur:
            cur.execute("INSERT INTO boroughs VALUES ('LOCAL','Example region')")
            cur.execute("INSERT INTO areas VALUES ('LOCAL_CENTRAL','LOCAL','Central')")
            cur.execute(
                "INSERT INTO users(email,role) VALUES ('admin@example.test','GLOBAL_ADMIN'),('limited@example.test','AREA_USER')"
            )
            cur.execute(
                "INSERT INTO routes(route_id,name,borough_id,area_id) VALUES ('test-route','Example route','LOCAL','LOCAL_CENTRAL'),('other-route','Other route','LOCAL','LOCAL_CENTRAL')"
            )
            cur.execute(
                "INSERT INTO route_codes(route_id,code_hash,code_ciphertext,expires_at) VALUES ('test-route',crypt(%s,gen_salt('bf')),%s,now()+interval '1 hour') RETURNING code_hash",
                (ROUTE_CODE, ciphertext),
            )
            code_hash = cur.fetchone()[0]
            cur.execute(
                "INSERT INTO addresses(route_id,street,house,postcode,full_address,source) VALUES ('test-route','Example Street','1','AB1 2CD','1 Example Street','manual') RETURNING address_id"
            )
            address_id = str(cur.fetchone()[0])
            cur.execute(
                "INSERT INTO flats(address_id,flat_label,flat_number,resident_name) VALUES (%s,'Resident','1','Sample Resident') RETURNING flat_id",
                (address_id,),
            )
            flat_id = str(cur.fetchone()[0])
            tokens = {}
            for email in ["admin@example.test", "limited@example.test"]:
                cur.execute(
                    "INSERT INTO admin_sessions(email,expires_at) VALUES (%s,now()+interval '1 hour') RETURNING session_token",
                    (email,),
                )
                tokens[email] = str(cur.fetchone()[0])
            cur.execute(
                "INSERT INTO canvasser_sessions(email,display_name,route_id,code_hash,expires_at) VALUES ('helper@example.test','Helper','test-route',%s,now()+interval '1 hour') RETURNING session_token",
                (code_hash,),
            )
            canvasser_token = str(cur.fetchone()[0])

        role_password = secrets.token_urlsafe(32)
        with root.cursor() as cur:
            for role in (
                "ops_admin",
                "ops_canvasser",
                "answers_admin",
                "answers_writer",
            ):
                cur.execute(
                    sql.SQL("ALTER ROLE {} PASSWORD %s").format(sql.Identifier(role)),
                    (role_password,),
                )

        def pool(database, role):
            p = ThreadedConnectionPool(
                1,
                5,
                **{
                    **settings,
                    "dbname": database,
                    "user": role,
                    "password": role_password,
                },
            )
            pools.append(p)
            return p

        admin_pool = pool(names[0], "ops_admin")
        canvasser_pool = pool(names[0], "ops_canvasser")
        POOLS.answers_write = pool(names[1], "answers_writer")
        POOLS.answers_admin = pool(names[1], "answers_admin")
        monkeypatch.setenv(
            "EMAIL_CODE_SECRET", "test-only-secret-with-at-least-32-characters"
        )
        monkeypatch.setenv("SMTP_HOST", "smtp.example.test")
        monkeypatch.setenv("SMTP_FROM", "login@example.test")

        class Client(TestClient):
            def __init__(self, app, pool, cookie, token):
                super().__init__(
                    app,
                    base_url="https://testserver",
                    headers={"Origin": "https://testserver"},
                    raise_server_exceptions=True,
                )
                self.pool = pool
                self.cookies.set(cookie, token)

            def request(self, *a, **kw):
                POOLS.ops = self.pool
                return super().request(*a, **kw)

        yield SimpleNamespace(
            ops=ops,
            answers=ans,
            flat_id=flat_id,
            route_code=ROUTE_CODE,
            address_id=address_id,
            admin=Client(
                admin_app, admin_pool, "admin_session", tokens["admin@example.test"]
            ),
            limited=Client(
                admin_app, admin_pool, "admin_session", tokens["limited@example.test"]
            ),
            canvasser=Client(
                canvasser_app, canvasser_pool, "canvasser_session", canvasser_token
            ),
        )
    finally:
        for p in pools:
            p.closeall()
        POOLS.ops = POOLS.answers_write = POOLS.answers_admin = None
        for conn in connections:
            conn.close()
        for name in names:
            with root.cursor() as cur:
                cur.execute(
                    sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(
                        sql.Identifier(name)
                    )
                )
        root.close()
