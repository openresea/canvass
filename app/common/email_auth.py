"""Provider-independent email codes. All limits and code use are database-atomic."""

import hashlib
import hmac
import logging
import os
import re
import secrets
import smtplib
import ssl
import uuid
from email.message import EmailMessage

from fastapi import HTTPException
from psycopg2 import sql

from app.common.db import get_ops, put_ops
from app.common.util import fetchone_dict

logger = logging.getLogger(__name__)
TABLES = {"admin": "admin_login_codes", "canvasser": "canvasser_login_codes"}
GENERIC_NOTICE = (
    "Thanks! If this address can sign in, your code is on its way. "
    "It can take a minute, so check your spam folder too."
)


def normalize_email(raw):
    if not isinstance(raw, str):
        raise HTTPException(400, "Please enter your email address.")
    value = raw.strip().lower()
    if len(value) > 254 or not re.fullmatch(
        r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}",
        value,
    ):
        raise HTTPException(400, "That email address doesn't look quite right. Could you check it?")
    if ".." in value or value.startswith(".") or ".@" in value:
        raise HTTPException(400, "That email address doesn't look quite right. Could you check it?")
    return value


def digest(value):
    key = os.environ.get("EMAIL_CODE_SECRET", "")
    if len(key) < 32:
        raise RuntimeError(
            "EMAIL_CODE_SECRET must contain at least 32 random characters"
        )
    return hmac.new(key.encode(), value.encode(), hashlib.sha256).hexdigest()


def table_for(purpose):
    return sql.Identifier(TABLES[purpose])


def enforce_limits(purpose, ip, email=None, *, verification=False):
    """Fixed windows persist across processes. Keys hide email addresses and IPs."""
    limits = (
        [(f"{purpose}:verify:ip:{ip}", 60, 900)]
        if verification
        else [
            (f"{purpose}:send:global", 200, 3600),
            (f"{purpose}:send:ip:{ip}", 20, 900),
            (f"{purpose}:send:email:{email}", 3, 900),
            (f"{purpose}:cooldown:{email}", 1, 60),
        ]
    )
    conn = get_ops()
    allowed = True
    try:
        with conn, conn.cursor() as cur:
            for key, cap, seconds in limits:
                cur.execute(
                    """INSERT INTO email_auth_limits(key_hash,hits,resets_at)
                    VALUES (%s,1,now()+%s*interval '1 second')
                    ON CONFLICT (key_hash) DO UPDATE SET
                      hits=CASE WHEN email_auth_limits.resets_at <= now() THEN 1 ELSE email_auth_limits.hits+1 END,
                      resets_at=CASE WHEN email_auth_limits.resets_at <= now() THEN EXCLUDED.resets_at ELSE email_auth_limits.resets_at END
                    RETURNING hits""",
                    (digest(key), seconds),
                )
                if cur.fetchone()[0] > cap:
                    allowed = False
                    break
    finally:
        put_ops(conn)
    if not allowed:
        raise HTTPException(
            429,
            "That's a lot of tries in a short time. Please wait a few minutes and try again.",
            headers={"Retry-After": "900"},
        )


def mail_config():
    host = os.environ.get("SMTP_HOST", "").strip()
    sender = normalize_email(os.environ.get("SMTP_FROM", ""))
    mode = os.environ.get("SMTP_SECURITY", "starttls")
    if not host or mode not in ("starttls", "ssl"):
        raise RuntimeError(
            "Configure SMTP_HOST, SMTP_FROM and SMTP_SECURITY (starttls or ssl)"
        )
    return host, sender, mode


def send_code(email, code, purpose):
    host, sender, mode = mail_config()
    port = int(os.environ.get("SMTP_PORT", "465" if mode == "ssl" else "587"))
    message = EmailMessage()
    message["From"] = sender
    message["To"] = email
    message["Subject"] = "Your Resea Canvass sign-in code"
    message.set_content(
        f"Hi,\n\nHere's your sign-in code: {code}\n\n"
        "It works once and expires in 10 minutes. Only type it into the Resea Canvass "
        "page where you asked for it, and please don't share it with anyone.\n\n"
        "If you didn't ask for a code, you can safely ignore this email.\n"
    )
    context = ssl.create_default_context()
    factory = smtplib.SMTP_SSL if mode == "ssl" else smtplib.SMTP
    kwargs = {"host": host, "port": port, "timeout": 15}
    if mode == "ssl":
        kwargs["context"] = context
    with factory(**kwargs) as smtp:
        if mode == "starttls":
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
        user = os.environ.get("SMTP_USERNAME", "")
        if user:
            smtp.login(user, os.environ.get("SMTP_PASSWORD", ""))
        smtp.send_message(message)


def deliver_code(email, code, purpose):
    try:
        send_code(email, code, purpose)
    except Exception:
        # Never log codes, addresses, message bodies, or SMTP credentials.
        logger.error(
            "Sign-in email delivery failed; check mail service configuration and availability."
        )


def request_code(email, purpose, ip, background_tasks):
    email = normalize_email(email)
    enforce_limits(purpose, ip, email)
    try:
        mail_config()
    except (RuntimeError, HTTPException):
        raise HTTPException(
            503, "Email sign-in isn't set up yet. Please let your organiser know."
        )
    challenge = str(uuid.uuid4())
    code = f"{secrets.randbelow(1000000):06d}"
    conn = get_ops()
    eligible = True
    try:
        with conn, conn.cursor() as cur:
            if purpose == "admin":
                cur.execute("SELECT 1 FROM users WHERE lower(email)=%s", (email,))
                eligible = cur.fetchone() is not None
            if eligible:
                cur.execute(
                    sql.SQL(
                        "UPDATE {} SET consumed=true WHERE email=%s AND NOT consumed"
                    ).format(table_for(purpose)),
                    (email,),
                )
                cur.execute(
                    sql.SQL("""INSERT INTO {}(challenge_id,email,code_digest,expires_at)
                    VALUES (%s,%s,%s,now()+interval '10 minutes')""").format(
                        table_for(purpose)
                    ),
                    (challenge, email, digest(f"{purpose}:{challenge}:{email}:{code}")),
                )
    finally:
        put_ops(conn)
    if eligible:
        # Delivery is outside the HTTP response path, avoiding an SMTP timing oracle.
        background_tasks.add_task(deliver_code, email, code, purpose)
    return {
        "ok": True,
        "challenge_id": challenge,
        "detail": GENERIC_NOTICE,
        "retry_after": 60,
    }


def verify_code(body, purpose):
    """Callers must apply enforce_limits(purpose, ip, verification=True) first."""
    email = normalize_email(body.get("email"))
    try:
        challenge = str(uuid.UUID(str(body.get("challenge_id"))))
    except ValueError:
        raise HTTPException(401, "That code didn't work. It may have expired, so try asking for a new one.")
    code = body.get("code")
    valid_shape = isinstance(code, str) and re.fullmatch(r"[0-9]{6}", code) is not None
    conn = get_ops()
    accepted = False
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                sql.SQL("""SELECT email,code_digest,attempts,consumed,expires_at>now() AS fresh
                FROM {} WHERE challenge_id=%s FOR UPDATE""").format(table_for(purpose)),
                (challenge,),
            )
            row = fetchone_dict(cur)
            if row and not row["consumed"] and row["fresh"] and row["attempts"] < 5:
                accepted = bool(
                    valid_shape
                    and row["email"] == email
                    and hmac.compare_digest(
                        row["code_digest"],
                        digest(f"{purpose}:{challenge}:{email}:{code}"),
                    )
                )
                cur.execute(
                    sql.SQL(
                        "UPDATE {} SET attempts=attempts+1,consumed=%s WHERE challenge_id=%s"
                    ).format(table_for(purpose)),
                    (accepted or row["attempts"] >= 4, challenge),
                )
        # Raise after committing, otherwise incorrect attempts would roll back.
    finally:
        put_ops(conn)
    if not accepted:
        raise HTTPException(401, "That code didn't work. It may have expired, so try asking for a new one.")
    return email
