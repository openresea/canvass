"""Create a fresh local Compose configuration without exposing generated secrets."""

import base64
import os
import re
import secrets
from pathlib import Path


def main():
    target = Path(__file__).resolve().parents[1] / ".env"
    if target.exists():
        raise SystemExit(
            ".env already exists. Edit it directly; existing secrets have not been changed."
        )
    email = input("Email of the first administrator: ").strip().lower()
    sender = (
        input("Sender email address (verified with your mail provider): ")
        .strip()
        .lower()
    )
    smtp_host = input("SMTP server hostname: ").strip()
    if not re.fullmatch(r"[a-z0-9.!+_-]+@[a-z0-9.-]+\.[a-z]{2,}", email):
        raise SystemExit("Enter a valid email address.")
    if not re.fullmatch(
        r"[a-z0-9.!+_-]+@[a-z0-9.-]+\.[a-z]{2,}", sender
    ) or not re.fullmatch(r"[A-Za-z0-9.-]+", smtp_host):
        raise SystemExit("Enter a valid sender email and SMTP hostname.")
    values = {
        "ADMIN_EMAIL": email,
        "ALLOWED_HOSTS": "localhost,127.0.0.1",
        "ROUTE_CODE_FERNET_KEY": base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode(),
        "EMAIL_CODE_SECRET": secrets.token_urlsafe(48),
        "SMTP_HOST": smtp_host,
        "SMTP_FROM": sender,
        "SMTP_PORT": "587",
        "SMTP_SECURITY": "starttls",
        "SMTP_USERNAME": "",
        "SMTP_PASSWORD": "",
    }
    for key in (
        "POSTGRES_PASSWORD",
        "OPS_ADMIN_PASSWORD",
        "OPS_CANVASSER_PASSWORD",
        "ANSWERS_ADMIN_PASSWORD",
        "ANSWERS_WRITER_PASSWORD",
    ):
        values[key] = secrets.token_urlsafe(32)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write("\n".join(f"{k}={v}" for k, v in values.items()) + "\n")
    print(
        "Created .env with fresh secrets and owner-only permissions. Add SMTP_USERNAME and SMTP_PASSWORD, then run docker compose up --build."
    )


if __name__ == "__main__":
    main()
