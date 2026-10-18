import os
from typing import Optional

from cryptography.fernet import Fernet

_fernet_instance: Optional[Fernet] = None


def _fernet() -> Fernet:
    global _fernet_instance
    if _fernet_instance is None:
        key = os.environ.get("ROUTE_CODE_FERNET_KEY", "").strip()
        if not key:
            raise RuntimeError(
                "Missing ROUTE_CODE_FERNET_KEY (generate with scripts/configure.py)"
            )
        _fernet_instance = Fernet(key.encode("utf-8"))
    return _fernet_instance


def encrypt_text(plain: str) -> str:
    return _fernet().encrypt(plain.encode("utf-8")).decode("utf-8")


def decrypt_text(cipher: str) -> str:
    return _fernet().decrypt(cipher.encode("utf-8")).decode("utf-8")
