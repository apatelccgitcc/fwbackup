"""Encrypt firewall passwords at rest with a key derived from APP_SECRET_KEY."""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from . import config


def _fernet():
    if not config.APP_SECRET_KEY:
        raise RuntimeError("APP_SECRET_KEY is not set")
    key = hashlib.sha256(("fwbackup-creds:" + config.APP_SECRET_KEY).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt(plain: str) -> str:
    if not plain:
        return ""
    return _fernet().encrypt(plain.encode()).decode()


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        raise RuntimeError("Stored password can't be decrypted (APP_SECRET_KEY changed?) - re-enter it")
