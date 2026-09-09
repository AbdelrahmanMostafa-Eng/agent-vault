"""Authenticated encryption and strict local key-file handling."""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

KEY_MODE = 0o600


class EncryptionError(ValueError):
    """Raised when a key or encrypted payload cannot be safely processed."""


def _reject_symlink(path: Path, label: str) -> None:
    try:
        if path.is_symlink():
            raise EncryptionError(f"{label} must not be a symlink")
    except OSError as exc:
        raise EncryptionError(f"Unable to inspect {label}") from exc


def _validate_key_permissions(key_path: Path) -> None:
    _reject_symlink(key_path, "encryption key")
    try:
        mode = stat.S_IMODE(key_path.stat().st_mode)
    except OSError as exc:
        raise EncryptionError("Unable to inspect encryption key") from exc
    if not stat.S_ISREG(key_path.stat().st_mode):
        raise EncryptionError("Encryption key must be a regular file")
    if mode & 0o077:
        raise EncryptionError("Encryption key permissions are too broad; expected mode 0600")


def create_key(key_path: Path) -> None:
    """Create a private Fernet key atomically without overwriting an existing path."""
    key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _reject_symlink(key_path.parent, "encryption key directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(key_path, flags, KEY_MODE)
    except FileExistsError as exc:
        raise FileExistsError(f"Encryption key already exists: {key_path}") from exc
    try:
        os.write(fd, Fernet.generate_key())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(key_path, KEY_MODE)


def load_key(key_path: Path) -> bytes:
    """Load and validate a private Fernet key, including filesystem permissions."""
    try:
        _validate_key_permissions(key_path)
        key = key_path.read_bytes().strip()
        Fernet(key)
    except (OSError, ValueError) as exc:
        if isinstance(exc, EncryptionError):
            raise
        raise EncryptionError("Invalid or unreadable encryption key") from exc
    return key


def encrypt(key: bytes, value: str) -> bytes:
    """Encrypt a UTF-8 string into authenticated ciphertext."""
    try:
        return Fernet(key).encrypt(value.encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise EncryptionError("Unable to encrypt memory payload") from exc


def search_token(key: bytes, value: str) -> str:
    """Return a keyed token for equality filtering without exposing the value."""
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def decrypt(key: bytes, value: bytes) -> str:
    """Decrypt authenticated ciphertext into a UTF-8 string."""
    try:
        return Fernet(key).decrypt(value).decode("utf-8")
    except (InvalidToken, TypeError, ValueError, UnicodeDecodeError) as exc:
        raise EncryptionError("Unable to decrypt memory payload") from exc
