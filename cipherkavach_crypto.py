"""Shared authenticated file encryption for the CipherKavach CLI and web app.

Format v1: magic (4 bytes), version (1), PBKDF2 salt (16), AES-GCM nonce
(12), then AES-GCM ciphertext and tag (16). The fixed header is authenticated
as associated data. Passwords are never stored in the file.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"CKAV"
VERSION = 1
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
HEADER_SIZE = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE
MIN_ENCRYPTED_SIZE = HEADER_SIZE + TAG_SIZE
PBKDF2_ITERATIONS = 600_000


class CipherKavachError(Exception):
    """Base class for expected file or credential errors."""


class UnsupportedFormatError(CipherKavachError):
    """The input is not a supported CipherKavach file."""


class InvalidEncryptedFileError(CipherKavachError):
    """The encrypted payload is truncated, corrupt, or uses a bad password."""


def _derive_key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("A non-empty password is required.")
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS
    ).derive(password.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """Encrypt bytes in the versioned CipherKavach v1 format."""
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    header = MAGIC + bytes([VERSION]) + salt + nonce
    encrypted = AESGCM(_derive_key(password, salt)).encrypt(nonce, plaintext, header)
    return header + encrypted


def decrypt_bytes(encrypted_file: bytes, password: str) -> bytes:
    """Decrypt a CipherKavach v1 file or raise a safe, expected error."""
    if not isinstance(encrypted_file, bytes):
        raise TypeError("encrypted_file must be bytes")
    if len(encrypted_file) < len(MAGIC) + 1:
        raise UnsupportedFormatError("This is not a supported CipherKavach encrypted file.")
    if encrypted_file[: len(MAGIC)] != MAGIC:
        raise UnsupportedFormatError("This is not a supported CipherKavach encrypted file.")
    if encrypted_file[len(MAGIC)] != VERSION:
        raise UnsupportedFormatError("This CipherKavach file version is not supported.")
    if len(encrypted_file) < MIN_ENCRYPTED_SIZE:
        raise InvalidEncryptedFileError("The encrypted file is incomplete or damaged.")

    header = encrypted_file[:HEADER_SIZE]
    salt = encrypted_file[5 : 5 + SALT_SIZE]
    nonce = encrypted_file[5 + SALT_SIZE : HEADER_SIZE]
    try:
        return AESGCM(_derive_key(password, salt)).decrypt(
            nonce, encrypted_file[HEADER_SIZE:], header
        )
    except InvalidTag as exc:
        # GCM cannot tell a wrong password from modified ciphertext.
        raise InvalidEncryptedFileError(
            "Could not decrypt this file. The password may be wrong, or the file may be damaged.") from exc

