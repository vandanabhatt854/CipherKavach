"""Command-line interface for CipherKavach's shared Python crypto functions."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from cipherkavach_crypto import (
    CipherKavachError,
    decrypt_bytes,
    encrypt_bytes,
)


def _password(confirm: bool = False) -> str:
    password = getpass.getpass("Password: ")
    if not password:
        raise ValueError("Password cannot be empty.")
    if confirm and getpass.getpass("Confirm password: ") != password:
        raise ValueError("Passwords do not match.")
    return password


def main() -> int:
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files with CipherKavach.")
    parser.add_argument("action", choices=("encrypt", "decrypt"))
    parser.add_argument("input", type=Path, help="Input file")
    parser.add_argument("-o", "--output", type=Path, help="Output file path")
    args = parser.parse_args()
    try:
        source = args.input.read_bytes()
        password = _password(confirm=args.action == "encrypt")
        if args.action == "encrypt":
            result = encrypt_bytes(source, password)
            destination = args.output or Path(str(args.input) + ".ckv")
        else:
            result = decrypt_bytes(source, password)
            default_name = args.input.name[:-4] if args.input.name.lower().endswith(".ckv") else args.input.name + ".decrypted"
            destination = args.output or args.input.with_name(default_name)
        destination.write_bytes(result)
        verb = "Encrypted" if args.action == "encrypt" else "Decrypted"
        print(f"{verb} file saved to: {destination}")
        return 0
    except (OSError, ValueError, CipherKavachError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

