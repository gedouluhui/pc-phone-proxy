#!/usr/bin/env python3
"""Verify the exact bytes of phone/sources.json against the committed public key."""
import argparse
import base64
import binascii
import hashlib
import hmac
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _tlv(data, offset):
    if offset + 2 > len(data):
        raise ValueError("truncated DER")
    tag = data[offset]
    offset += 1
    first = data[offset]
    offset += 1
    if first & 0x80:
        count = first & 0x7f
        if count == 0 or count > 4 or offset + count > len(data):
            raise ValueError("invalid DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    else:
        length = first
    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return tag, data[offset:end], end


def _rsa_public_numbers(public_key):
    if isinstance(public_key, str):
        public_key = public_key.encode("ascii")
    text = public_key.decode("ascii")
    body = "".join(line.strip() for line in text.splitlines()
                   if line and not line.startswith("-----"))
    der = base64.b64decode(body, validate=True)
    tag, spki, end = _tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError("invalid public key")
    tag, algorithm, offset = _tlv(spki, 0)
    if tag != 0x30:
        raise ValueError("invalid public key algorithm")
    tag, bit_string, offset = _tlv(spki, offset)
    if tag != 0x03 or not bit_string or bit_string[0] != 0 or offset != len(spki):
        raise ValueError("invalid public key bit string")
    tag, rsa, end = _tlv(bit_string, 1)
    if tag != 0x30 or end != len(bit_string):
        raise ValueError("invalid RSA public key")
    tag, modulus, offset = _tlv(rsa, 0)
    if tag != 0x02:
        raise ValueError("invalid RSA modulus")
    tag, exponent, offset = _tlv(rsa, offset)
    if tag != 0x02 or offset != len(rsa):
        raise ValueError("invalid RSA exponent")
    return int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")


def verify_bytes(data, signature, public_key, openssl_exe=None):
    """Verify RSA PKCS#1 v1.5 with SHA-256 using only the Python standard library."""
    if not isinstance(data, bytes) or not data or not isinstance(signature, bytes) or not signature:
        return False
    try:
        modulus, exponent = _rsa_public_numbers(public_key)
        size = (modulus.bit_length() + 7) // 8
        if size < 128 or size > 512 or len(signature) != size or exponent < 3:
            return False
        value = int.from_bytes(signature, "big")
        if value >= modulus:
            return False
        encoded = pow(value, exponent, modulus).to_bytes(size, "big")
        digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(data).digest()
        padding = size - len(digest_info) - 3
        if padding < 8:
            return False
        expected = b"\x00\x01" + b"\xff" * padding + b"\x00" + digest_info
        return hmac.compare_digest(encoded, expected)
    except (ValueError, TypeError, UnicodeError, binascii.Error):
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=str(ROOT / "phone" / "sources.json"))
    parser.add_argument("--signature", default=str(ROOT / "phone" / "sources.sig"))
    parser.add_argument("--public-key", default=str(ROOT / "phone" / "source_signing_public.pem"))
    args = parser.parse_args(argv)
    try:
        valid = verify_bytes(Path(args.manifest).read_bytes(), Path(args.signature).read_bytes(),
                             Path(args.public_key).read_bytes())
    except OSError as error:
        print("verification failed: %s" % error, file=sys.stderr)
        return 1
    print("source manifest signature OK" if valid else "source manifest signature INVALID")
    return 0 if valid else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print("verification failed: %s" % error, file=sys.stderr)
        raise SystemExit(1)
