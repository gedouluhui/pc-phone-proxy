#!/usr/bin/env python3
"""Sign the exact bytes of phone/sources.json with an offline RSA private key."""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def openssl():
    found = os.environ.get("OPENSSL") or shutil.which("openssl")
    if not found:
        raise RuntimeError("OpenSSL not found; set OPENSSL")
    return found


def sign_bytes(data, private_key, openssl_exe=None):
    if not isinstance(data, bytes) or not data:
        raise ValueError("manifest bytes are empty")
    exe = openssl_exe or openssl()
    with tempfile.TemporaryDirectory(prefix="source-sign-") as directory:
        manifest = Path(directory) / "sources.json"
        signature = Path(directory) / "sources.sig"
        manifest.write_bytes(data)
        result = subprocess.run([exe, "dgst", "-sha256", "-sign", str(private_key),
                                 "-out", str(signature), str(manifest)], capture_output=True)
        if result.returncode != 0:
            raise RuntimeError("RSA signing failed")
        return signature.read_bytes()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--manifest", default=str(ROOT / "phone" / "sources.json"))
    parser.add_argument("--signature", default=str(ROOT / "phone" / "sources.sig"))
    args = parser.parse_args(argv)
    manifest = Path(args.manifest)
    if not manifest.is_file() or not Path(args.private_key).is_file():
        parser.error("manifest and existing private key are required")
    signature = sign_bytes(manifest.read_bytes(), args.private_key)
    output = Path(args.signature)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_bytes(signature)
    os.replace(temporary, output)
    print("signed %s (%d bytes)" % (manifest, len(signature)))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError) as error:
        print("signing failed: %s" % error, file=sys.stderr)
        raise SystemExit(1)
