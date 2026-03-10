"""
Task 4: Padding – Encrypt the three task4 files using OpenSSL (SEED Lab method).

This script follows the instruction given in the SEED Lab manual: encryption
is performed with OpenSSL command-line (openssl enc) in ECB, CBC, CFB, and OFB
modes. The SEED Lab Secret-Key Encryption lab and its manual use OpenSSL for
all encryption tasks; see seedsecuritylabs.org and the lab manual.

Usage (from project root):
    python scripts/encrypt_task4_openssl.py

Requires: OpenSSL in PATH (e.g. from Git for Windows, or install OpenSSL).
Output: Ciphertexts in data/task4/; lengths and hex printed to console.
"""

import subprocess
import sys
from pathlib import Path

# AES-128: 16-byte key and IV (hex = 32 chars each).
# From key_iv.txt (Moodle): AES key 00112233445566778899aabbccddeeff, IV 010203040506070809000a0b0c0d0e0f
KEY_HEX = "00112233445566778899aabbccddeeff"
IV_HEX  = "010203040506070809000a0b0c0d0e0f"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TASK4_DIR = PROJECT_ROOT / "data" / "task4"
FILES = [("f1.txt", 5), ("f2.txt", 10), ("f3.txt", 16)]


def run_openssl_enc(mode: str, infile: Path, outfile: Path, key_hex: str, iv_hex: str | None) -> int:
    """Encrypt with openssl enc. Returns ciphertext length in bytes."""
    cmd = [
        "openssl", "enc", f"-aes-128-{mode}", "-e",
        "-K", key_hex, "-in", str(infile), "-out", str(outfile)
    ]
    if iv_hex and mode != "ecb":
        cmd.extend(["-iv", iv_hex])
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        raise RuntimeError(f"openssl failed: {r.stderr or r.stdout}")
    return outfile.stat().st_size


def main() -> None:
    # Check OpenSSL is available
    r = subprocess.run(["openssl", "version"], capture_output=True, text=True, timeout=5)
    if r.returncode != 0:
        print("OpenSSL not found in PATH. Install OpenSSL or use Git for Windows.", file=sys.stderr)
        sys.exit(1)
    print("Task 4: Padding – OpenSSL (SEED Lab / lab manual method)")
    print("OpenSSL:", r.stdout.strip())
    print("Key (hex):", KEY_HEX)
    print("IV  (hex):", IV_HEX)
    print()

    TASK4_DIR.mkdir(parents=True, exist_ok=True)

    for fname, expected_len in FILES:
        path = TASK4_DIR / fname
        if not path.exists():
            print(f"Skip (not found): {path}")
            continue
        n = path.stat().st_size
        base = path.stem
        print("=" * 60)
        print(f"File: {fname}  |  Plaintext length: {n} bytes  |  Expected: {expected_len}")
        print("=" * 60)

        for mode in ("ecb", "cbc", "cfb", "ofb"):
            out = TASK4_DIR / f"{base}_{mode}.bin"
            try:
                size = run_openssl_enc(mode, path, out, KEY_HEX, IV_HEX if mode != "ecb" else None)
                hex_val = out.read_bytes().hex()
                print(f"  {mode.upper():3} | Ciphertext length: {size} bytes | Hex: {hex_val}")
            except Exception as e:
                print(f"  {mode.upper():3} | Error: {e}")

        print()

    print("=" * 60)
    print("Summary: Padding (as in SEED Lab manual)")
    print("=" * 60)
    print("  Modes WITH padding:    ECB, CBC  (block modes; PKCS#7 in OpenSSL)")
    print("  Modes WITHOUT padding: CFB, OFB  (stream-like; no padding)")
    print()
    print("Ciphertexts written to:", TASK4_DIR)


if __name__ == "__main__":
    main()
