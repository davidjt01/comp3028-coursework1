"""
Task 4: Padding – Encrypt the three task4 files (5, 10, 16 bytes) with
AES-128 in ECB, CBC, CFB, and OFB modes. Report ciphertext lengths and
which modes use padding.

Coursework: COMP3028 Computer Security – report which modes have padding
and which do not, and explain why.

Usage (from project root):
    python scripts/encrypt_task4.py

Output: Prints plaintext/ciphertext lengths and hex; writes ciphertexts
to data/task4/ (optional). Use key and IV below or replace with Moodle
values if provided.
"""

import sys
from pathlib import Path

# AES-128: 16-byte key; CBC/CFB/OFB need 16-byte IV (same as block size)
# From key_iv.txt (Moodle): AES key 00112233445566778899aabbccddeeff, IV 010203040506070809000a0b0c0d0e0f
KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
IV  = bytes.fromhex("010203040506070809000a0b0c0d0e0f")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
TASK4_DIR = DATA_DIR / "task4"

# Input files (5, 10, 16 bytes per spec)
FILES = [
    ("f1.txt", 5),
    ("f2.txt", 10),
    ("f3.txt", 16),
]


def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded)


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded)


def encrypt_cfb(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    return cipher.encrypt(plaintext)


def encrypt_ofb(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    return cipher.encrypt(plaintext)


def main() -> None:
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("Requires pycryptodome: pip install pycryptodome", file=sys.stderr)
        sys.exit(1)

    TASK4_DIR.mkdir(parents=True, exist_ok=True)

    print("Task 4: Padding – AES-128 ECB, CBC, CFB, OFB")
    print("Key (hex):", KEY.hex())
    print("IV  (hex):", IV.hex())
    print()

    for fname, expected_len in FILES:
        path = TASK4_DIR / fname
        if not path.exists():
            print(f"Skip (not found): {path}")
            continue
        plaintext = path.read_bytes()
        n = len(plaintext)
        base = path.stem
        print("=" * 60)
        print(f"File: {fname}  |  Plaintext length: {n} bytes  |  Expected: {expected_len}")
        print("=" * 60)

        # ECB
        c_ecb = encrypt_ecb(plaintext, KEY)
        print(f"  ECB  | Ciphertext length: {len(c_ecb)} bytes | Hex: {c_ecb.hex()}")
        (TASK4_DIR / f"{base}_ecb.bin").write_bytes(c_ecb)

        # CBC
        c_cbc = encrypt_cbc(plaintext, KEY, IV)
        print(f"  CBC  | Ciphertext length: {len(c_cbc)} bytes | Hex: {c_cbc.hex()}")
        (TASK4_DIR / f"{base}_cbc.bin").write_bytes(c_cbc)

        # CFB (no padding: stream mode)
        c_cfb = encrypt_cfb(plaintext, KEY, IV)
        print(f"  CFB  | Ciphertext length: {len(c_cfb)} bytes | Hex: {c_cfb.hex()}")
        (TASK4_DIR / f"{base}_cfb.bin").write_bytes(c_cfb)

        # OFB (no padding: stream mode)
        c_ofb = encrypt_ofb(plaintext, KEY, IV)
        print(f"  OFB  | Ciphertext length: {len(c_ofb)} bytes | Hex: {c_ofb.hex()}")
        (TASK4_DIR / f"{base}_ofb.bin").write_bytes(c_ofb)

        print()

    print("=" * 60)
    print("Summary: Padding")
    print("=" * 60)
    print("  Modes WITH padding:    ECB, CBC  (ciphertext length is multiple of 16)")
    print("  Modes WITHOUT padding: CFB, OFB  (ciphertext length = plaintext length)")
    print()
    print("Ciphertexts written to:", TASK4_DIR)


if __name__ == "__main__":
    main()
