"""
Task 5: Error Propagation – Corrupted Cipher Text (COMP3028 Coursework 1).

Encrypt the Task 5 plaintext with AES-128 in ECB, CBC, CFB, and OFB modes.
Corrupt a single bit of the 55th byte in each encrypted file, decrypt, and
report how much information can be recovered in each mode.

Follows the SEED Lab Secret-Key Encryption lab (Task 5 / Section 7) and
coursework spec: use key and IV from Moodle (replace KEY_HEX/IV_HEX below).

Usage (from project root):
    python scripts/task5_error_propagation.py

Uses OpenSSL if in PATH; otherwise pycryptodome (pip install pycryptodome).
Output: Ciphertexts, corrupted ciphertexts, and decrypted files in data/task5/;
        recovery statistics and report text to console.
"""

import subprocess
import sys
from pathlib import Path

# AES-128: 16-byte key and IV in hex (32 hex chars each).
# From key_iv.txt (Moodle): AES key 00112233445566778899aabbccddeeff, IV 010203040506070809000a0b0c0d0e0f
KEY_HEX = "00112233445566778899aabbccddeeff"
IV_HEX = "010203040506070809000a0b0c0d0e0f"

# 55th byte (1-based) = index 54 (0-based). Corrupt exactly one bit (LSB flip).
BYTE_INDEX_TO_CORRUPT = 54
BIT_MASK = 0x01  # flip LSB

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TASK5_DIR = PROJECT_ROOT / "data" / "task5"
PLAINTEXT_FILE = TASK5_DIR / "task5_plaintext.txt"
MODES = ("ecb", "cbc", "cfb", "ofb")


def _key_iv_bytes() -> tuple[bytes, bytes]:
    key = bytes.fromhex(KEY_HEX)
    iv = bytes.fromhex(IV_HEX)
    return key[:16], iv[:16]


# ---------- OpenSSL backend ----------
def run_openssl_enc(
    mode: str, infile: Path, outfile: Path, key_hex: str, iv_hex: str | None
) -> None:
    """Encrypt with openssl enc. Raises on failure."""
    cmd = [
        "openssl", "enc", f"-aes-128-{mode}", "-e",
        "-K", key_hex, "-in", str(infile), "-out", str(outfile)
    ]
    if iv_hex and mode != "ecb":
        cmd.extend(["-iv", iv_hex])
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"openssl enc failed: {r.stderr or r.stdout}")


def run_openssl_dec(
    mode: str, infile: Path, outfile: Path, key_hex: str, iv_hex: str | None
) -> None:
    """Decrypt with openssl enc -d. Raises on failure."""
    cmd = [
        "openssl", "enc", f"-aes-128-{mode}", "-d",
        "-K", key_hex, "-in", str(infile), "-out", str(outfile)
    ]
    if iv_hex and mode != "ecb":
        cmd.extend(["-iv", iv_hex])
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"openssl dec failed: {r.stderr or r.stdout}")


# ---------- PyCryptodome backend (fallback when OpenSSL not in PATH) ----------
def _encrypt_decrypt_pycrypto(
    mode: str, plaintext_or_ciphertext: bytes, key: bytes, iv: bytes | None, encrypt: bool
) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    if mode == "ecb":
        cipher = AES.new(key, AES.MODE_ECB)
        if encrypt:
            data = pad(plaintext_or_ciphertext, AES.block_size)
            return cipher.encrypt(data)
        else:
            dec = cipher.decrypt(plaintext_or_ciphertext)
            return unpad(dec, AES.block_size)
    if mode == "cbc":
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        if encrypt:
            data = pad(plaintext_or_ciphertext, AES.block_size)
            return cipher.encrypt(data)
        else:
            dec = cipher.decrypt(plaintext_or_ciphertext)
            return unpad(dec, AES.block_size)
    if mode == "cfb":
        cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
        return cipher.encrypt(plaintext_or_ciphertext) if encrypt else cipher.decrypt(plaintext_or_ciphertext)
    if mode == "ofb":
        cipher = AES.new(key, AES.MODE_OFB, iv=iv)
        return cipher.encrypt(plaintext_or_ciphertext) if encrypt else cipher.decrypt(plaintext_or_ciphertext)
    raise ValueError(f"unknown mode: {mode}")


def corrupt_one_bit(data: bytes, byte_index: int, bit_mask: int = 0x01) -> bytes:
    """Return a copy of data with one bit flipped at byte_index."""
    if byte_index < 0 or byte_index >= len(data):
        raise ValueError(f"byte_index {byte_index} out of range [0, {len(data)})")
    arr = bytearray(data)
    arr[byte_index] ^= bit_mask
    return bytes(arr)


def compare_recovery(original: bytes, decrypted: bytes) -> dict:
    """
    Compare original plaintext with decrypted (possibly corrupted) output.
    Returns dict with total bytes, matching bytes, first error index, and
    recoverable percentage.
    """
    n_orig = len(original)
    n_dec = len(decrypted)
    # Compare up to min length; extra bytes in decrypted (e.g. padding) not counted as recovered.
    n_compare = min(n_orig, n_dec)
    matches = sum(1 for i in range(n_compare) if original[i] == decrypted[i])
    first_error = None
    for i in range(n_compare):
        if original[i] != decrypted[i]:
            first_error = i
            break
    pct = (100.0 * matches / n_orig) if n_orig else 0.0
    return {
        "original_len": n_orig,
        "decrypted_len": n_dec,
        "matching_bytes": matches,
        "first_error_index": first_error,
        "recoverable_pct": pct,
    }


def main() -> None:
    use_openssl = False
    try:
        r = subprocess.run(
            ["openssl", "version"], capture_output=True, text=True, timeout=5
        )
        use_openssl = r.returncode == 0
    except (FileNotFoundError, OSError):
        pass

    if not PLAINTEXT_FILE.exists():
        print(f"Plaintext not found: {PLAINTEXT_FILE}", file=sys.stderr)
        sys.exit(1)

    TASK5_DIR.mkdir(parents=True, exist_ok=True)
    plaintext = PLAINTEXT_FILE.read_bytes()
    n_plain = len(plaintext)
    key_b, iv_b = _key_iv_bytes()

    print("Task 5: Error Propagation – Corrupted Cipher Text")
    if use_openssl:
        print("Backend: OpenSSL", r.stdout.strip())
    else:
        try:
            __import__("Crypto.Cipher.AES")
            print("Backend: pycryptodome (OpenSSL not in PATH)")
        except ImportError:
            print("OpenSSL not in PATH and pycryptodome not installed.", file=sys.stderr)
            print("Install pycryptodome: pip install pycryptodome", file=sys.stderr)
            sys.exit(1)
    print("Key (hex):", KEY_HEX)
    print("IV  (hex):", IV_HEX)
    print(f"Plaintext: {PLAINTEXT_FILE} ({n_plain} bytes)")
    print(f"Corruption: flip 1 bit (mask=0x{BIT_MASK:02x}) at byte index {BYTE_INDEX_TO_CORRUPT} (55th byte)")
    print()

    results = []

    for mode in MODES:
        if use_openssl:
            cipher_file = TASK5_DIR / f"task5_{mode}.bin"
            run_openssl_enc(
                mode, PLAINTEXT_FILE, cipher_file, KEY_HEX,
                IV_HEX if mode != "ecb" else None
            )
            ciphertext = cipher_file.read_bytes()
        else:
            ciphertext = _encrypt_decrypt_pycrypto(
                mode, plaintext, key_b, iv_b if mode != "ecb" else None, encrypt=True
            )
            (TASK5_DIR / f"task5_{mode}.bin").write_bytes(ciphertext)

        n_cipher = len(ciphertext)

        if BYTE_INDEX_TO_CORRUPT >= n_cipher:
            print(f"  {mode.upper()}: ciphertext too short ({n_cipher} bytes), need index {BYTE_INDEX_TO_CORRUPT}; skip.")
            continue

        # Corrupt 55th byte (one bit)
        corrupted = corrupt_one_bit(ciphertext, BYTE_INDEX_TO_CORRUPT, BIT_MASK)
        corrupted_file = TASK5_DIR / f"task5_{mode}_corrupted.bin"
        corrupted_file.write_bytes(corrupted)

        if use_openssl:
            decrypted_file = TASK5_DIR / f"task5_{mode}_decrypted.bin"
            run_openssl_dec(
                mode, corrupted_file, decrypted_file, KEY_HEX,
                IV_HEX if mode != "ecb" else None
            )
            decrypted = decrypted_file.read_bytes()
        else:
            decrypted = _encrypt_decrypt_pycrypto(
                mode, corrupted, key_b, iv_b if mode != "ecb" else None, encrypt=False
            )
            (TASK5_DIR / f"task5_{mode}_decrypted.bin").write_bytes(decrypted)

        # Compare
        rec = compare_recovery(plaintext, decrypted)
        rec["mode"] = mode
        rec["cipher_len"] = n_cipher
        results.append(rec)

        first_err = rec["first_error_index"]
        err_str = f"first error at byte {first_err}" if first_err is not None else "no errors"
        print(f"  {mode.upper():3} | cipher: {n_cipher} bytes | "
              f"recovered: {rec['matching_bytes']}/{n_plain} bytes ({rec['recoverable_pct']:.2f}%) | {err_str}")

    print()
    print("=" * 70)
    print("Recovery summary (how much information can you recover?)")
    print("=" * 70)

    for rec in results:
        m = rec["mode"].upper()
        pct = rec["recoverable_pct"]
        first = rec["first_error_index"]
        block_of_first = (first // 16) if first is not None else None
        print(f"\n{m}:")
        print(f"  Recovered: {rec['matching_bytes']} / {rec['original_len']} bytes ({pct:.2f}%)")
        if first is not None:
            print(f"  First corrupted plaintext byte: index {first} (block index {block_of_first})")
        print(f"  Justification: see SEED Lab manual §7 and report.")

    print()
    print("Output files in:", TASK5_DIR)
    print("  Encrypted:      task5_ecb.bin, task5_cbc.bin, task5_cfb.bin, task5_ofb.bin")
    print("  Corrupted:      task5_<mode>_corrupted.bin")
    print("  Decrypted:      task5_<mode>_decrypted.bin")


if __name__ == "__main__":
    main()
