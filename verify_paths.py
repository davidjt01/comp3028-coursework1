"""Verify all paths referenced in the codebase. Run from project root."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Paths that must exist (README, scripts, report sources, docs)
SHOULD_EXIST = [
    # Root
    ROOT / "README.md",
    ROOT / "requirements.txt",
    ROOT / ".gitignore",
    ROOT / "verify_paths.py",
    # Reports (per-task sources + coursework1 submission)
    ROOT / "docs" / "reports" / "task1",
    ROOT / "docs" / "reports" / "task1" / "report_task1.tex",
    ROOT / "docs" / "reports" / "task1" / "report_task1.bib",
    ROOT / "docs" / "reports" / "task4",
    ROOT / "docs" / "reports" / "task4" / "report_task4.tex",
    ROOT / "docs" / "reports" / "task5",
    ROOT / "docs" / "reports" / "task5" / "report_task5.tex",
    ROOT / "docs" / "reports" / "coursework1",
    ROOT / "docs" / "reports" / "coursework1" / "report_coursework1.tex",
    ROOT / "docs" / "reports" / "coursework1" / "task1_content.tex",
    ROOT / "docs" / "reports" / "coursework1" / "report_coursework1.bib",
    # SEED lab manuals (optional: Crypto_Encryption.pdf)
    ROOT / "docs" / "seed_lab_manuals",
    ROOT / "docs" / "PATH_VERIFICATION.md",
    # Scripts
    ROOT / "scripts" / "decrypt_task1.py",
    ROOT / "scripts" / "fetch_wikipedia_frequencies.py",
    ROOT / "scripts" / "encrypt_task4_openssl.py",
    ROOT / "scripts" / "encrypt_task4.py",
    ROOT / "scripts" / "task5_error_propagation.py",
    # Data: task1
    ROOT / "data" / "task1" / "article_encrypted.txt",
    ROOT / "data" / "task1" / "article_decrypted.txt",
    ROOT / "data" / "task1" / "article_decrypted_spaced.txt",
    ROOT / "data" / "task1" / "substitution_key.txt",
    # Data: task4 inputs
    ROOT / "data" / "task4" / "f1.txt",
    ROOT / "data" / "task4" / "f2.txt",
    ROOT / "data" / "task4" / "f3.txt",
    # Data: task5 input
    ROOT / "data" / "task5" / "task5_plaintext.txt",
    # Data: frequencies
    ROOT / "data" / "frequencies" / "letter_frequency.json",
    ROOT / "data" / "frequencies" / "bigram_frequency.json",
    ROOT / "data" / "frequencies" / "trigram_frequency.json",
    ROOT / "data" / "frequencies" / "README.md",
]

# Optional: generated or alternate paths
OPTIONAL = [
    ROOT / "docs" / "reports" / "coursework1" / "report_coursework1.pdf",
    ROOT / "docs" / "seed_lab_manuals" / "Crypto_Encryption.pdf",
]


def main():
    print("Verifying paths (run from project root)...")
    print(f"Project root: {ROOT}\n")
    missing = []
    for p in SHOULD_EXIST:
        rel = p.relative_to(ROOT)
        if p.exists():
            kind = "dir " if p.is_dir() else "file"
            print(f"  OK   {kind}  {rel}")
        else:
            print(f"  MISSING     {rel}")
            missing.append(rel)
    print("\nOptional (may be absent):")
    for p in OPTIONAL:
        rel = p.relative_to(ROOT)
        print(f"  {'OK (present)' if p.exists() else 'absent (OK)'}  {rel}")
    if missing:
        print(f"\nERROR: {len(missing)} path(s) missing.")
        return 1
    print("\nAll required paths exist.")
    return 0


if __name__ == "__main__":
    exit(main())
