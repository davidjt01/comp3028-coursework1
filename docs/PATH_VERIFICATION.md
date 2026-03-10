# Path verification summary

This document records the result of a full path audit. After reorganizing the repo, run `python verify_paths.py` from the project root to check that all required paths exist.

## Scope

Paths are referenced in:

- **README.md** — project layout, script usage, build instructions
- **.gitignore** — LaTeX artifact paths (docs/reports/task1, docs/reports/coursework1)
- **scripts/** — all Python scripts use `Path(__file__).resolve().parent.parent` as project root and reference `data/`, `docs/` as needed
- **docs/reports/coursework1/report_coursework1.tex** — `\input{task1_content}`, `\input{../task4/report_task4}`, `\input{../task5/report_task5}`, `\bibliography{report_coursework1}`
- **docs/reports/task1/report_task1.tex** — `\bibliography{report_task1}` (same directory)
- **data/frequencies/README.md** — script paths and output folder

## Required paths (must exist)

These are checked by `verify_paths.py`. All must exist for the project to be complete.

| Category | Paths |
|----------|--------|
| Root | `README.md`, `requirements.txt`, `.gitignore`, `verify_paths.py` |
| Reports | `docs/reports/task1/` (report_task1.tex, report_task1.bib), `docs/reports/task4/report_task4.tex`, `docs/reports/task5/report_task5.tex`, `docs/reports/coursework1/` (report_coursework1.tex, .bib, task1_content.tex) |
| SEED manuals | `docs/seed_lab_manuals/` (optional: Crypto_Encryption.pdf) |
| Docs | `docs/PATH_VERIFICATION.md` |
| Scripts | `scripts/decrypt_task1.py`, `fetch_wikipedia_frequencies.py`, `encrypt_task4_openssl.py`, `encrypt_task4.py`, `task5_error_propagation.py` |
| Data task1 | `data/task1/article_encrypted.txt`, `article_decrypted.txt`, `article_decrypted_spaced.txt`, `substitution_key.txt` |
| Data task4 | `data/task4/f1.txt`, `f2.txt`, `f3.txt` |
| Data task5 | `data/task5/task5_plaintext.txt` |
| Data frequencies | `data/frequencies/letter_frequency.json`, `bigram_frequency.json`, `trigram_frequency.json`, `README.md` |

## Optional paths

- `docs/reports/coursework1/report_coursework1.pdf` — built by pdflatex; submission file
- `docs/seed_lab_manuals/Crypto_Encryption.pdf` — optional SEED lab manual PDF

Generated files (created by scripts, not required to exist beforehand): `data/task4/*.bin`, `data/task5/*.bin`, `docs/reports/coursework1/report_coursework1.pdf`, and LaTeX build artifacts (`.aux`, `.bbl`, etc.) listed in `.gitignore`.

## How to verify

From project root:

```bash
python verify_paths.py
```

Exit code 0 means all required paths exist.
