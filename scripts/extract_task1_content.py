"""
Extract the Task 1 report body from report_task1.tex into task1_content.tex
for inclusion in the coursework1 combined report.

Run from project root: python scripts/extract_task1_content.py
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "reports" / "task1" / "report_task1.tex"
DST = ROOT / "docs" / "reports" / "coursework1" / "task1_content.tex"

# Content body in report_task1.tex (adjust slice if structure changes)
TASK1_BODY_LINES = (44, 562)


def main():
    if not SRC.exists():
        print(f"Source not found: {SRC}")
        return 1
    lines = SRC.read_text(encoding="utf-8").splitlines()
    start, end = TASK1_BODY_LINES
    chunk = "\n".join(lines[start - 1 : end])
    DST.parent.mkdir(parents=True, exist_ok=True)
    DST.write_text(chunk, encoding="utf-8")
    print(f"Written {DST}")
    return 0

if __name__ == "__main__":
    exit(main())
