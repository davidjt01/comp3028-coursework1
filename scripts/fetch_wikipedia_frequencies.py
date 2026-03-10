"""
Fetch letter frequency, bigram and trigram tables from Wikipedia and save to files.
Uses virtual environment dependencies only (see requirements.txt).
"""

import re
import json
from pathlib import Path

import requests
from bs4 import BeautifulSoup

# Output directory: data/frequencies in project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "data" / "frequencies"

# Wikipedia URLs
URL_LETTER_FREQ = "https://en.wikipedia.org/wiki/Letter_frequency"
URL_BIGRAM = "https://en.wikipedia.org/wiki/Bigram"
URL_TRIGRAM = "https://en.wikipedia.org/wiki/Trigram"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0 "
    "(Coursework script; educational use)"
)


def fetch_page(url: str) -> str:
    """Fetch raw HTML from a URL."""
    resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=30)
    resp.raise_for_status()
    return resp.text


def parse_letter_frequency(html: str) -> list[dict]:
    """
    Parse the main English letter frequency table from Letter_frequency.
    Table: Letter | Relative frequency (Texts | Dictionaries).
    """
    soup = BeautifulSoup(html, "html.parser")
    tables = soup.find_all("table", class_="wikitable")
    best = []
    for table in tables:
        rows = table.find_all("tr")
        if not rows:
            continue
        result = []
        for row in rows:
            cells = row.find_all(["td", "th"])
            if len(cells) < 2:
                continue
            letter = cells[0].get_text(strip=True)
            if len(letter) != 1 or letter.upper() not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                continue
            texts_pct = cells[1].get_text(strip=True)
            dict_pct = cells[2].get_text(strip=True) if len(cells) > 2 else ""
            result.append({
                "letter": letter.upper(),
                "texts_percent": texts_pct,
                "dictionaries_percent": dict_pct,
            })
        if len(result) == 26 and (not best or any(r["dictionaries_percent"] for r in result)):
            best = result
            if any(r["dictionaries_percent"] for r in result):
                break
    return best


def parse_bigram_frequency(html: str) -> list[dict]:
    """
    Parse bigram frequency from Bigram page. Data is in a <pre> block:
    th 3.56% of 1.17% io 0.83%
    ...
    """
    soup = BeautifulSoup(html, "html.parser")
    for pre in soup.find_all("pre"):
        text = pre.get_text()
        # Pattern: bigram (2 letters) followed by optional space and percentage
        # Lines look like: "th 3.56% of 1.17% io 0.83%"
        pairs = re.findall(r"([a-z]{2})\s*([\d.]+)%?", text)
        if pairs:
            return [
                {"bigram": b, "frequency_percent": f"{p}%"}
                for b, p in pairs
            ]
    return []


def parse_trigram_frequency(html: str) -> list[dict]:
    """
    Parse trigram frequency table from Trigram page.
    Table: Rank | Trigram | Frequency
    """
    soup = BeautifulSoup(html, "html.parser")
    # Try all tables (Wikipedia may use different class names)
    for table in soup.find_all("table"):
        rows = table.find_all("tr")
        result = []
        for row in rows:
            cells = row.find_all(["td", "th"])
            if len(cells) < 2:
                continue
            rank_cell = cells[0].get_text(strip=True)
            trigram_cell = (cells[1].get_text(strip=True) if len(cells) > 1 else "").lower()
            freq_cell = cells[2].get_text(strip=True) if len(cells) > 2 else ""
            # Skip header row
            if rank_cell.lower() == "rank" or trigram_cell == "trigram":
                continue
            # Data row: trigram must be 3 letters
            if trigram_cell and len(trigram_cell) == 3 and trigram_cell.isalpha():
                result.append({
                    "rank": rank_cell,
                    "trigram": trigram_cell,
                    "frequency_percent": freq_cell or "",
                })
        if result:
            return result
    return []


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print("Fetching letter frequency from Wikipedia...")
    letter_html = fetch_page(URL_LETTER_FREQ)
    letter_data = parse_letter_frequency(letter_html)
    letter_path = OUTPUT_DIR / "letter_frequency.json"
    with open(letter_path, "w", encoding="utf-8") as f:
        json.dump(letter_data, f, indent=2)
    print(f"  Saved {len(letter_data)} letters to {letter_path}")

    print("Fetching bigram frequency from Wikipedia...")
    bigram_html = fetch_page(URL_BIGRAM)
    bigram_data = parse_bigram_frequency(bigram_html)
    bigram_path = OUTPUT_DIR / "bigram_frequency.json"
    with open(bigram_path, "w", encoding="utf-8") as f:
        json.dump(bigram_data, f, indent=2)
    print(f"  Saved {len(bigram_data)} bigrams to {bigram_path}")

    print("Fetching trigram frequency from Wikipedia...")
    trigram_html = fetch_page(URL_TRIGRAM)
    trigram_data = parse_trigram_frequency(trigram_html)
    trigram_path = OUTPUT_DIR / "trigram_frequency.json"
    with open(trigram_path, "w", encoding="utf-8") as f:
        json.dump(trigram_data, f, indent=2)
    print(f"  Saved {len(trigram_data)} trigrams to {trigram_path}")

    print("Done.")


if __name__ == "__main__":
    main()
