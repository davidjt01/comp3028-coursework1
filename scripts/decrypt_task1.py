"""
Task 1: Decrypt substitution cipher using provided letter frequency,
bigram and trigram data. All steps are logged with justification.

Coursework: COMP3028 Computer Security – discover encryption key and decipher
article_encrypted.txt using data/frequencies/*.json.

Usage (from project root):
    python scripts/decrypt_task1.py

Or:
    python -m scripts.decrypt_task1
"""

import json
import logging
import math
import random
import sys
from pathlib import Path
from collections import Counter

# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
TASK1_DIR = DATA_DIR / "task1"
FREQ_DIR = DATA_DIR / "frequencies"
CIPHERTEXT_PATH = TASK1_DIR / "article_encrypted.txt"
LETTER_FREQ_PATH = FREQ_DIR / "letter_frequency.json"
BIGRAM_FREQ_PATH = FREQ_DIR / "bigram_frequency.json"
TRIGRAM_FREQ_PATH = FREQ_DIR / "trigram_frequency.json"
OUTPUT_PLAINTEXT_PATH = TASK1_DIR / "article_decrypted.txt"
OUTPUT_KEY_PATH = TASK1_DIR / "substitution_key.txt"

ALPHABET = "abcdefghijklmnopqrstuvwxyz"

# Configure logging: process log with justification for each step
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    stream=sys.stdout,
)
LOG = logging.getLogger(__name__)


def log_section(title: str) -> None:
    LOG.info("")
    LOG.info("=" * 60)
    LOG.info("  %s", title)
    LOG.info("=" * 60)


def log_step(step: str, justification: str) -> None:
    LOG.info("  STEP: %s", step)
    LOG.info("  JUSTIFICATION: %s", justification)
    LOG.info("")


# --- Load and parse frequency data ---

def load_letter_frequencies() -> list[tuple[str, float]]:
    """
    Load letter frequency JSON and return list of (letter_lower, percentage).
    Letters ordered by frequency descending (E first, then T, A, ...).
    """
    log_section("Loading letter frequency data")
    with open(LETTER_FREQ_PATH, encoding="utf-8") as f:
        data = json.load(f)
    # Parse "12.7%" -> 12.7; use uppercase letter from JSON, convert to lower
    out = []
    for item in data:
        letter = item["letter"].upper()
        raw = item.get("texts_percent", "0%").replace("%", "").strip()
        try:
            pct = float(raw)
        except ValueError:
            pct = 0.0
        out.append((letter.lower(), pct))
    # Sort by frequency descending so we get standard English order (E, T, A, O, I, N, ...)
    out.sort(key=lambda x: -x[1])
    LOG.info("  Loaded %d letters; order by frequency (highest first): %s",
             len(out), " ".join(x[0] for x in out[:10]) + " ...")
    log_step(
        "Use letter frequency order to guess substitution.",
        "In English, E is most common (~12.7%%), then T (~9.1%%), A, O, I, N, etc. "
        "We will map the most frequent cipher letter to E, the second to T, and so on."
    )
    return out


def load_bigram_frequencies() -> dict[str, float]:
    """Load bigram JSON and return dict bigram -> frequency (as decimal)."""
    log_section("Loading bigram frequency data")
    with open(BIGRAM_FREQ_PATH, encoding="utf-8") as f:
        data = json.load(f)
    result = {}
    for item in data:
        bigram = item["bigram"].lower()
        raw = item.get("frequency_percent", "0%").replace("%", "").strip()
        try:
            result[bigram] = float(raw) / 100.0
        except ValueError:
            result[bigram] = 1e-6
    LOG.info("  Loaded %d bigrams; e.g. th=%.4f, he=%.4f", len(result),
             result.get("th", 0), result.get("he", 0))
    log_step(
        "Use bigram frequencies to score and refine the key.",
        "Common English bigrams (e.g. th, he, in, er) should appear often in correct plaintext; "
        "wrong keys produce rare bigrams. We score decrypted text by sum of log(bigram_prob)."
    )
    return result


def load_trigram_frequencies() -> dict[str, float]:
    """Load trigram JSON and return dict trigram -> frequency (as decimal)."""
    log_section("Loading trigram frequency data")
    with open(TRIGRAM_FREQ_PATH, encoding="utf-8") as f:
        data = json.load(f)
    result = {}
    for item in data:
        trigram = item["trigram"].lower()
        raw = item.get("frequency_percent", "").replace("%", "").strip()
        try:
            result[trigram] = float(raw) / 100.0 if raw else 1e-5
        except ValueError:
            result[trigram] = 1e-5
    LOG.info("  Loaded %d trigrams; e.g. the=%.4f, and=%.4f", len(result),
             result.get("the", 0), result.get("and", 0))
    log_step(
        "Use trigram frequencies to score and refine the key.",
        "Trigrams like 'the', 'and', 'ing' are very common in English; "
        "incorrect decryptions contain rare trigrams and get a lower score."
    )
    return result


# --- Ciphertext and n-gram extraction ---

def load_ciphertext() -> str:
    """Load raw ciphertext (preserving spaces/[] etc. for final output)."""
    log_section("Loading ciphertext")
    raw = CIPHERTEXT_PATH.read_text(encoding="utf-8")
    LOG.info("  Loaded %d characters from %s", len(raw), CIPHERTEXT_PATH.name)
    log_step(
        "We preserve the full ciphertext including non-letters (e.g. []).",
        "Non-letters are left unchanged when applying the substitution; only a-z are decrypted."
    )
    return raw


def letters_only(text: str) -> str:
    """Return lowercase letters only, for frequency analysis."""
    return "".join(c.lower() for c in text if c.isalpha())


def extract_ngrams(text: str, n: int) -> list[str]:
    """Extract overlapping n-grams from letter-only text."""
    t = letters_only(text)
    return [t[i : i + n] for i in range(len(t) - n + 1)] if len(t) >= n else []


# --- Key representation and apply ---
# Key: 26-char string. key[i] = cipher letter for plain letter alphabet[i].
# So encryption: plain 'a' -> key[0], plain 'b' -> key[1], ...
# Decryption: cipher letter c -> plain letter = alphabet[key.index(c)]

def decrypt_text(ciphertext: str, key: str) -> str:
    """Decrypt ciphertext using substitution key. Non-letters unchanged."""
    # Inverse: cipher char c -> plain char at position where key[pos]==c
    inv = {key[i]: ALPHABET[i] for i in range(26)}
    return "".join(inv.get(c.lower(), c) if c.isalpha() else c for c in ciphertext)


def encrypt_text(plaintext: str, key: str) -> str:
    """Encrypt plaintext with key (for reference)."""
    tr = str.maketrans(ALPHABET, key)
    return "".join(c.translate(tr) if c.isalpha() else c for c in plaintext.lower())


# --- Initial key from letter frequency (monogram) ---

def cipher_letter_counts(letter_only: str) -> list[tuple[str, int]]:
    """Return list of (letter, count) sorted by count descending."""
    cnt = Counter(letter_only)
    return sorted(
        [(c, cnt[c]) for c in ALPHABET if cnt[c] > 0],
        key=lambda x: -x[1],
    )


def build_initial_key(
    letter_freq_order: list[tuple[str, float]],
    cipher_ranked: list[tuple[str, int]],
) -> str:
    """
    Build initial substitution key: plaintext -> ciphertext.
    Map most frequent plain letter (E) to most frequent cipher letter, etc.
    key[plain_index] = cipher_letter.
    """
    # letter_freq_order is (letter, pct) sorted by pct desc -> E, T, A, O, I, N, ...
    plain_ranked = [x[0] for x in letter_freq_order]
    # cipher_ranked is (cipher_letter, count) sorted by count desc
    cipher_letters_ranked = [x[0] for x in cipher_ranked]
    # All 26 cipher letters: ranked first, then any missing from alphabet
    used = set(cipher_letters_ranked)
    for c in ALPHABET:
        if c not in used:
            cipher_letters_ranked.append(c)
    # Build key: key[i] = cipher letter for plain letter ALPHABET[i]
    key_list = ["?"] * 26
    for j in range(min(26, len(plain_ranked), len(cipher_letters_ranked))):
        plain = plain_ranked[j]
        cipher = cipher_letters_ranked[j]
        idx = ALPHABET.index(plain)
        key_list[idx] = cipher
    for i in range(26):
        if key_list[i] == "?":
            for c in ALPHABET:
                if c not in key_list:
                    key_list[i] = c
                    break
        if key_list[i] == "?":
            key_list[i] = ALPHABET[i]
    return "".join(key_list)


def build_initial_key_with_crib(
    letter_freq_order: list[tuple[str, float]],
    cipher_ranked: list[tuple[str, int]],
    cipher_trigram: str,
    plain_trigram: str,
) -> str | None:
    """
    Build initial key by fixing crib mapping (e.g. cipher "meh" -> plain "the")
    and filling the rest by frequency rank. Returns None if crib is invalid.
    """
    if len(cipher_trigram) != 3 or len(plain_trigram) != 3:
        return None
    cipher_trigram = cipher_trigram.lower()
    plain_trigram = plain_trigram.lower()
    key_list = ["?"] * 26
    for i in range(3):
        plain = plain_trigram[i]
        cipher = cipher_trigram[i]
        idx = ALPHABET.index(plain)
        key_list[idx] = cipher
    plain_ranked = [x[0] for x in letter_freq_order]
    cipher_letters_ranked = [x[0] for x in cipher_ranked]
    used = set(cipher_letters_ranked)
    for c in ALPHABET:
        if c not in used:
            cipher_letters_ranked.append(c)
    j = 0
    for plain in plain_ranked:
        idx = ALPHABET.index(plain)
        if key_list[idx] != "?":
            continue
        while j < len(cipher_letters_ranked) and cipher_letters_ranked[j] in key_list:
            j += 1
        if j < len(cipher_letters_ranked):
            key_list[idx] = cipher_letters_ranked[j]
            j += 1
    for i in range(26):
        if key_list[i] == "?":
            for c in ALPHABET:
                if c not in key_list:
                    key_list[i] = c
                    break
        if key_list[i] == "?":
            key_list[i] = ALPHABET[i]
    return "".join(key_list)


# --- Fitness (n-gram score) ---

def safe_log(p: float, floor: float = 1e-10) -> float:
    """Log with floor to avoid -inf."""
    return math.log(max(p, floor))


def fitness(
    decrypted_letters: str,
    unigram_probs: dict[str, float],
    bigram_probs: dict[str, float],
    trigram_probs: dict[str, float],
    weights: tuple[float, float, float] = (0.2, 0.3, 0.5),
) -> float:
    """
    Score decrypted text: higher = more English-like.
    Uses weighted sum of log(prob) for unigrams, bigrams, trigrams.
    Missing n-grams get a small default probability.
    """
    default_uni = 1e-5
    default_bi = 1e-8
    default_tri = 1e-10
    score = 0.0
    if weights[0] > 0:
        for c in decrypted_letters:
            score += weights[0] * safe_log(unigram_probs.get(c, default_uni))
    if weights[1] > 0:
        for bg in extract_ngrams(decrypted_letters, 2):
            score += weights[1] * safe_log(bigram_probs.get(bg, default_bi))
    if weights[2] > 0:
        for tg in extract_ngrams(decrypted_letters, 3):
            score += weights[2] * safe_log(trigram_probs.get(tg, default_tri))
    return score


# --- Hill climbing ---

def hill_climb(
    cipher_letters: str,
    key: str,
    unigram_probs: dict[str, float],
    bigram_probs: dict[str, float],
    trigram_probs: dict[str, float],
    max_iterations: int = 5000,
    no_improve_limit: int = 1000,
    verbose: bool = True,
) -> str:
    """
    Refine key by repeatedly swapping two letters in the key; keep swap if fitness improves.
    """
    current_key = key
    current_dec = decrypt_text(cipher_letters, current_key)
    current_score = fitness(
        letters_only(current_dec),
        unigram_probs,
        bigram_probs,
        trigram_probs,
    )
    if verbose:
        LOG.info("  Initial fitness (log-probability sum): %.2f", current_score)
        log_step(
            "Iteratively swap two letters in the key and re-score decrypted text.",
            "If the new key yields higher n-gram fitness, we keep it. "
            "This escapes local errors from monogram-only mapping (e.g. similar-frequency letters)."
        )
    no_improve = 0
    key_list = list(current_key)
    for it in range(max_iterations):
        if no_improve >= no_improve_limit:
            if verbose:
                LOG.info("  No improvement for %d iterations; stopping.", no_improve_limit)
            break
        # Swap two random positions
        i, j = random.randint(0, 25), random.randint(0, 25)
        if i == j:
            continue
        key_list[i], key_list[j] = key_list[j], key_list[i]
        new_key = "".join(key_list)
        new_dec = decrypt_text(cipher_letters, new_key)
        new_score = fitness(
            letters_only(new_dec),
            unigram_probs,
            bigram_probs,
            trigram_probs,
        )
        if new_score > current_score:
            current_key = new_key
            current_score = new_score
            no_improve = 0
            if verbose:
                LOG.info("  Iteration %d: fitness improved to %.2f (swap key[%s]<->key[%s])",
                         it, current_score, ALPHABET[i], ALPHABET[j])
        else:
            key_list[i], key_list[j] = key_list[j], key_list[i]
            no_improve += 1
    return current_key


def exhaustive_swap_refinement(
    ciphertext: str,
    key: str,
    unigram_probs: dict[str, float],
    bigram_probs: dict[str, float],
    trigram_probs: dict[str, float],
    verbose: bool = True,
) -> str:
    """
    Refine key by trying every pair swap (key[i], key[j]); keep any swap that
    improves fitness. Repeat until no improvement. Ensures we reach a local
    maximum over all 325 possible single swaps.
    """
    current_key = key
    current_dec = decrypt_text(ciphertext, current_key)
    current_score = fitness(
        letters_only(current_dec),
        unigram_probs,
        bigram_probs,
        trigram_probs,
    )
    improved = True
    round_num = 0
    while improved:
        improved = False
        round_num += 1
        key_list = list(current_key)
        for i in range(26):
            for j in range(i + 1, 26):
                key_list[i], key_list[j] = key_list[j], key_list[i]
                new_key = "".join(key_list)
                new_dec = decrypt_text(ciphertext, new_key)
                new_score = fitness(
                    letters_only(new_dec),
                    unigram_probs,
                    bigram_probs,
                    trigram_probs,
                )
                if new_score > current_score:
                    current_key = new_key
                    current_score = new_score
                    improved = True
                    if verbose:
                        LOG.info("  Refinement: swap %s<->%s (fitness %.2f)",
                                 ALPHABET[i], ALPHABET[j], current_score)
                    break
                else:
                    key_list[i], key_list[j] = key_list[j], key_list[i]
            if improved:
                break
    if verbose and round_num > 1:
        LOG.info("  Exhaustive refinement: %d round(s), final fitness %.2f",
                 round_num, current_score)
    return current_key


# --- Unigram probs from letter frequency ---

def unigram_probs_from_letter_freq(letter_freq: list[tuple[str, float]]) -> dict[str, float]:
    """Convert letter frequency list to dict letter -> probability (sum to 1)."""
    total = sum(p for _, p in letter_freq)
    if total <= 0:
        total = 1.0
    return {letter: p / total for letter, p in letter_freq}


# --- Output key in coursework format ---

def apply_swaps(key: str, swaps: list[tuple[int, int]]) -> str:
    """Apply a list of (i, j) index swaps to the key (swap key[i] and key[j])."""
    key_list = list(key)
    for i, j in swaps:
        key_list[i], key_list[j] = key_list[j], key_list[i]
    return "".join(key_list)


def format_key_report(key: str) -> str:
    """
    Format as required:
    Plaintext  a b c d e f g h i j k l m n o p q r s t u v w x y z
    Ciphertext <mapping>
    """
    plain_line = "Plaintext  " + " ".join(ALPHABET)
    cipher_line = "Ciphertext " + " ".join(key)
    return plain_line + "\n" + cipher_line


def main() -> None:
    LOG.info("COMP3028 Task 1: Substitution cipher decryption using frequency analysis")
    LOG.info("Using provided letter, bigram and trigram data with full process logging.")

    # 1. Load frequency data
    letter_freq = load_letter_frequencies()
    bigram_probs = load_bigram_frequencies()
    trigram_probs = load_trigram_frequencies()
    unigram_probs = unigram_probs_from_letter_freq(letter_freq)

    # 2. Load ciphertext
    ciphertext_raw = load_ciphertext()
    cipher_letters_only = letters_only(ciphertext_raw)

    log_section("Analysing ciphertext letter frequencies")
    cipher_ranked = cipher_letter_counts(cipher_letters_only)
    LOG.info("  Cipher letter counts (top 10): %s",
             ", ".join("%s=%d" % (c, n) for c, n in cipher_ranked[:10]))
    log_step(
        "Count how often each cipher letter appears.",
        "This ranking is matched to English letter frequency ranking to form the initial key."
    )

    # 3. Build initial key from monogram
    log_section("Building initial key from letter frequency (monogram)")
    initial_key = build_initial_key(letter_freq, cipher_ranked)
    LOG.info("  Plain (by freq): e t a o i n s h r d l c ...")
    LOG.info("  Cipher (by freq): %s ...", " ".join(x[0] for x in cipher_ranked[:12]))
    log_step(
        "Map cipher letters to plain letters by matching frequency rank.",
        "The most frequent cipher letter is assumed to be E, the second T, etc. "
        "This gives a first approximation of the substitution key."
    )

    # Optional: try crib-based start if a very common cipher trigram suggests "the"
    cipher_trigrams = extract_ngrams(cipher_letters_only, 3)
    trigram_counts = Counter(cipher_trigrams)
    top_trigram = trigram_counts.most_common(1)[0] if trigram_counts else ("", 0)
    LOG.info("  Most common cipher trigram: '%s' (count=%d)", top_trigram[0], top_trigram[1])
    if top_trigram[0] and top_trigram[1] >= 3:
        crib_key = build_initial_key_with_crib(
            letter_freq, cipher_ranked, top_trigram[0], "the"
        )
        if crib_key:
            log_step(
                "Also build an alternative initial key using crib: '%s' -> 'the'." % top_trigram[0],
                "The most frequent trigram in English is 'the'; using it to seed the key often improves the result."
            )
            initial_key_crib = crib_key
        else:
            initial_key_crib = None
    else:
        initial_key_crib = None

    # 4. Refine with hill climbing; multiple restarts and take best key
    log_section("Refining key with hill climbing (bigram and trigram)")
    log_step(
        "Run several restarts from frequency-based and crib-based keys; keep the key with highest fitness.",
        "Hill climbing can stop at a local maximum; multiple restarts increase the chance of finding the true key."
    )
    candidates = [(initial_key, "frequency-based")]
    if initial_key_crib is not None:
        candidates.append((initial_key_crib, "crib meh->the"))
    best_key = None
    best_score = -float("inf")
    num_restarts = 5
    for run in range(num_restarts):
        seed = 42 + run * 97
        random.seed(seed)
        start_key, label = candidates[run % len(candidates)]
        key = hill_climb(
            ciphertext_raw,
            start_key,
            unigram_probs,
            bigram_probs,
            trigram_probs,
            max_iterations=10000,
            no_improve_limit=1500,
            verbose=(run == 0),
        )
        dec = decrypt_text(ciphertext_raw, key)
        score = fitness(
            letters_only(dec),
            unigram_probs,
            bigram_probs,
            trigram_probs,
        )
        LOG.info("  Restart %d (%s) final fitness: %.2f", run + 1, label, score)
        if score > best_score:
            best_score = score
            best_key = key
    if best_key is None:
        best_key = initial_key

    # 4b. Exhaustive refinement: try every pair swap until no improvement
    log_section("Exhaustive pair-swap refinement")
    log_step(
        "Try all 325 pair swaps in the key; keep any swap that improves n-gram fitness.",
        "This fixes remaining letter confusions (e.g. b/w, p/k) so the decrypted text is fully coherent."
    )
    best_key = exhaustive_swap_refinement(
        ciphertext_raw,
        best_key,
        unigram_probs,
        bigram_probs,
        trigram_probs,
        verbose=True,
    )

    # 4c. Manual corrections: apply known plain-letter swaps for full coherence
    log_section("Manual letter-swap corrections for coherence")
    log_step(
        "Apply swaps (b<->w), (k<->v), (b<->p), (j<->x), (q<->x), (q<->z) for full coherence.",
        "Fixes world/was, marketing/governments, product/described, adjacently, complex, blitzkrieg, emphasized."
    )
    # Indices: a=0, b=1, ..., j=9, k=10, ..., p=15, q=16, ..., v=21, w=22, x=23, y=24, z=25
    manual_swaps = [
        (1, 22), (10, 21), (1, 15),  # b<->w, k<->v, b<->p
        (9, 23), (16, 23), (16, 25), # j<->x (adjacently), q<->x (complex), q<->z (blitzkrieg, emphasized)
    ]
    swap_reasons = [
        "(1,22) b<->w: corrects 'world' vs 'was' (e.g. 'end of world war i')",
        "(10,21) k<->v: corrects 'marketing' vs 'governments' (e.g. 'military and government services')",
        "(1,15) b<->p: corrects 'product' vs 'described' (e.g. 'finished product', 'described in detail')",
        "(9,23) j<->x: corrects 'adjacently' (e.g. 'used ... adjacently')",
        "(16,23) q<->x: corrects 'complex' (e.g. 'the most complex')",
        "(16,25) q<->z: corrects 'blitzkrieg' and 'emphasized'",
    ]
    for reason in swap_reasons:
        LOG.info("  %s", reason)
    best_key = apply_swaps(best_key, manual_swaps)
    LOG.info("  Applied swaps: (1,22)(10,21)(1,15)(9,23)(16,23)(16,25)")

    # 5. Final key and decryption
    log_section("Final substitution key and decryption")
    decrypted = decrypt_text(ciphertext_raw, best_key)
    LOG.info("  Key (plain -> cipher):")
    LOG.info("  %s", format_key_report(best_key))
    log_step(
        "Apply inverse substitution to ciphertext to obtain plaintext.",
        "Each cipher letter is replaced by the corresponding plain letter from the discovered key."
    )

    # 6. Write outputs
    TASK1_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_PLAINTEXT_PATH.write_text(decrypted, encoding="utf-8")
    OUTPUT_KEY_PATH.write_text(format_key_report(best_key) + "\n", encoding="utf-8")
    LOG.info("  Decrypted text saved to: %s", OUTPUT_PLAINTEXT_PATH)
    LOG.info("  Key saved to: %s", OUTPUT_KEY_PATH)

    # Show first few lines of decrypted text
    log_section("Decrypted plaintext (first 500 chars)")
    LOG.info("%s", decrypted[:500])
    if len(decrypted) > 500:
        LOG.info("... [truncated; full text in %s]", OUTPUT_PLAINTEXT_PATH.name)
    LOG.info("")
    LOG.info("Done.")


if __name__ == "__main__":
    main()
