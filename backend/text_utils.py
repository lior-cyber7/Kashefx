"""Shared bilingual text normalization, similarity, and domain matching helpers."""

from __future__ import annotations

import re
from typing import Any

# Arabic diacritics (tashkeel), tatweel elongation, and zero-width evasion characters
TASHKEEL_OR_ZW_REGEX = re.compile(r"[\u064B-\u065F\u0670\u0640\u200B-\u200D\uFEFF]")

ARABIC_CHAR_REPLACEMENTS: dict[str, str] = {
    "أ": "ا",
    "إ": "ا",
    "آ": "ا",
    "ى": "ي",
    "ة": "ه",
}


def normalize_arabic_with_map(text: str) -> tuple[str, list[int]]:
    """Normalize Arabic text while tracking each output char's original string index."""
    out_chars: list[str] = []
    index_map: list[int] = []

    for idx, ch in enumerate(text):
        if TASHKEEL_OR_ZW_REGEX.match(ch):
            continue
        mapped = ARABIC_CHAR_REPLACEMENTS.get(ch, ch).lower()
        out_chars.append(mapped)
        index_map.append(idx)

    return "".join(out_chars), index_map


def normalize_arabic(text: str) -> str:
    """Return collapsed whitespace, diacritic-free, lowercase normalized Arabic text."""
    normalized, _ = normalize_arabic_with_map(text)
    return re.sub(r"\s+", " ", normalized).strip()


def levenshtein_distance(first: str, second: str) -> int:
    """Compute classic Levenshtein edit distance between two strings."""
    if first == second:
        return 0
    if not first:
        return len(second)
    if not second:
        return len(first)

    prev_row = list(range(len(second) + 1))
    for i, ch_first in enumerate(first, start=1):
        curr_row = [i]
        for j, ch_second in enumerate(second, start=1):
            cost = 0 if ch_first == ch_second else 1
            curr_row.append(
                min(
                    curr_row[j - 1] + 1,
                    prev_row[j] + 1,
                    prev_row[j - 1] + cost,
                )
            )
        prev_row = curr_row
    return prev_row[-1]


def matches_domain_suffix(host: str, domain: str) -> bool:
    """Return True if host equals domain or is a direct subdomain of domain."""
    clean_host = host.lower().strip(".")
    clean_domain = domain.lower().strip(".")
    return bool(clean_host and clean_domain) and (
        clean_host == clean_domain or clean_host.endswith(f".{clean_domain}")
    )


def split_text_by_highlights(text: str, highlights: list[str]) -> list[dict[str, Any]]:
    """Split text into non-overlapping highlighted and unhighlighted segments."""
    if not text:
        return []

    valid_highlights = sorted(
        {h for h in highlights if h and h in text},
        key=len,
        reverse=True,
    )
    if not valid_highlights:
        return [{"text": text, "highlighted": False}]

    ranges: list[tuple[int, int]] = []
    for phrase in valid_highlights:
        search_from = 0
        phrase_len = len(phrase)
        while search_from < len(text):
            idx = text.find(phrase, search_from)
            if idx == -1:
                break
            start = idx
            end = idx + phrase_len
            if not any(start < r_end and end > r_start for r_start, r_end in ranges):
                ranges.append((start, end))
            search_from = end

    if not ranges:
        return [{"text": text, "highlighted": False}]

    ranges.sort(key=lambda item: item[0])
    segments: list[dict[str, Any]] = []
    cursor = 0
    for start, end in ranges:
        if start > cursor:
            segments.append({"text": text[cursor:start], "highlighted": False})
        segments.append({"text": text[start:end], "highlighted": True})
        cursor = end

    if cursor < len(text):
        segments.append({"text": text[cursor:], "highlighted": False})

    return segments

