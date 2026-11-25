"""Pure-Python Academic Integrity (Calibrated AI Stylometry + Plagiarism + Behavioral Biometrics) & DLP Scanner."""

from __future__ import annotations

import math
import re
from typing import Any, Literal, TypedDict

from ai_detector import analyze_ai_vs_human
from analyzer import analyze_message
from rules_config import (
    AI_PROBABILITY_WEIGHT,
    CERT_MAX_PLAGIARISM_PCT,
    CERT_MIN_ORIGINALITY_SCORE,
    CERT_MIN_WORD_COUNT,
    PLAGIARISM_MATCH_MIN_PCT,
    PLAGIARISM_WEIGHT,
)
from text_utils import normalize_arabic

# Built-in sample academic reference corpus for offline shingling plagiarism checks
BUILTIN_CORPUS: list[dict[str, str]] = [
    {
        "source": "IEEE Cybersecurity & Phishing Taxonomy (2025)",
        "text": (
            "Phishing attacks exploit human cognitive biases by creating artificial urgency and "
            "impersonating trusted financial institutions through homograph domains and shortened links."
        ),
    },
    {
        "source": "مجلة الجامعة التكنولوجية للأمن السيبراني (2025)",
        "text": (
            "تعتمد هجمات التصيد الإلكتروني على انتحال صفة المصارف والمؤسسات الرسمية عبر نطاقات "
            "مشابهة للخداع البصري ومطالبة الضحية بإرسال رموز التحقق المؤقتة أو بيانات البطاقة المصرفية."
        ),
    },
    {
        "source": "Academic Integrity & Stylometry Survey (2024)",
        "text": (
            "Automated text generation systems often exhibit uniform sentence length distributions, "
            "predictable transitional connectors, and reduced lexical burstiness compared to human authorship."
        ),
    },
]

SECRET_PATTERNS: list[tuple[str, str, str, re.Pattern[str]]] = [
    (
        "private_key",
        "مفتاح تشفير خاص مكشوف (Private Key PEM/SSH)",
        "Exposed Private Key Material (PEM / SSH)",
        re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    ),
    (
        "api_key",
        "مفتاح برمجي أو سر وصول مكشوف (API Key / Token)",
        "Exposed API Key or Access Token",
        re.compile(
            r"\b(?:AIza[0-9A-Za-z\-_]{20,}|sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,}|"
            r"AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}|sk_live_[0-9A-Za-z]{16,}|hf_[A-Za-z0-9]{20,})\b"
        ),
    ),
    (
        "env_secret",
        "بيانات اعتماد أو متغير بيئة سري (.env Secret / Password)",
        "Exposed Environment Secret / Credential Assignment",
        re.compile(
            r"\b(?:SECRET_KEY|API_KEY|ACCESS_KEY|AUTH_TOKEN|DB_PASS(?:WORD)?|DATABASE_URL|"
            r"PRIVATE_KEY|CLIENT_SECRET|PASSWORD)\s*=\s*['\"]?[^\s'\"]{6,}['\"]?",
            re.IGNORECASE,
        ),
    ),
    (
        "bearer_token",
        "رمز تفويض وصول مكشوف (Bearer Token)",
        "Exposed HTTP Bearer Authorization Token",
        re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/=]{16,}\b"),
    ),
    (
        "jwt_token",
        "رمز جلسة مصادقة مكشوف (JWT Token)",
        "Exposed JWT Authentication Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    (
        "iraq_phone",
        "رقم هاتف شخصي مكشوف (قد ينتهك خصوصية الطلبة)",
        "Exposed Personal Phone Number",
        re.compile(r"(?:\+?964|0)7[3-9]\d{8}\b"),
    ),
    (
        "email_pii",
        "عنوان بريد إلكتروني مكشوف",
        "Exposed Email Address (PII)",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "payment_card",
        "رقم بطاقة دفع محتمل مكشوف",
        "Potential Payment Card Number Detected",
        re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    ),
]

_HIGH_SEVERITY_DLP_RULES = {
    "private_key",
    "api_key",
    "env_secret",
    "bearer_token",
    "jwt_token",
    "payment_card",
}


class BehavioralMetrics(TypedDict):
    keystrokes: int
    pasted_chars: int
    total_chars: int
    avg_interval_ms: float
    interval_std_ms: float


def _tokenize_words(text: str) -> list[str]:
    return re.findall(r"[\w\u0600-\u06FF]+", text.lower())


def _word_shingles(words: list[str], k: int = 4) -> set[tuple[str, ...]]:
    if len(words) < k:
        return {tuple(words)} if words else set()
    return {tuple(words[i : i + k]) for i in range(len(words) - k + 1)}


def _luhn_valid(digits: str) -> bool:
    """Validate payment card candidates via Luhn mod-10 checksum to avoid numeric ID false positives."""
    nums = [int(c) for c in digits if c.isdigit()]
    if len(nums) < 13 or len(nums) > 19:
        return False
    checksum = 0
    parity = len(nums) % 2
    for idx, n in enumerate(nums):
        if idx % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


def _mask_secret(raw: str) -> str:
    """Redact middle characters so DLP reports never echo raw secrets or PII."""
    clean = raw.strip()
    if len(clean) <= 6:
        return "***"
    return f"{clean[:3]}••••{clean[-3:]}"


def _compute_plagiarism_matches(
    norm_text: str,
    reference_text: str | None,
) -> tuple[list[dict[str, Any]], int]:
    corpus_sources = list(BUILTIN_CORPUS)
    if reference_text and reference_text.strip():
        corpus_sources.insert(
            0,
            {
                "source": "المصدر المرجعي المُرفق / Attached Reference",
                "text": reference_text.strip()[:15000],
            },
        )

    doc_norm_words = _tokenize_words(norm_text)
    doc_norm_shingles = _word_shingles(doc_norm_words, k=4)
    plagiarism_matches: list[dict[str, Any]] = []
    max_overlap_pct = 0

    for src in corpus_sources:
        ref_words = _tokenize_words(normalize_arabic(src["text"]))
        ref_shingles = _word_shingles(ref_words, k=4)
        if not doc_norm_shingles or not ref_shingles:
            continue
        inter = doc_norm_shingles.intersection(ref_shingles)
        if not inter:
            continue

        overlap_pct = min(100, round((len(inter) / len(doc_norm_shingles)) * 100))
        union_count = len(doc_norm_shingles.union(ref_shingles))
        jaccard_pct = min(100, round((len(inter) / max(1, union_count)) * 100))
        max_overlap_pct = max(max_overlap_pct, overlap_pct)

        if overlap_pct >= PLAGIARISM_MATCH_MIN_PCT:
            ordered_phrases = sorted((" ".join(sh) for sh in inter))
            plagiarism_matches.append(
                {
                    "source": src["source"],
                    "overlap_pct": overlap_pct,
                    "jaccard_pct": jaccard_pct,
                    "sample": ordered_phrases[0],
                    "samples": ordered_phrases[:3],
                }
            )

    return plagiarism_matches, max(0, min(100, max_overlap_pct))


LiveBehaviorPreview = Literal["not_captured", "human_cadence", "paste_heavy"]


def compute_interval_stats(intervals_ms: list[int | float] | None) -> dict[str, float]:
    """Compute mean and population std-dev (1 decimal) across valid keystroke intervals [10..2500] ms."""
    if not intervals_ms:
        return {"avg_interval_ms": 0.0, "interval_std_ms": 0.0}
    valid = [
        float(ms)
        for ms in intervals_ms
        if isinstance(ms, (int, float)) and not isinstance(ms, bool) and math.isfinite(ms) and 10 <= ms <= 2500
    ]
    if not valid:
        return {"avg_interval_ms": 0.0, "interval_std_ms": 0.0}
    mean = sum(valid) / len(valid)
    variance = sum((val - mean) ** 2 for val in valid) / len(valid)
    return {
        "avg_interval_ms": round(mean, 1),
        "interval_std_ms": round(math.sqrt(variance), 1),
    }


def build_behavior_telemetry(
    *,
    intervals_ms: list[int | float] | None = None,
    keystrokes: int = 0,
    pasted_chars: int = 0,
    total_chars: int = 0,
    avg_interval_ms: float | None = None,
    interval_std_ms: float | None = None,
) -> BehavioralMetrics:
    """Construct normalized behavioral typing telemetry from raw intervals or precomputed metrics."""
    if intervals_ms is not None:
        stats = compute_interval_stats(intervals_ms)
        resolved_avg = stats["avg_interval_ms"]
        resolved_std = stats["interval_std_ms"]
    else:
        resolved_avg = float(avg_interval_ms or 0.0)
        resolved_std = float(interval_std_ms or 0.0)

    return {
        "keystrokes": max(0, round(float(keystrokes))),
        "pasted_chars": max(0, round(float(pasted_chars))),
        "total_chars": max(0, round(float(total_chars))),
        "avg_interval_ms": resolved_avg,
        "interval_std_ms": resolved_std,
    }


def classify_behavior_preview(telemetry: BehavioralMetrics | dict[str, Any]) -> LiveBehaviorPreview:
    """Classify typing telemetry into a concise behavioral indicator category."""
    keystrokes = int(telemetry.get("keystrokes", 0))
    pasted_chars = int(telemetry.get("pasted_chars", 0))
    total_chars = int(telemetry.get("total_chars", 0))
    interval_std = float(telemetry.get("interval_std_ms", 0.0))

    if keystrokes == 0 and pasted_chars == 0:
        return "not_captured"
    denom = max(1, total_chars)
    paste_ratio = pasted_chars / denom
    if paste_ratio >= 0.65:
        return "paste_heavy"
    if keystrokes >= 10 and interval_std >= 20:
        return "human_cadence"
    return "paste_heavy" if pasted_chars > keystrokes * 2 else "not_captured"


def _evaluate_typing_behavior(
    behavior: BehavioralMetrics | dict[str, Any] | None,
    raw_len: int,
) -> tuple[str, int, float, float, float]:
    if not behavior or not isinstance(behavior, dict):
        return "not_captured", 100, 0.0, 0.0, 0.0

    raw_intervals = behavior.get("intervals_ms")
    normalized = build_behavior_telemetry(
        intervals_ms=raw_intervals if isinstance(raw_intervals, list) else None,
        keystrokes=int(behavior.get("keystrokes", 0)),
        pasted_chars=int(behavior.get("pasted_chars", 0)),
        total_chars=int(behavior.get("total_chars", raw_len)),
        avg_interval_ms=float(behavior.get("avg_interval_ms", 0.0)),
        interval_std_ms=float(behavior.get("interval_std_ms", 0.0)),
    )

    total_chars = max(1, normalized["total_chars"])
    pasted_chars = normalized["pasted_chars"]
    keystrokes = normalized["keystrokes"]
    avg_interval = normalized["avg_interval_ms"]
    interval_std = normalized["interval_std_ms"]
    paste_ratio = round(min(1.0, pasted_chars / total_chars), 2)

    if keystrokes >= 15 and paste_ratio < 0.25:
        if interval_std >= 20:
            return "human_verified", 94, paste_ratio, avg_interval, interval_std
        return "robotic_cadence", 45, paste_ratio, avg_interval, interval_std
    if paste_ratio >= 0.65:
        return "bulk_pasted", 35, paste_ratio, avg_interval, interval_std
    if keystrokes > 0:
        return "mixed_input", 72, paste_ratio, avg_interval, interval_std
    return "not_captured", 100, paste_ratio, avg_interval, interval_std


def _build_academic_signals(
    *,
    ai_res: dict[str, Any],
    plagiarism_matches: list[dict[str, Any]],
    plagiarism_pct: int,
    behavior_status: str,
    paste_ratio: float,
) -> list[dict[str, str]]:
    signals: list[dict[str, str]] = [
        {
            "severity": "safe" if ev["severity"] == "safe" else "medium",
            "title_ar": ev["title_ar"],
            "title_en": ev["title_en"],
            "detail": f"{ev['source']} · {ev['observed_value']}",
        }
        for ev in ai_res["evidence_bundle"]["evidence"]
    ]

    if plagiarism_matches:
        signals.append(
            {
                "severity": "high",
                "title_ar": f"تشابه نصي بنسبة {plagiarism_pct}% مع مصادر مرجعية (4-gram)",
                "title_en": f"{plagiarism_pct}% 4-gram overlap with reference corpus",
                "detail": plagiarism_matches[0]["source"],
            }
        )

    if behavior_status == "human_verified":
        signals.append(
            {
                "severity": "safe",
                "title_ar": "البصمة السلوكية للكتابة تشير لإدخال بشري حي",
                "title_en": "Behavioral typing cadence aligns with live human input",
                "detail": f"Paste ratio: {int(paste_ratio * 100)}%",
            }
        )
    elif behavior_status == "bulk_pasted":
        signals.append(
            {
                "severity": "medium",
                "title_ar": "نسبة لصق مباشر مرتفعة مقارنةً بضغطات المفاتيح",
                "title_en": "High bulk-paste ratio relative to keystrokes",
                "detail": f"Paste ratio: {int(paste_ratio * 100)}%",
            }
        )

    return signals


def analyze_academic_text(
    text: str,
    reference_text: str | None = None,
    behavior: BehavioralMetrics | dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate calibrated AI stylometry, n-gram plagiarism overlap, and typing behavior."""
    raw = (text or "").strip()[:15000]
    ai_res = analyze_ai_vs_human(raw)
    word_count = int(ai_res["word_count"])
    sentence_count = int(ai_res["sentence_count"])
    norm = normalize_arabic(raw)

    plagiarism_matches, plagiarism_pct = _compute_plagiarism_matches(norm, reference_text)
    behavior_status, behavior_score, paste_ratio, avg_interval_ms, interval_std_ms = _evaluate_typing_behavior(
        behavior, len(raw)
    )

    cal_prob = ai_res["calibrated_ai_probability"]
    ai_probability = round(cal_prob * 100) if cal_prob is not None else None

    # Originality reflects verified overlap + calibrated AI likelihood (never penalize inconclusive short texts).
    effective_ai_pct = ai_probability if ai_probability is not None else 0
    originality_score = max(
        0,
        min(100, round(100 - (plagiarism_pct * PLAGIARISM_WEIGHT + effective_ai_pct * AI_PROBABILITY_WEIGHT))),
    )

    if plagiarism_pct >= 30 or ai_res["classification"] == "ai_leaning":
        verdict = "flagged" if (plagiarism_pct >= 40 or (ai_probability is not None and ai_probability >= 75)) else "review_needed"
    elif ai_res["classification"] == "inconclusive" or behavior_status in {"bulk_pasted", "robotic_cadence"}:
        verdict = "review_needed"
    else:
        verdict = "authentic"

    signals = _build_academic_signals(
        ai_res=ai_res,
        plagiarism_matches=plagiarism_matches,
        plagiarism_pct=plagiarism_pct,
        behavior_status=behavior_status,
        paste_ratio=paste_ratio,
    )

    metrics = ai_res["metrics"]
    richness_norm = min(1.0, round(metrics["root_ttr"] / 8.5, 2))

    ai_res["evidence_bundle"]["limitations"].append(
        {
            "code": "offline_plagiarism_scope",
            "ar": "فحص الاستلال يقارن النص فقط مع المرجع المرفق وثلاث وثائق عينة محلية (لا يفحص الإنترنت أو قواعد الجامعات الخارجية).",
            "en": "Plagiarism 4-gram shingling compares only against the attached reference and 3 built-in sample documents (not external web databases).",
        }
    )

    eligible_for_certificate = (
        originality_score >= CERT_MIN_ORIGINALITY_SCORE
        and word_count >= CERT_MIN_WORD_COUNT
        and plagiarism_pct < CERT_MAX_PLAGIARISM_PCT
    )

    return {
        "word_count": word_count,
        "sentence_count": sentence_count,
        "lexical_richness": richness_norm,
        "burstiness": round(metrics["burstiness_cv"], 2),
        "ai_probability": ai_probability,
        "plagiarism_pct": plagiarism_pct,
        "originality_score": originality_score,
        "verdict": verdict,
        "plagiarism_matches": plagiarism_matches,
        "behavior": {
            "status": behavior_status,
            "score": behavior_score,
            "paste_ratio": paste_ratio,
            "avg_interval_ms": avg_interval_ms,
            "interval_std_ms": interval_std_ms,
        },
        "signals": signals,
        "ai_detection": ai_res,
        "eligible_for_certificate": eligible_for_certificate,
    }


def scan_dlp_content(text: str) -> dict[str, Any]:
    """Data Loss Prevention (DLP) & file security scanner for PII, secrets, and embedded links."""
    raw = (text or "")[:20000]
    findings: list[dict[str, str]] = []
    seen_masked: set[str] = set()

    for rule_id, title_ar, title_en, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(raw):
            val = match.group(0)
            if rule_id == "payment_card" and not _luhn_valid(re.sub(r"\D", "", val)):
                continue
            masked = _mask_secret(val)
            dedup_key = f"{rule_id}:{masked}"
            if dedup_key in seen_masked:
                continue
            seen_masked.add(dedup_key)
            findings.append(
                {
                    "id": rule_id,
                    "title_ar": title_ar,
                    "title_en": title_en,
                    "masked_value": masked,
                    "severity": "high" if rule_id in _HIGH_SEVERITY_DLP_RULES else "medium",
                }
            )

    cyber_res = analyze_message(raw[:5000])
    risk_score = min(100, cyber_res["score"] + len(findings) * 20)
    verdict = "safe" if risk_score <= 29 else ("suspicious" if risk_score <= 64 else "dangerous")

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "dlp_findings": findings,
        "urls_found": cyber_res["urls"],
        "url_forensics": cyber_res["url_forensics"],
        "cyber_reasons": cyber_res["reasons"],
    }
