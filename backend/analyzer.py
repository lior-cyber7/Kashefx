"""Context-aware, evidence-based scam and phishing message analyzer (Arabic/Iraqi/MSA/English)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.request
from typing import Any, TypedDict

from evidence_engine import (
    EvidenceBundle,
    RiskLevel,
    build_evidence_bundle,
    make_evidence,
    make_limitation,
    utc_now_iso,
)
from rules_config import (
    ACTION_LURE_PHRASES,
    AUTHORITY_PHRASES,
    BENIGN_CONTEXT_DAMPENER,
    BENIGN_CONTEXT_PHRASES,
    COERCIVE_URGENCY_PHRASES,
    DEFAULT_MESSAGE_THRESHOLDS,
    DELIVERY_PHRASES,
    DIRECT_PRIZE_SCAM_PHRASES,
    INVESTMENT_PHRASES,
    JOB_PHRASES,
    LOW_SIGNAL_DAMPENER,
    MESSAGE_CATEGORY_PRIORITY,
    MESSAGE_RULE_POINTS,
    NO_SHARE_ADVISORY_PHRASES,
    OAUTH_CONSENT_PHRASES,
    SENSITIVE_CREDENTIAL_PHRASES,
    SOFT_URGENCY_PHRASES,
    SUBTLE_SE_PHRASES,
    THREAT_TYPE_LABELS,
    TRANSFER_AND_FEE_PHRASES,
    WEAK_PRIZE_WORDS,
)
from text_utils import (
    normalize_arabic,
    normalize_arabic_with_map,
    split_text_by_highlights,
)
from url_inspector import SUSPICIOUS_TLDS, UrlForensics, inspect_url_forensics

URL_REGEX = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'\u200e\u200f\u202a-\u202e]+|"
    r"\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd|ow\.ly|shorturl\.at|rebrand\.ly|t\.ly)/[^\s<>\"'\u200e\u200f]+",
    re.IGNORECASE,
)

EMOJI_REGEX = re.compile(
    "["
    "\U0001F300-\U0001F5FF"
    "\U0001F600-\U0001F64F"
    "\U0001F680-\U0001F6FF"
    "\U0001F900-\U0001F9FF"
    "\u2600-\u26FF"
    "\u2700-\u27BF"
    "]",
    flags=re.UNICODE,
)


class Reason(TypedDict):
    id: str
    points: int
    title_ar: str
    title_en: str
    detail_ar: str
    detail_en: str
    match: str


class SuspiciousSegment(TypedDict):
    text: str
    threat_type: str
    severity: str
    reason_ar: str
    reason_en: str


class HighlightSegment(TypedDict):
    text: str
    highlighted: bool


class GroupedSuspiciousSegment(TypedDict):
    text: str
    severity: str
    labels_ar: list[str]
    labels_en: list[str]
    reasons_ar: list[str]
    reasons_en: list[str]


class AnalysisResult(TypedDict):
    score: int
    verdict: str
    risk_level: RiskLevel
    category: str
    threat_types: list[str]
    reasons: list[Reason]
    highlights: list[str]
    highlight_segments: list[HighlightSegment]
    suspicious_segments: list[SuspiciousSegment]
    grouped_suspicious_segments: list[GroupedSuspiciousSegment]
    links_requiring_verification: list[dict[str, Any]]
    recommended_actions: list[dict[str, str]]
    family_warning: dict[str, str]
    auxiliary_llm: dict[str, Any]
    fingerprint: str
    urls: list[str]
    url_forensics: list[UrlForensics]
    evidence_bundle: EvidenceBundle
    scan_timestamp: str


MAX_BATCH_MESSAGES = 25
_WHATSAPP_LINE_PREFIX_RE = re.compile(
    r"^\[?\d{1,2}/\d{1,2}/\d{2,4},?\s+\d{1,2}:\d{2}(?:\s*[AP]M)?\]?\s*-?\s*[^:]{1,40}:\s*",
    re.IGNORECASE,
)

_WARNING_VERDICT_LABELS: dict[str, dict[str, str]] = {
    "ar": {"safe": "آمنة غالباً", "suspicious": "مشبوهة", "dangerous": "خطيرة"},
    "en": {"safe": "Likely Safe", "suspicious": "Suspicious", "dangerous": "Dangerous"},
}

_WARNING_CATEGORY_LABELS: dict[str, dict[str, str]] = {
    "ar": {
        "phishing_bank": "انتحال مصرفي أو جهة رسمية",
        "fake_prize": "جائزة أو سحب وهمي",
        "fake_delivery": "احتيال توصيل وطرود",
        "investment_fraud": "احتيال استثماري",
        "otp_theft": "سرقة رمز التحقق (OTP)",
        "fake_job": "عرض عمل وهمي",
        "other": "محاولة احتيال عامة",
    },
    "en": {
        "phishing_bank": "Bank or Authority Phishing",
        "fake_prize": "Fake Prize or Lottery",
        "fake_delivery": "Fake Delivery Scam",
        "investment_fraud": "Investment Fraud",
        "otp_theft": "OTP Code Theft",
        "fake_job": "Fake Job Offer",
        "other": "General Suspicious Activity",
    },
}


def parse_batch_messages(raw: str, max_items: int = MAX_BATCH_MESSAGES) -> list[str]:
    """Split pasted multi-message text or WhatsApp exports into up to max_items individual messages."""
    trimmed = (raw or "").strip()
    if not trimmed:
        return []

    block_split = [
        part.strip()
        for part in re.split(r"(?:\r?\n\s*\r?\n|\r?\n-{3,}\r?\n)", trimmed)
        if part and part.strip()
    ]
    if len(block_split) > 1:
        return block_split[:max_items]

    line_split: list[str] = []
    for line in re.split(r"\r?\n", trimmed):
        cleaned = _WHATSAPP_LINE_PREFIX_RE.sub("", line).strip()
        if len(cleaned) >= 4:
            line_split.append(cleaned)
    if len(line_split) > 1:
        return line_split[:max_items]

    return [trimmed][:max_items]


def build_family_warning_text(
    *,
    lang: str,
    score: int,
    verdict: str = "suspicious",
    category: str = "other",
    reasons: list[str] | None = None,
    verdict_label: str | None = None,
    category_label: str | None = None,
) -> str:
    """Format a concise shareable Arabic or English scam warning summary for family/colleagues."""
    is_ar = lang == "ar"
    loc = "ar" if is_ar else "en"
    resolved_verdict = verdict_label or _WARNING_VERDICT_LABELS[loc].get(verdict, verdict)
    resolved_category = category_label or _WARNING_CATEGORY_LABELS[loc].get(
        category, _WARNING_CATEGORY_LABELS[loc]["other"]
    )
    bullets = "\n".join(f"- {item}" for item in (reasons or [])[:3] if item)

    if is_ar:
        lines = [
            f"⚠️ تنبيه احتيال من أداة كشف ({resolved_verdict} — {score}/100)",
            f"التصنيف: {resolved_category}",
            f"الأسباب:\n{bullets}" if bullets else "",
            "لا تضغط على أي رابط ولا تشارك رمز التحقق (OTP) أو بيانات البطاقة.",
        ]
    else:
        lines = [
            f"⚠️ Scam Warning via Kashf ({resolved_verdict} — {score}/100)",
            f"Category: {resolved_category}",
            f"Detected signals:\n{bullets}" if bullets else "",
            "Do not click any link or share OTP codes, passwords, or card details.",
        ]
    return "\n".join(line for line in lines if line)


def compute_fingerprint(text: str) -> str:
    """Compute privacy-preserving 16-hex SHA-256 fingerprint of normalized message."""
    normalized = normalize_arabic(text)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def extract_urls(text: str, extra_url: str | None = None) -> list[str]:
    """Extract URLs from text and merge optional explicit URL without duplicates."""
    found: list[str] = []
    seen: set[str] = set()

    for match in URL_REGEX.finditer(text):
        raw = match.group(0).rstrip(".,;:!?)،؛")
        if raw and raw not in seen:
            seen.add(raw)
            found.append(raw)

    if extra_url and extra_url.strip():
        candidate = extra_url.strip().rstrip(".,;:!?)،؛")
        if candidate not in seen:
            seen.add(candidate)
            found.append(candidate)

    return found


def _match_phrases(
    raw_text: str,
    norm_text: str,
    index_map: list[int],
    phrases: list[str],
) -> str | None:
    """Find first boundary-aware phrase match and return original substring."""
    for phrase in phrases:
        norm_phrase, _ = normalize_arabic_with_map(phrase)
        parts = [re.escape(part) for part in norm_phrase.split()]
        if not parts:
            continue
        pattern_str = r"(?<!\w)" + r"[\s!؟?,،.:؛\-]+".join(parts) + r"(?!\w)"
        match = re.search(pattern_str, norm_text)
        if match:
            start_norm, end_norm = match.start(), match.end()
            if start_norm < len(index_map) and end_norm - 1 < len(index_map):
                orig_start = index_map[start_norm]
                orig_end = index_map[end_norm - 1] + 1
                return raw_text[orig_start:orig_end]
    return None


def _split_sentences(raw_text: str) -> list[str]:
    parts = re.split(r"(?<=[.!؟?\n])\s+|\n+", raw_text.strip())
    return [part.strip() for part in parts if part.strip()]


def _find_containing_sentence(sentences: list[str], snippet: str) -> str:
    if not snippet:
        return sentences[0] if sentences else ""
    for sent in sentences:
        if snippet in sent:
            return sent
    return snippet


def _run_optional_gemini_auxiliary(text: str, timeout: float = 3.5) -> dict[str, Any]:
    """Optional auxiliary semantic review using GEMINI_API_KEY (never sole verdict source)."""
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key or api_key.startswith("MY_"):
        return {
            "used": False,
            "status": "not_configured",
            "summary_ar": "المحلل الدلالي المساعد (Gemini) غير مفعّل — يعتمد التحليل على المحرك الحتمي.",
            "summary_en": "Auxiliary LLM review (Gemini) not configured; deterministic rule & context engine used.",
        }

    endpoint = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-2.5-flash:generateContent"
    )
    prompt = (
        "Analyze if this message shows social engineering or BEC/phishing cues. "
        "Respond strictly in JSON with keys: cue_detected (boolean), reason_ar (string), reason_en (string). "
        f"Message:\n{text[:1200]}"
    )
    body = json.dumps(
        {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"},
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = json.loads(resp.read(65536).decode("utf-8", errors="replace"))
        cand_text = (
            raw.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
        )
        parsed = json.loads(cand_text) if cand_text else {}
        return {
            "used": True,
            "status": "ok",
            "cue_detected": bool(parsed.get("cue_detected", False)),
            "summary_ar": str(parsed.get("reason_ar") or "تمت المراجعة الدلالية المساعدة."),
            "summary_en": str(parsed.get("reason_en") or "Auxiliary semantic check completed."),
        }
    except Exception:
        return {
            "used": False,
            "status": "unavailable",
            "summary_ar": "تعذر الوصول للمحلل الدلالي المساعد (مهلة/شبكة).",
            "summary_en": "Auxiliary Gemini check unavailable or timed out.",
        }


def _load_runtime_thresholds() -> dict[str, Any]:
    """Load administrator-configured scoring thresholds with safe defaults."""
    try:
        from dev_console import get_runtime_settings

        return get_runtime_settings()
    except Exception:
        return {
            "suspicious_threshold": DEFAULT_MESSAGE_THRESHOLDS["suspicious_threshold"],
            "dangerous_threshold": DEFAULT_MESSAGE_THRESHOLDS["dangerous_threshold"],
            "enable_auxiliary_llm": False,
        }


def _create_scan_state(raw_text: str, scan_ts: str) -> dict[str, Any]:
    return {
        "raw_text": raw_text,
        "sentences": _split_sentences(raw_text),
        "scan_ts": scan_ts,
        "reasons": [],
        "highlights": [],
        "evidence": [],
        "suspicious_segments": [],
        "threat_types": [],
        "category_points": {
            "phishing_bank": 0,
            "fake_prize": 0,
            "fake_delivery": 0,
            "investment_fraud": 0,
            "otp_theft": 0,
            "fake_job": 0,
            "other": 0,
        },
    }


def _append_finding(
    state: dict[str, Any],
    *,
    rule_id: str,
    points: int,
    title_ar: str,
    title_en: str,
    detail_ar: str,
    detail_en: str,
    match: str,
    category_key: str,
    threat_type: str,
    severity: str = "medium",
    source: str = "phishing_context_engine",
) -> None:
    """Record a matched rule across reasons, category weights, highlights, and evidence."""
    state["reasons"].append(
        {
            "id": rule_id,
            "points": points,
            "title_ar": title_ar,
            "title_en": title_en,
            "detail_ar": detail_ar,
            "detail_en": detail_en,
            "match": match,
        }
    )
    cat_points = state["category_points"]
    cat_points[category_key] = cat_points.get(category_key, 0) + points

    if threat_type not in state["threat_types"]:
        state["threat_types"].append(threat_type)
    if match and match in state["raw_text"] and match not in state["highlights"]:
        state["highlights"].append(match)

    state["evidence"].append(
        make_evidence(
            evidence_id=rule_id,
            category=threat_type,
            severity=severity,  # type: ignore[arg-type]
            title_ar=title_ar,
            title_en=title_en,
            detail_ar=detail_ar,
            detail_en=detail_en,
            source=source,
            observed_value=match[:120],
            timestamp=state["scan_ts"],
        )
    )
    seg_text = _find_containing_sentence(state["sentences"], match)
    if seg_text and not any(
        seg["text"] == seg_text and seg["threat_type"] == threat_type
        for seg in state["suspicious_segments"]
    ):
        state["suspicious_segments"].append(
            {
                "text": seg_text,
                "threat_type": threat_type,
                "severity": severity,
                "reason_ar": detail_ar,
                "reason_en": detail_en,
            }
        )


def _record_unique_url_rule(
    state: dict[str, Any],
    seen_rules: set[str],
    *,
    rule_id: str,
    points: int,
    title_ar: str,
    title_en: str,
    detail_ar: str,
    detail_en: str,
    match: str,
    category_key: str,
    threat_type: str,
    severity: str,
    source: str = "url_static_forensics",
) -> bool:
    """Record a URL-level rule at most once per message, returning True if newly added."""
    if rule_id in seen_rules:
        return False
    seen_rules.add(rule_id)
    _append_finding(
        state,
        rule_id=rule_id,
        points=points,
        title_ar=title_ar,
        title_en=title_en,
        detail_ar=detail_ar,
        detail_en=detail_en,
        match=match,
        category_key=category_key,
        threat_type=threat_type,
        severity=severity,
        source=source,
    )
    return True


def _score_url_forensics(
    url_forensics: list[UrlForensics],
    state: dict[str, Any],
) -> tuple[bool, bool]:
    """Evaluate extracted URL forensics and return (has_risky_url, all_official_urls)."""
    url_rule_flags: set[str] = set()
    has_risky_url = False

    def _add_url_rule(
        rule_id: str,
        title_ar: str,
        title_en: str,
        detail_ar: str,
        detail_en: str,
        *,
        match: str,
        category_key: str,
        threat_type: ThreatType,
        severity: Literal["critical", "high", "medium", "low"],
        source: str = "context_rule_engine",
        mark_risky: bool = True,
    ) -> None:
        nonlocal has_risky_url
        added = _record_unique_url_rule(
            state,
            url_rule_flags,
            rule_id=rule_id,
            points=MESSAGE_RULE_POINTS[rule_id],
            title_ar=title_ar,
            title_en=title_en,
            detail_ar=detail_ar,
            detail_en=detail_en,
            match=match,
            category_key=category_key,
            threat_type=threat_type,
            severity=severity,
            source=source,
        )
        if added and mark_risky:
            has_risky_url = True

    for uf in url_forensics:
        raw_url = uf["original_url"]
        if uf.get("custom_blocklisted"):
            _add_url_rule(
                "custom_domain_blocklist",
                f"نطاق محظور في قائمة المطورين ({uf['host']})",
                f"Administrator-blocklisted domain ({uf['host']})",
                "تم إدراج هذا النطاق في قائمة الحظر الخاصة عبر لوحة تحكم المطورين.",
                "This domain is explicitly blocked by platform administrators.",
                match=raw_url,
                category_key="phishing_bank",
                threat_type="suspicious_link",
                severity="critical",
                source="dev_domain_rules",
            )
        if uf["matched_brand"] and not uf["is_official_brand"]:
            _add_url_rule(
                "brand_impersonation",
                f"انتحال علامة معروفة في الرابط ({uf['matched_brand']})",
                f"Brand impersonation in URL ({uf['matched_brand']})",
                f"الرابط يقلّد أو يضمّن اسم {uf['matched_brand']} على نطاق غير رسمي.",
                f"URL mimics or embeds {uf['matched_brand']} on an unofficial domain.",
                match=raw_url,
                category_key="phishing_bank",
                threat_type="fake_authority_impersonation",
                severity="high",
            )
        if uf["is_ip"]:
            _add_url_rule(
                "raw_ip_url",
                "الرابط يستخدم عنوان IP مباشر بدل اسم نطاق",
                "Raw IP address used instead of domain",
                "الخدمات الشرعية تستخدم نطاقات رسمية بدلاً من أرقام IP.",
                "Legitimate services do not route login flows through raw IP addresses.",
                match=raw_url,
                category_key="phishing_bank",
                threat_type="suspicious_link",
                severity="high",
            )
        if uf["is_mixed_script_homograph"] or uf["has_punycode"]:
            _add_url_rule(
                "punycode_or_homograph",
                "حروف متشابهة مخادعة (Homograph) أو ترميز Punycode",
                "Homograph spoofing or Punycode domain",
                "النطاق يستخدم أحرفاً غير قياسية لخداع القارئ.",
                "Domain uses Punycode or mixed-script characters to spoof legitimate text.",
                match=raw_url,
                category_key="phishing_bank",
                threat_type="suspicious_link",
                severity="high",
            )
        if (
            uf["suspicious_params"]
            and "?" in raw_url
            and re.search(r"https?://", raw_url.split("?", 1)[1], re.IGNORECASE)
        ):
            params_preview = ", ".join(uf["suspicious_params"][:2])
            _add_url_rule(
                "open_redirect_lure",
                f"إعادة توجيه مفتوحة نحو وجهة خارجية ({params_preview})",
                f"Open-redirect parameter targeting external URL ({params_preview})",
                "يحتوي الرابط على معامل تحويل ينقل المستخدم خفية إلى وجهة خارجية غير موثوقة.",
                "URL embeds a redirect query parameter pointing to an untrusted external destination.",
                match=raw_url,
                category_key="phishing_bank",
                threat_type="suspicious_link",
                severity="high",
            )
        if uf["is_shortener"]:
            _add_url_rule(
                "shortened_url",
                "رابط مختصر يخفي الوجهة الحقيقية",
                "Shortened URL hides final destination",
                "تمنع الروابط المختصرة رؤية النطاق الحقيقي قبل فتحها.",
                "Shortened links obscure destination host until resolved.",
                match=raw_url,
                category_key="other",
                threat_type="suspicious_link",
                severity="medium",
            )
        if uf["tld"] in SUSPICIOUS_TLDS:
            _add_url_rule(
                "suspicious_tld",
                f"امتداد نطاق مرتفع المخاطر ({uf['tld']})",
                f"High-abuse top-level domain ({uf['tld']})",
                "الرابط ينتهي بامتداد شائع في حملات التصيّد.",
                "Domain uses a TLD heavily abused in phishing campaigns.",
                match=raw_url,
                category_key="other",
                threat_type="suspicious_link",
                severity="medium",
            )
        if uf["subdomain_depth"] >= 3 or uf["has_at_symbol"]:
            _add_url_rule(
                "excessive_subdomains_or_at",
                "بنية رابط مضللة بكثرة النطاقات الفرعية أو الرمز @",
                "Deceptive subdomain depth or '@' syntax",
                "ترتيب النطاق الفرعي مصمم لإخفاء اسم المضيف الفعلي.",
                "Excessive subdomains or '@' syntax obscures the true host.",
                match=raw_url,
                category_key="other",
                threat_type="suspicious_link",
                severity="medium",
            )
        if not uf["is_https"] and uf["scheme"] == "http":
            _add_url_rule(
                "no_https",
                "الرابط غير مشفر (HTTP بدون HTTPS)",
                "Unencrypted HTTP link",
                "البيانات عبر HTTP غير محمية بالتشفير.",
                "HTTP links lack transport encryption.",
                match=raw_url,
                category_key="other",
                threat_type="suspicious_link",
                severity="low",
                mark_risky=False,
            )

    all_official_urls = bool(url_forensics) and all(
        (uf["is_official_brand"] or uf.get("is_official_institution") or uf.get("custom_allowlisted"))
        and not uf.get("custom_blocklisted")
        for uf in url_forensics
    )
    return has_risky_url, all_official_urls


def _score_text_threats(
    raw_text: str,
    norm_text: str,
    index_map: list[int],
    urls: list[str],
    has_risky_url: bool,
    all_official_urls: bool,
    state: dict[str, Any],
) -> dict[str, bool]:
    """Evaluate context-sensitive linguistic scam rules and return summary signal flags."""
    action_match = _match_phrases(raw_text, norm_text, index_map, ACTION_LURE_PHRASES)
    has_action_or_link = bool(urls or action_match)
    has_benign_context = bool(_match_phrases(raw_text, norm_text, index_map, BENIGN_CONTEXT_PHRASES))

    # Guard against legitimate "do not share this OTP" banking security advisories
    has_no_share_guard = bool(
        _match_phrases(raw_text, norm_text, index_map, NO_SHARE_ADVISORY_PHRASES)
        and not urls
        and not action_match
    )

    # A. Sensitive credential / OTP / API secret request
    sensitive_match = (
        None
        if has_no_share_guard
        else _match_phrases(raw_text, norm_text, index_map, SENSITIVE_CREDENTIAL_PHRASES)
    )
    has_sensitive = bool(sensitive_match)
    if sensitive_match:
        _append_finding(
            state,
            rule_id="sensitive_data",
            points=MESSAGE_RULE_POINTS["sensitive_data"],
            title_ar="طلب رموز تحقق أو كلمات مرور أو بيانات بطاقة/مفاتيح سرية",
            title_en="Request for OTP, password, secret keys, or payment credentials",
            detail_ar="المصارف والجهات الرسمية والأصدقاء الموثوقون لا يطلبون أبداً إرسال رمز OTP أو كلمة المرور أو مفاتيح API.",
            detail_en="Legitimate services never ask users to share OTPs, passwords, CVV codes, or .env/API secrets.",
            match=sensitive_match,
            category_key="otp_theft",
            threat_type="otp_credential_theft",
            severity="critical",
        )

    # B. Financial transfer / fee / gift-card demand
    transfer_match = _match_phrases(raw_text, norm_text, index_map, TRANSFER_AND_FEE_PHRASES)
    if transfer_match:
        _append_finding(
            state,
            rule_id="money_transfer_giftcard",
            points=MESSAGE_RULE_POINTS["money_transfer_giftcard"],
            title_ar="طلب تحويل أموال أو دفع رسوم أو تغيير حساب الدفع",
            title_en="Request for money transfer, upfront fee, or changed payment routing",
            detail_ar="طلبات التحويل العاجلة أو بطاقات الهدايا أو تغيير الحساب المصرفي من سمات الاحتيال المالي.",
            detail_en="Urgent wire transfers, gift cards, or sudden payment routing changes indicate financial fraud.",
            match=transfer_match,
            category_key="phishing_bank",
            threat_type="financial_fraud",
            severity="high",
        )

    # C. Coercive urgency vs. soft urgency paired with risky action/link
    coercive_match = _match_phrases(raw_text, norm_text, index_map, COERCIVE_URGENCY_PHRASES)
    soft_urg_match = _match_phrases(raw_text, norm_text, index_map, SOFT_URGENCY_PHRASES)
    has_urgency = False
    if coercive_match:
        has_urgency = True
        _append_finding(
            state,
            rule_id="urgency",
            points=MESSAGE_RULE_POINTS["coercive_urgency"],
            title_ar="تهديد بإيقاف الحساب وضغط زمني للتحايل على التحقق",
            title_en="Account suspension threat and pressure tactic",
            detail_ar="التهديد بإغلاق الحساب يهدف لخلق ذعر يمنعك من التحقق عبر القنوات الرسمية.",
            detail_en="Threatening imminent account suspension pressures victims into skipping verification.",
            match=coercive_match,
            category_key="other",
            threat_type="urgency_pressure",
            severity="high",
        )
    elif soft_urg_match and (
        has_risky_url
        or has_sensitive
        or bool(transfer_match)
        or (bool(action_match) and not all_official_urls and not has_benign_context)
    ):
        has_urgency = True
        _append_finding(
            state,
            rule_id="urgency",
            points=MESSAGE_RULE_POINTS["soft_urgency"],
            title_ar="استعجال مقترن بدعوة لإجراء أو رابط غير موثوق",
            title_en="Urgency paired with call-to-action or untrusted link",
            detail_ar="الاستعجال بحد ذاته ليس دليلاً، لكنه مقترن هنا بدعوة فورية أو رابط يستوجب الحذر.",
            detail_en="Urgency alone is benign, but here it is paired with an immediate link or action demand.",
            match=soft_urg_match,
            category_key="other",
            threat_type="urgency_pressure",
            severity="medium",
        )

    # D. Unsolicited prize or free offer lure
    direct_prize_match = _match_phrases(raw_text, norm_text, index_map, DIRECT_PRIZE_SCAM_PHRASES)
    weak_prize_match = _match_phrases(raw_text, norm_text, index_map, WEAK_PRIZE_WORDS)
    if direct_prize_match and not has_benign_context:
        _append_finding(
            state,
            rule_id="prize_reward",
            points=MESSAGE_RULE_POINTS["direct_prize"],
            title_ar="إغراء بجائزة مالية أو سحب غير مبرر",
            title_en="Unsolicited prize or lottery lure",
            detail_ar="الادعاء بالفوز بجائزة أو سحب عشوائي وطلب التفاعل عبر رابط هو نمط احتيالي شائع.",
            detail_en="Unsolicited cash prize or raffle win claims are classic social engineering lures.",
            match=direct_prize_match,
            category_key="fake_prize",
            threat_type="fake_offer_prize",
            severity="high",
        )
    elif weak_prize_match and not has_benign_context and (
        has_risky_url or has_sensitive or bool(transfer_match) or bool(action_match)
    ):
        _append_finding(
            state,
            rule_id="prize_reward",
            points=MESSAGE_RULE_POINTS["weak_prize"],
            title_ar="إغراء بمكافأة أو عرض مجاني مقترن برابط أو طلب إجراء",
            title_en="Prize/free offer lure paired with link or action demand",
            detail_ar="تم اقتران ذكر الجائزة أو العرض المجاني بدعوة ضغط رابط أو تقديم بيانات.",
            detail_en="Prize or free-offer language is paired with a suspicious action or link.",
            match=weak_prize_match,
            category_key="fake_prize",
            threat_type="fake_offer_prize",
            severity="medium",
        )

    # E. Fake delivery / customs fee lure
    delivery_match = _match_phrases(raw_text, norm_text, index_map, DELIVERY_PHRASES)
    if delivery_match and (has_action_or_link or bool(transfer_match)):
        _append_finding(
            state,
            rule_id="fake_delivery",
            points=MESSAGE_RULE_POINTS["fake_delivery"],
            title_ar="ادعاء طرد معلق أو رسوم شحن/جمارك مع رابط أو طلب دفع",
            title_en="Delivery or customs fee claim paired with link/payment",
            detail_ar="رسائل تعذّر التسليم ورسوم الجمارك الصغيرة تُستخدم لسرقة بيانات الدفع.",
            detail_en="Fake delivery holds and micro customs fees are commonly used for card harvesting.",
            match=delivery_match,
            category_key="fake_delivery",
            threat_type="social_engineering",
            severity="medium",
        )

    # F. Fake investment returns or upfront employment fees
    invest_match = _match_phrases(raw_text, norm_text, index_map, INVESTMENT_PHRASES)
    job_match = _match_phrases(raw_text, norm_text, index_map, JOB_PHRASES)
    if invest_match:
        _append_finding(
            state,
            rule_id="fake_job_investment",
            points=MESSAGE_RULE_POINTS["fake_job_investment"],
            title_ar="وعد بأرباح مضمونة أو مضاعفة رأس المال",
            title_en="Guaranteed profit or investment fraud lure",
            detail_ar="لا يوجد استثمار حقيقي يضمن أرباحاً يومية ثابتة أو خالية من المخاطر.",
            detail_en="No legitimate investment guarantees daily fixed returns.",
            match=invest_match,
            category_key="investment_fraud",
            threat_type="financial_fraud",
            severity="high",
        )
    elif job_match:
        _append_finding(
            state,
            rule_id="fake_job_investment",
            points=MESSAGE_RULE_POINTS["fake_job_investment"],
            title_ar="عرض توظيف مشبوه يطلب رسوماً أو يعد بربح غير واقعي",
            title_en="Suspicious employment lure or upfront job fee",
            detail_ar="جهات التوظيف الموثوقة لا تطلب رسوم تسجيل مسبقة.",
            detail_en="Legitimate employers do not charge upfront hiring or registration fees.",
            match=job_match,
            category_key="fake_job",
            threat_type="financial_fraud",
            severity="high",
        )

    # G. OAuth consent phishing, calm IT/BEC social engineering, and authority impersonation
    oauth_match = _match_phrases(raw_text, norm_text, index_map, OAUTH_CONSENT_PHRASES)
    if oauth_match and not all_official_urls:
        _append_finding(
            state,
            rule_id="oauth_consent_phishing",
            points=MESSAGE_RULE_POINTS["oauth_consent_phishing"],
            title_ar="تصيّد تفويضات OAuth يطلب صلاحية قراءة وإرسال بريدك",
            title_en="OAuth consent phishing requesting mailbox read/send permissions",
            detail_ar="تطلب بعض الهجمات تفويض تطبيق خارجي لقراءة وإرسال بريدك بدلاً من سرقة كلمة المرور مباشرة.",
            detail_en="Consent phishing tricks victims into granting untrusted third-party apps full read/send access.",
            match=oauth_match,
            category_key="phishing_bank",
            threat_type="social_engineering",
            severity="high",
        )

    subtle_match = _match_phrases(raw_text, norm_text, index_map, SUBTLE_SE_PHRASES)
    authority_match = _match_phrases(raw_text, norm_text, index_map, AUTHORITY_PHRASES)
    if (
        subtle_match
        and (urls or has_action_or_link or bool(transfer_match))
        and not all_official_urls
        and not has_no_share_guard
    ):
        _append_finding(
            state,
            rule_id="subtle_social_engineering",
            points=MESSAGE_RULE_POINTS["subtle_social_engineering"],
            title_ar="هندسة اجتماعية هادئة تطلب تأكيد الوصول أو تحديث بيانات عبر قناة بديلة",
            title_en="Subtle social engineering / alternate-portal credential lure",
            detail_ar="تنتحل هذه الصيغة صفة دعم تقني أو مالي دون كلمات صاخبة لإقناع الضحية بتأكيد الدخول أو التحويل.",
            detail_en="Uses calm administrative/IT-support framing instead of noisy buzzwords to elicit credentials or transfers.",
            match=subtle_match,
            category_key="phishing_bank",
            threat_type="social_engineering",
            severity="high",
        )
    elif urls and authority_match and not all_official_urls:
        _append_finding(
            state,
            rule_id="authority_impersonation_link",
            points=MESSAGE_RULE_POINTS["authority_impersonation_link"],
            title_ar="انتحال أو إشارة لجهة مصرفية/رسمية مع رابط غير موثّق",
            title_en="Bank/authority reference combined with unverified link",
            detail_ar="المصارف والمؤسسات الرسمية لا ترسل روابط خارج نطاقاتها الموثقة لتحديث البيانات.",
            detail_en="Banks and authorities do not request updates via unofficial external domains.",
            match=authority_match,
            category_key="phishing_bank",
            threat_type="fake_authority_impersonation",
            severity="high",
        )

    return {
        "has_benign_context": has_benign_context,
        "has_sensitive": has_sensitive,
        "has_urgency": has_urgency,
        "has_transfer": bool(transfer_match),
        "has_oauth": bool(oauth_match),
        "has_subtle": bool(subtle_match),
    }


def _score_formatting_and_obfuscation(raw_text: str, state: dict[str, Any]) -> None:
    """Evaluate punctuation pressure (only if another cue fired) and filter-evasion characters."""
    punct_bursts = re.findall(r"[!؟?]{3,}", raw_text)
    emojis = EMOJI_REGEX.findall(raw_text)
    if (punct_bursts or len(emojis) >= 4) and len(state["reasons"]) > 0:
        fmt = punct_bursts[0] if punct_bursts else "".join(emojis[:4])
        _append_finding(
            state,
            rule_id="excessive_formatting",
            points=MESSAGE_RULE_POINTS["excessive_formatting"],
            title_ar="تهويل بصري بالعلامات أو الرموز التعبيرية",
            title_en="Visual pressure via excessive punctuation or emojis",
            detail_ar="تستخدم مع مؤشرات أخرى لرفع التوتر البصري.",
            detail_en="Combined with scam cues to amplify visual urgency.",
            match=fmt,
            category_key="other",
            threat_type="social_engineering",
            severity="low",
        )

    zw_matches = re.findall(r"[\u200B-\u200D\uFEFF]+", raw_text)
    tatweel_burst = re.search(r"[^\s]*\u0640{3,}[^\s]*", raw_text)
    if len(zw_matches) >= 2 or tatweel_burst:
        obf_match = tatweel_burst.group(0) if tatweel_burst else ""
        _append_finding(
            state,
            rule_id="text_obfuscation",
            points=MESSAGE_RULE_POINTS["text_obfuscation"],
            title_ar="تمويه النص برموز غير مرئية أو تطويل مفرط لتجاوز الفلاتر",
            title_en="Zero-width characters or tatweel filter evasion",
            detail_ar="تمويه الكلمات الحساسة تقنية معروفة لتخطي فلاتر الرسائل.",
            detail_en="Obfuscating words with zero-width characters or elongation evades naive keyword filters.",
            match=obf_match,
            category_key="other",
            threat_type="filter_evasion",
            severity="medium",
        )


def _apply_score_dampeners(
    reasons: list[Reason],
    urls: list[str],
    has_risky_url: bool,
    signals: dict[str, bool],
) -> int:
    """Sum rule points, apply benign-context or low-signal dampeners, and clamp to 0..100."""
    raw_score = sum(reason["points"] for reason in reasons)

    if (
        signals["has_benign_context"]
        and not signals["has_sensitive"]
        and not has_risky_url
        and not signals["has_transfer"]
        and not signals["has_oauth"]
    ):
        raw_score = max(0, raw_score - BENIGN_CONTEXT_DAMPENER)
    elif (
        not urls
        and not signals["has_sensitive"]
        and not signals["has_urgency"]
        and not signals["has_transfer"]
        and not signals["has_subtle"]
        and not signals["has_oauth"]
    ):
        raw_score = max(0, raw_score - LOW_SIGNAL_DAMPENER)

    return max(0, min(100, raw_score))


def _resolve_verdict_and_category(
    final_score: int,
    runtime_settings: dict[str, Any],
    category_points: dict[str, int],
) -> tuple[str, RiskLevel, str]:
    susp_threshold = int(
        runtime_settings.get("suspicious_threshold", DEFAULT_MESSAGE_THRESHOLDS["suspicious_threshold"])
    )
    dang_threshold = int(
        runtime_settings.get("dangerous_threshold", DEFAULT_MESSAGE_THRESHOLDS["dangerous_threshold"])
    )

    if final_score < susp_threshold:
        verdict = "safe"
    elif final_score < dang_threshold:
        verdict = "suspicious"
    else:
        verdict = "dangerous"

    if final_score >= 80:
        risk_level: RiskLevel = "critical"
    elif final_score >= 60:
        risk_level = "high"
    elif final_score >= 30:
        risk_level = "medium"
    elif final_score >= 10:
        risk_level = "low"
    else:
        risk_level = "minimal"

    best_category = "other"
    best_pts = 0
    for cat in MESSAGE_CATEGORY_PRIORITY:
        pts = category_points.get(cat, 0)
        if pts > best_pts:
            best_pts = pts
            best_category = cat

    return verdict, risk_level, best_category


def _build_links_requiring_verification(url_forensics: list[UrlForensics]) -> list[dict[str, Any]]:
    links: list[dict[str, Any]] = []
    for uf in url_forensics:
        needs_intel = not uf["is_official_brand"]
        links.append(
            {
                "url": uf["original_url"],
                "defanged_url": uf["defanged_url"],
                "static_classification": uf["classification"],
                "needs_separate_intel_check": needs_intel,
                "reason_ar": (
                    "هذا الرابط ليس نطاقاً رسمياً موثقاً ويحتاج فحصاً منفصلاً عبر قواعد Threat Intelligence و Sandbox الآمن."
                    if needs_intel
                    else "النطاق يطابق مرجعاً رسمياً، ومع ذلك يُنصح بفحصه إذا كان مختصراً أو متغيراً."
                ),
                "reason_en": (
                    "URL is not on the verified official domain registry and requires separate Threat Intel / Sandbox inspection."
                    if needs_intel
                    else "Domain matches a known official entry; verify context independently."
                ),
            }
        )
    return links


def _build_recommended_actions(verdict: str, has_urls: bool) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []
    if verdict == "dangerous":
        actions.extend(
            [
                {
                    "ar": "تجنب التفاعل مع الرسالة تماماً ولا تفتح الروابط ولا ترسل أي رمز تحقق أو بيانات بطاقة.",
                    "en": "Do not reply, click embedded links, or share any OTP, password, or card details.",
                },
                {
                    "ar": "تواصل مع الجهة المذكورة عبر رقمها أو تطبيقها الرسمي فقط للتحقق المستقل.",
                    "en": "Verify directly through the institution's official website or known customer service line.",
                },
            ]
        )
    elif verdict == "suspicious":
        actions.extend(
            [
                {
                    "ar": "لا تقم بأي إجراء عاجل؛ افحص أي رابط مرفق في تبويب «تشريح رابط» أو «Sandbox الآمن» أولاً.",
                    "en": "Do not rush; inspect any attached URL in URL X-Ray or Safe Sandbox first.",
                },
                {
                    "ar": "تحقق من هوية المرسل عبر قناة اتصال أخرى معروفة مسبقاً.",
                    "en": "Confirm sender identity out-of-band via a known trusted channel.",
                },
            ]
        )
    else:
        actions.append(
            {
                "ar": "لم تُرصد مؤشرات احتيال قوية في النص، لكن غياب المؤشرات لا يضمن سلامة الروابط غير المفحوصة خارجياً.",
                "en": "No strong phishing cues detected in text, though embedded unfamiliar links still merit caution.",
            }
        )

    if has_urls:
        actions.append(
            {
                "ar": "يوجد رابط مرفق — استخدم زر «اختبار الرابط في Sandbox الآمن» أو «فحص حي» قبل الوثوق به.",
                "en": "Embedded URL found — run live Threat Intel probe or Safe Sandbox before opening.",
            }
        )
    return actions


def _build_message_limitations(urls: list[str]) -> list[dict[str, Any]]:
    limitations = [
        make_limitation(
            "message_text_scope",
            "تحليل الرسالة يقيّم الأنماط اللغوية وبنية الروابط ساكنًا؛ المرفقات أو الروابط تحتاج فحص Threat Intelligence منفصل للتحقق من سمعتها الحية.",
            "Message analysis evaluates linguistic cues and URL structure statically; URLs require separate Threat Intel lookup for live reputation.",
        )
    ]
    if urls:
        limitations.append(
            make_limitation(
                "urls_need_live_intel",
                f"تحتوي الرسالة على {len(urls)} رابط/روابط تحتاج فحصاً منفصلاً عبر Threat Intelligence.",
                f"Message contains {len(urls)} link(s) requiring separate Threat Intelligence verification.",
            )
        )
    return limitations


_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def group_suspicious_segments(
    segments: list[SuspiciousSegment],
) -> list[GroupedSuspiciousSegment]:
    """Group suspicious segments by unique sentence and resolve highest severity and bilingual labels."""
    grouped: dict[str, GroupedSuspiciousSegment] = {}
    for seg in segments:
        text_key = seg["text"]
        threat_type = seg["threat_type"]
        label_map = THREAT_TYPE_LABELS.get(threat_type)
        label_ar = label_map["ar"] if label_map else threat_type
        label_en = label_map["en"] if label_map else threat_type
        reason_ar = seg["reason_ar"]
        reason_en = seg["reason_en"]

        existing = grouped.get(text_key)
        if existing is None:
            grouped[text_key] = {
                "text": text_key,
                "severity": seg["severity"],
                "labels_ar": [label_ar],
                "labels_en": [label_en],
                "reasons_ar": [reason_ar],
                "reasons_en": [reason_en],
            }
        else:
            if _SEVERITY_RANK.get(seg["severity"], 0) > _SEVERITY_RANK.get(
                existing["severity"], 0
            ):
                existing["severity"] = seg["severity"]
            if label_ar not in existing["labels_ar"]:
                existing["labels_ar"].append(label_ar)
            if label_en not in existing["labels_en"]:
                existing["labels_en"].append(label_en)
            if reason_ar not in existing["reasons_ar"]:
                existing["reasons_ar"].append(reason_ar)
            if reason_en not in existing["reasons_en"]:
                existing["reasons_en"].append(reason_en)

    return list(grouped.values())


def analyze_message(
    text: str,
    url: str | None = None,
    *,
    use_auxiliary_llm: bool = False,
) -> AnalysisResult:
    """Context-aware analysis of SMS/WhatsApp/email text and embedded URLs."""
    scan_ts = utc_now_iso()
    raw_text = (text or "")[:5000]
    urls = extract_urls(raw_text, url)
    norm_text, index_map = normalize_arabic_with_map(raw_text)
    runtime_settings = _load_runtime_thresholds()
    state = _create_scan_state(raw_text, scan_ts)

    url_forensics = [inspect_url_forensics(u) for u in urls]
    has_risky_url, all_official_urls = _score_url_forensics(url_forensics, state)
    signal_flags = _score_text_threats(
        raw_text,
        norm_text,
        index_map,
        urls,
        has_risky_url,
        all_official_urls,
        state,
    )
    _score_formatting_and_obfuscation(raw_text, state)

    final_score = _apply_score_dampeners(state["reasons"], urls, has_risky_url, signal_flags)
    verdict, risk_level, best_category = _resolve_verdict_and_category(
        final_score, runtime_settings, state["category_points"]
    )
    links_requiring_verification = _build_links_requiring_verification(url_forensics)
    recommended_actions = _build_recommended_actions(verdict, bool(urls))

    effective_aux_llm = bool(use_auxiliary_llm or runtime_settings.get("enable_auxiliary_llm", False))
    auxiliary_llm = (
        _run_optional_gemini_auxiliary(raw_text)
        if effective_aux_llm
        else {
            "used": False,
            "status": "skipped",
            "summary_ar": "اعتمد الفحص على المحرك الحتمي السياقي دون استدعاء نموذج لغوي خارجي.",
            "summary_en": "Analyzed purely by the deterministic context engine without external LLM calls.",
        }
    )

    bundle = build_evidence_bundle(
        evidence=state["evidence"],
        risk_level=risk_level,
        limitations=_build_message_limitations(urls),
        has_authoritative_hit=False,
        data_sufficient=len(raw_text.strip()) >= 8,
        scan_timestamp=scan_ts,
    )

    family_warning = {
        "ar": build_family_warning_text(
            lang="ar",
            score=final_score,
            verdict=verdict,
            category=best_category,
            reasons=[reason["title_ar"] for reason in state["reasons"]],
        ),
        "en": build_family_warning_text(
            lang="en",
            score=final_score,
            verdict=verdict,
            category=best_category,
            reasons=[reason["title_en"] for reason in state["reasons"]],
        ),
    }

    highlight_segments = split_text_by_highlights(raw_text, state["highlights"])
    grouped_suspicious_segments = group_suspicious_segments(state["suspicious_segments"])

    return {
        "score": final_score,
        "verdict": verdict,
        "risk_level": risk_level,
        "category": best_category,
        "threat_types": state["threat_types"],
        "reasons": state["reasons"],
        "highlights": state["highlights"],
        "highlight_segments": highlight_segments,
        "suspicious_segments": state["suspicious_segments"],
        "grouped_suspicious_segments": grouped_suspicious_segments,
        "links_requiring_verification": links_requiring_verification,
        "recommended_actions": recommended_actions,
        "family_warning": family_warning,
        "auxiliary_llm": auxiliary_llm,
        "fingerprint": compute_fingerprint(raw_text),
        "urls": urls,
        "url_forensics": url_forensics,
        "evidence_bundle": bundle,
        "scan_timestamp": scan_ts,
    }


def _batch_entry_score(entry: dict[str, Any]) -> int:
    result = entry.get("result")
    if isinstance(result, dict):
        return int(result.get("score", 0))
    return 0


def analyze_batch(messages: list[str]) -> dict[str, object]:
    """Analyze up to 25 messages in a single Python pass and return aggregate statistics."""
    cleaned = [msg.strip()[:5000] for msg in messages if msg and msg.strip()][:25]
    items: list[dict[str, Any]] = []
    dangerous_count = 0
    suspicious_count = 0
    safe_count = 0
    max_score = 0

    for idx, msg in enumerate(cleaned):
        res = analyze_message(msg)
        if res["verdict"] == "dangerous":
            dangerous_count += 1
        elif res["verdict"] == "suspicious":
            suspicious_count += 1
        else:
            safe_count += 1
        if res["score"] > max_score:
            max_score = res["score"]
        items.append(
            {
                "index": idx,
                "preview": msg[:140] + ("..." if len(msg) > 140 else ""),
                "text": msg,
                "result": res,
            }
        )

    items.sort(key=_batch_entry_score, reverse=True)

    return {
        "total": len(items),
        "dangerous_count": dangerous_count,
        "suspicious_count": suspicious_count,
        "safe_count": safe_count,
        "max_score": max_score,
        "items": items,
    }
