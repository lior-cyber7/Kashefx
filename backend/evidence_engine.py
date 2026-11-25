"""Unified Evidence, Source Attribution, Conflict Detection & Confidence Engine."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, TypedDict

EvidenceSeverity = Literal["critical", "high", "medium", "low", "info", "safe"]
EvidenceStrength = Literal["strong", "moderate", "weak", "insufficient"]
RiskLevel = Literal["critical", "high", "medium", "low", "minimal"]


class EvidenceItem(TypedDict):
    id: str
    category: str
    severity: EvidenceSeverity
    title_ar: str
    title_en: str
    detail_ar: str
    detail_en: str
    source: str
    timestamp: str
    observed_value: str


class SourceConflict(TypedDict):
    topic_ar: str
    topic_en: str
    source_a: str
    result_a: str
    source_b: str
    result_b: str


class ConfidenceAssessment(TypedDict):
    calibrated: bool
    evidence_strength: EvidenceStrength
    calibrated_probability: float | None
    detection_ratio: str | None
    explanation_ar: str
    explanation_en: str


class EvidenceBundle(TypedDict):
    scan_timestamp: str
    risk_level: RiskLevel
    evidence: list[EvidenceItem]
    conflicts: list[SourceConflict]
    limitations: list[dict[str, str]]
    confidence: ConfidenceAssessment


_STRENGTH_LABELS_AR: dict[EvidenceStrength, str] = {
    "strong": "قوية — مدعومة بأدلة تقنية متطابقة أو مصدر استخبارات تهديدات.",
    "moderate": "متوسطة — توجد مؤشرات خطر ملموسة تستدعي الحذر والتحقق.",
    "weak": "محدودة — مؤشرات أولية أو غياب التهديد في المصادر المفحوصة لا يثبت الأمان.",
    "insufficient": "غير كافية — تعذّر جمع بيانات كافية للحكم القاطع.",
}

_STRENGTH_LABELS_EN: dict[EvidenceStrength, str] = {
    "strong": "Strong — backed by corroborating technical indicators or threat-intel hits.",
    "moderate": "Moderate — tangible risk indicators observed; verify independently.",
    "weak": "Limited — preliminary signals or absence in checked feeds does not prove safety.",
    "insufficient": "Insufficient — unable to gather enough telemetry for a firm conclusion.",
}


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format with Z suffix."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def make_evidence(
    *,
    evidence_id: str,
    category: str,
    severity: EvidenceSeverity,
    title_ar: str,
    title_en: str,
    detail_ar: str,
    detail_en: str,
    source: str,
    observed_value: str = "",
    timestamp: str | None = None,
) -> EvidenceItem:
    """Create a structured, source-attributed evidence item."""
    return {
        "id": evidence_id,
        "category": category,
        "severity": severity,
        "title_ar": title_ar,
        "title_en": title_en,
        "detail_ar": detail_ar,
        "detail_en": detail_en,
        "source": source,
        "timestamp": timestamp or utc_now_iso(),
        "observed_value": observed_value,
    }


def make_limitation(code: str, ar: str, en: str) -> dict[str, str]:
    """Create a structured transparency note explaining inspection scope limits."""
    return {"code": code, "ar": ar, "en": en}


def compute_evidence_strength(
    evidence: list[EvidenceItem],
    *,
    has_authoritative_hit: bool = False,
    data_sufficient: bool = True,
) -> EvidenceStrength:
    """Assess strength of technical evidence WITHOUT fabricating a statistical probability."""
    if not data_sufficient:
        return "insufficient"

    critical_count = sum(1 for e in evidence if e["severity"] in {"critical", "high"})
    medium_count = sum(1 for e in evidence if e["severity"] == "medium")

    if has_authoritative_hit or critical_count >= 2:
        return "strong"
    if critical_count == 1 or medium_count >= 2:
        return "moderate"
    if medium_count == 1 or any(e["severity"] in {"low", "safe"} for e in evidence):
        return "weak"
    return "insufficient"


def _build_confidence_assessment(
    *,
    strength: EvidenceStrength,
    calibrated: bool,
    calibrated_probability: float | None,
    detection_ratio: str | None,
    has_conflicts: bool,
) -> ConfidenceAssessment:
    if calibrated and calibrated_probability is not None:
        exp_ar = (
            f"نسبة احتمالية معايرة إحصائياً ({round(calibrated_probability * 100, 1)}%) "
            "من نموذج مُختبر خارج العينة؛ وهي مؤشر احتمالي وليست دليلاً قاطعاً."
        )
        exp_en = (
            f"Statistically calibrated model probability ({round(calibrated_probability * 100, 1)}%) "
            "from out-of-sample validation; probabilistic indicator, not definitive proof."
        )
        final_prob: float | None = round(float(calibrated_probability), 4)
    else:
        final_prob = None
        exp_ar = f"قوة الأدلة: {_STRENGTH_LABELS_AR[strength]} (لا تُعرض نسبة مئوية بدون معايرة إحصائية)."
        exp_en = f"Evidence strength: {_STRENGTH_LABELS_EN[strength]} (No uncalibrated probability is fabricated.)"

    if has_conflicts:
        exp_ar += " تنبيه: يوجد تعارض مرصود بين المصادر وتم إبرازه أدناه."
        exp_en += " Note: Source disagreement detected and surfaced explicitly."

    return {
        "calibrated": bool(calibrated and final_prob is not None),
        "evidence_strength": strength,
        "calibrated_probability": final_prob,
        "detection_ratio": detection_ratio,
        "explanation_ar": exp_ar,
        "explanation_en": exp_en,
    }


def build_evidence_bundle(
    *,
    evidence: list[EvidenceItem],
    risk_level: RiskLevel,
    conflicts: list[SourceConflict] | None = None,
    limitations: list[dict[str, str]] | None = None,
    has_authoritative_hit: bool = False,
    data_sufficient: bool = True,
    calibrated: bool = False,
    calibrated_probability: float | None = None,
    detection_ratio: str | None = None,
    scan_timestamp: str | None = None,
) -> EvidenceBundle:
    """Assemble a complete evidence-based verdict metadata bundle."""
    ts = scan_timestamp or utc_now_iso()
    conflict_list = list(conflicts or [])
    limitation_list = list(limitations or [])
    strength = compute_evidence_strength(
        evidence,
        has_authoritative_hit=has_authoritative_hit,
        data_sufficient=data_sufficient,
    )
    confidence = _build_confidence_assessment(
        strength=strength,
        calibrated=calibrated,
        calibrated_probability=calibrated_probability,
        detection_ratio=detection_ratio,
        has_conflicts=bool(conflict_list),
    )

    return {
        "scan_timestamp": ts,
        "risk_level": risk_level,
        "evidence": evidence,
        "conflicts": conflict_list,
        "limitations": limitation_list,
        "confidence": confidence,
    }
