"""Stage 1 tests for Evidence & Confidence Engine."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evidence_engine import (  # noqa: E402
    build_evidence_bundle,
    make_evidence,
    make_limitation,
)


def test_uncalibrated_evidence_never_fabricates_probability():
    ev = [
        make_evidence(
            evidence_id="homograph",
            category="technical",
            severity="high",
            title_ar="أحرف متشابهة",
            title_en="Mixed-script homograph",
            detail_ar="تفاصيل",
            detail_en="Details",
            source="url_static_forensics",
            observed_value="pаypal.com",
        ),
        make_evidence(
            evidence_id="urlhaus_hit",
            category="threat_intel",
            severity="critical",
            title_ar="تطابق URLhaus",
            title_en="URLhaus listed",
            detail_ar="تفاصيل",
            detail_en="Details",
            source="urlhaus",
        ),
    ]
    bundle = build_evidence_bundle(
        evidence=ev,
        risk_level="critical",
        has_authoritative_hit=True,
        detection_ratio="1/3",
        limitations=[make_limitation("vt_missing", "مفتاح VT غير مضبوط", "VirusTotal API key missing")],
    )
    assert bundle["confidence"]["calibrated"] is False
    assert bundle["confidence"]["calibrated_probability"] is None
    assert bundle["confidence"]["evidence_strength"] == "strong"
    assert bundle["confidence"]["detection_ratio"] == "1/3"
    assert bundle["scan_timestamp"].endswith("Z")
    assert len(bundle["limitations"]) == 1


def test_calibrated_model_confidence_and_conflict_surfacing():
    bundle = build_evidence_bundle(
        evidence=[],
        risk_level="medium",
        calibrated=True,
        calibrated_probability=0.6142,
        conflicts=[
            {
                "topic_ar": "تعارض المصادر",
                "topic_en": "Source conflict",
                "source_a": "OpenPhish",
                "result_a": "clean",
                "source_b": "url_static_forensics",
                "result_b": "suspicious",
            }
        ],
    )
    assert bundle["confidence"]["calibrated"] is True
    assert bundle["confidence"]["calibrated_probability"] == 0.6142
    assert len(bundle["conflicts"]) == 1
    assert "تعارض" in bundle["confidence"]["explanation_ar"]


if __name__ == "__main__":
    test_uncalibrated_evidence_never_fabricates_probability()
    test_calibrated_model_confidence_and_conflict_surfacing()
    print("Stage 1 tests passed (2/2).")
