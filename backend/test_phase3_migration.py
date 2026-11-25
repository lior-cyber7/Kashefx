"""Phase 3 Python-dominant migration tests for highlight segmentation, segment grouping, raw telemetry, and runtime architecture."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

import academic_analyzer  # noqa: E402
import analyzer  # noqa: E402
import rules_config  # noqa: E402
import text_utils  # noqa: E402


class Phase3MigrationTests(unittest.TestCase):
    def test_split_text_by_highlights_non_overlapping_and_roundtrip(self) -> None:
        msg = "مبروك! ربحت 5000$، اضغط http://paypa1-secure.xyz/login وأرسل رمز التحقق"
        segments = text_utils.split_text_by_highlights(
            msg,
            [
                "مبروك! ربحت",
                "ربحت",
                "http://paypa1-secure.xyz/login",
                "رمز التحقق",
                "غير موجود",
            ],
        )
        highlighted_parts = [s["text"] for s in segments if s["highlighted"]]
        self.assertEqual(
            highlighted_parts,
            [
                "مبروك! ربحت",
                "http://paypa1-secure.xyz/login",
                "رمز التحقق",
            ],
        )
        self.assertEqual("".join(s["text"] for s in segments), msg)

    def test_split_text_by_highlights_empty_and_no_matches(self) -> None:
        self.assertEqual(text_utils.split_text_by_highlights("", ["abc"]), [])
        self.assertEqual(
            text_utils.split_text_by_highlights("رسالة عادية", ["missing"]),
            [{"text": "رسالة عادية", "highlighted": False}],
        )

    def test_group_suspicious_segments_merges_severity_and_bilingual_labels(self) -> None:
        segments: list[analyzer.SuspiciousSegment] = [
            {
                "text": "أرسل رمز التحقق الآن عبر الرابط",
                "threat_type": "urgency_pressure",
                "severity": "medium",
                "reason_ar": "ضغط وقتي",
                "reason_en": "Urgency cue",
            },
            {
                "text": "أرسل رمز التحقق الآن عبر الرابط",
                "threat_type": "otp_credential_theft",
                "severity": "critical",
                "reason_ar": "طلب رمز التحقق",
                "reason_en": "OTP request",
            },
        ]
        grouped = analyzer.group_suspicious_segments(segments)
        self.assertEqual(len(grouped), 1)
        entry = grouped[0]
        self.assertEqual(entry["severity"], "critical")
        self.assertEqual(
            entry["labels_en"],
            [
                rules_config.THREAT_TYPE_LABELS["urgency_pressure"]["en"],
                rules_config.THREAT_TYPE_LABELS["otp_credential_theft"]["en"],
            ],
        )
        self.assertEqual(
            entry["labels_ar"],
            [
                rules_config.THREAT_TYPE_LABELS["urgency_pressure"]["ar"],
                rules_config.THREAT_TYPE_LABELS["otp_credential_theft"]["ar"],
            ],
        )
        self.assertEqual(entry["reasons_en"], ["Urgency cue", "OTP request"])

    def test_analyze_message_returns_python_computed_segments_and_preserves_legacy_fields(self) -> None:
        msg = "مبروك ربحت 5000$! اضغط http://paypa1-secure.xyz/login وأرسل رمز التحقق OTP فوراً"
        result = analyzer.analyze_message(msg)
        self.assertEqual(result["verdict"], "dangerous")
        self.assertIn("highlights", result)
        self.assertIn("highlight_segments", result)
        self.assertIn("suspicious_segments", result)
        self.assertIn("grouped_suspicious_segments", result)
        self.assertEqual("".join(s["text"] for s in result["highlight_segments"]), msg)
        self.assertTrue(any(s["highlighted"] for s in result["highlight_segments"]))
        self.assertGreaterEqual(len(result["grouped_suspicious_segments"]), 1)

    def test_academic_analyzer_computes_stats_from_raw_intervals_only(self) -> None:
        raw_intervals = [110, 145, 210, 95, 180, 240, 130, 195, 160, 225, 140, 200, 115, 250, 175, 155]
        sample_text = (
            "During our campus security study, students reacted differently to shortened SMS links than faculty staff. "
            "Why did urgent messages succeed in laboratory testing?"
        )
        res = academic_analyzer.analyze_academic_text(
            sample_text,
            behavior={
                "keystrokes": 45,
                "pasted_chars": 0,
                "total_chars": len(sample_text),
                "intervals_ms": raw_intervals,
            },
        )
        telemetry = res["behavior"]
        self.assertEqual(telemetry["status"], "human_verified")
        self.assertGreater(telemetry["avg_interval_ms"], 100.0)
        self.assertGreater(telemetry["interval_std_ms"], 20.0)

    def test_node_fallback_removed_and_start_targets_python(self) -> None:
        fallback_path = BACKEND_DIR / "node_cloudrun_fallback.mjs"
        self.assertFalse(fallback_path.exists())
        pkg = json.loads((ROOT_DIR / "package.json").read_text(encoding="utf-8"))
        self.assertIn("backend/main.py", pkg["scripts"]["start"])
        self.assertNotIn("node_cloudrun_fallback", pkg["scripts"]["start"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
