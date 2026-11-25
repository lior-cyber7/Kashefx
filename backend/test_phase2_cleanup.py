"""Focused Phase 2 cleanup tests for text_utils, rules_config, db context managers, redirects, and analyzer parity."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

import analyzer  # noqa: E402
import db  # noqa: E402
import evaluate_models  # noqa: E402
import rules_config  # noqa: E402
import text_utils  # noqa: E402
import url_inspector  # noqa: E402


class Phase2CleanupTests(unittest.TestCase):
    def test_text_utils_normalization_distance_and_suffix(self) -> None:
        raw = "أَرْ\u200bسِلـ الرّمز"
        norm, idx_map = text_utils.normalize_arabic_with_map(raw)
        self.assertEqual(len(norm), len(idx_map))
        self.assertIn("ارسل", norm)
        self.assertEqual(analyzer.normalize_arabic(raw), "ارسل الرمز")

        self.assertEqual(text_utils.levenshtein_distance("paypal", "paypal"), 0)
        self.assertEqual(text_utils.levenshtein_distance("paypal", "paypa1"), 1)
        self.assertEqual(text_utils.levenshtein_distance("", "abc"), 3)

        self.assertTrue(text_utils.matches_domain_suffix("uotechnology.edu.iq", "edu.iq"))
        self.assertTrue(text_utils.matches_domain_suffix("sub.edu.iq.", "EDU.IQ"))
        self.assertFalse(text_utils.matches_domain_suffix("fake-edu.iq", "edu.iq"))
        self.assertFalse(text_utils.matches_domain_suffix("", "edu.iq"))

    def test_rules_config_centralized_constants(self) -> None:
        self.assertEqual(rules_config.DEFAULT_MESSAGE_THRESHOLDS["suspicious_threshold"], 30)
        self.assertEqual(rules_config.DEFAULT_MESSAGE_THRESHOLDS["dangerous_threshold"], 65)
        self.assertEqual(rules_config.MESSAGE_RULE_POINTS["sensitive_data"], 35)
        self.assertEqual(rules_config.URL_FORENSIC_WEIGHTS["brand_impersonation"], 35)
        self.assertGreater(len(rules_config.SENSITIVE_CREDENTIAL_PHRASES), 15)
        self.assertGreater(len(rules_config.AI_DISCOURSE_AR), 10)
        self.assertGreater(len(rules_config.AI_DISCOURSE_EN), 10)

    def test_db_transaction_rollback_and_clean_handle_release(self) -> None:
        fd, temp_db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            db.init_db(temp_db)
            with self.assertRaises(RuntimeError):
                with db.db_transaction(temp_db) as conn:
                    conn.execute(
                        "INSERT INTO reports (fingerprint, category, score, ts) VALUES (?, ?, ?, ?)",
                        ("fp1234567890abcd", "other", 50, 1000.0),
                    )
                    raise RuntimeError("simulated transaction failure")

            with db.open_db(temp_db) as conn:
                row = conn.execute("SELECT COUNT(*) AS cnt FROM reports").fetchone()
                self.assertEqual(int(row["cnt"]), 0)
        finally:
            for suffix in ("", "-wal", "-shm"):
                candidate = f"{temp_db}{suffix}"
                if os.path.exists(candidate):
                    os.remove(candidate)

    def test_trace_safe_redirects_blocks_unsafe_scheme_hop(self) -> None:
        with patch.object(url_inspector, "_resolve_public_host", return_value=(True, ["93.184.216.34"], None)), patch.object(
            url_inspector,
            "_pinned_http_request",
            return_value=(302, {"Location": "javascript:alert(1)"}, b""),
        ):
            trace = url_inspector.trace_safe_redirects("https://example.com/start", max_hops=3)
            self.assertEqual(len(trace["hops"]), 1)
            self.assertIsNotNone(trace["ssrf_reason"])
            self.assertIn("unsafe scheme", trace["ssrf_reason"])
            self.assertFalse(trace["completed_non_redirect"])

    def test_analyzer_and_evaluation_benchmark_integrity(self) -> None:
        benign = analyzer.analyze_message("تنويه للطلبة: ندوة علمية والدخول مجاني في قاعة المؤتمرات غداً.")
        self.assertEqual(benign["verdict"], "safe")

        scam = analyzer.analyze_message("مبروك ربحت 5000$، اضغط الرابط http://paypa1-secure.xyz/login وادخل رمز التحقق OTP")
        self.assertEqual(scam["verdict"], "dangerous")
        self.assertGreaterEqual(scam["score"], 80)

        report = evaluate_models.run_all_evaluations()
        self.assertEqual(report["url_analyzer"]["accuracy"], 1.0)
        self.assertEqual(report["message_analyzer"]["accuracy"], 1.0)
        self.assertEqual(report["ai_detector"]["accuracy"], 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
