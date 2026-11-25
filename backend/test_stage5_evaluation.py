"""Stage 5 tests verifying held-out dataset separation and evaluation metrics."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ai_training_corpus import TRAIN_AR, TRAIN_EN  # noqa: E402
from eval_datasets import AI_EVAL_SET  # noqa: E402
from evaluate_models import run_all_evaluations  # noqa: E402


class Stage5EvaluationTests(unittest.TestCase):
    def test_eval_corpus_strictly_disjoint_from_training(self) -> None:
        train_texts = {item[0].strip() for item in TRAIN_AR + TRAIN_EN}
        eval_texts = {item["text"].strip() for item in AI_EVAL_SET}
        self.assertEqual(len(train_texts.intersection(eval_texts)), 0)

    def test_evaluation_metrics_meet_quality_gates(self) -> None:
        report = run_all_evaluations()
        url_m = report["url_analyzer"]
        msg_m = report["message_analyzer"]
        ai_m = report["ai_detector"]

        self.assertGreaterEqual(url_m["f1_score"], 0.85)
        self.assertLessEqual(url_m["false_positive_rate"], 0.15)
        self.assertGreaterEqual(msg_m["f1_score"], 0.85)
        self.assertLessEqual(msg_m["false_positive_rate"], 0.15)
        self.assertGreaterEqual(ai_m["accuracy"], 0.75)
        self.assertLessEqual(ai_m["brier_score"], 0.22)
        self.assertGreaterEqual(ai_m["hybrid_cautiously_flagged"], 1)


if __name__ == "__main__":
    unittest.main()
