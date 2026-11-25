"""Real out-of-sample evaluation & confusion-matrix runner for Kashf's 3 core engines."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ai_detector import analyze_ai_vs_human  # noqa: E402
from analyzer import analyze_message  # noqa: E402
from eval_datasets import AI_EVAL_SET, MESSAGE_EVAL_SET, URL_EVAL_SET  # noqa: E402
from url_inspector import inspect_url_forensics  # noqa: E402


def compute_binary_metrics(y_true: list[bool], y_pred: list[bool]) -> dict[str, Any]:
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt and yp)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if (not yt) and yp)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if (not yt) and (not yp))
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt and (not yp))
    total = len(y_true)

    accuracy = round((tp + tn) / total, 4) if total else 0.0
    precision = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
    f1 = round((2 * precision * recall) / (precision + recall), 4) if (precision + recall) else 0.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) else 0.0

    return {
        "total": total,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": fpr,
    }


def run_all_evaluations() -> dict[str, Any]:
    # 1. URL Technical Analyzer evaluation (offline static forensics; malicious/suspicious = positive threat)
    url_true: list[bool] = []
    url_pred: list[bool] = []
    url_breakdown: list[dict[str, Any]] = []
    for case in URL_EVAL_SET:
        res = inspect_url_forensics(case["url"])
        pred_threat = res["classification"] in {"malicious", "suspicious"}
        url_true.append(case["is_threat"])
        url_pred.append(pred_threat)
        url_breakdown.append(
            {
                "category": case["category"],
                "expected_threat": case["is_threat"],
                "predicted_classification": res["classification"],
                "correct": pred_threat == case["is_threat"],
            }
        )
    url_metrics = compute_binary_metrics(url_true, url_pred)

    # 2. Message Phishing Engine evaluation (suspicious/dangerous = positive scam)
    msg_true: list[bool] = []
    msg_pred: list[bool] = []
    msg_breakdown: list[dict[str, Any]] = []
    for case in MESSAGE_EVAL_SET:
        res = analyze_message(case["text"])
        pred_scam = res["verdict"] in {"suspicious", "dangerous"}
        msg_true.append(case["is_scam"])
        msg_pred.append(pred_scam)
        msg_breakdown.append(
            {
                "category": case["category"],
                "expected_scam": case["is_scam"],
                "predicted_verdict": res["verdict"],
                "score": res["score"],
                "correct": pred_scam == case["is_scam"],
            }
        )
    msg_metrics = compute_binary_metrics(msg_true, msg_pred)

    # 3. AI-vs-Human Calibration & Evaluation (on pure Human vs AI, plus Hybrid Inconclusive rate)
    pure_true: list[bool] = []
    pure_pred: list[bool] = []
    brier_errors: list[float] = []
    inconclusive_on_pure = 0
    hybrid_total = 0
    hybrid_cautious = 0  # inconclusive OR surfaced conflict

    for case in AI_EVAL_SET:
        res = analyze_ai_vs_human(case["text"])
        if case["expected_origin"] == "hybrid":
            hybrid_total += 1
            if res["classification"] == "inconclusive" or len(res["evidence_bundle"]["conflicts"]) > 0:
                hybrid_cautious += 1
            continue

        is_ai_true = case["expected_origin"] == "ai"
        prob = res["calibrated_ai_probability"]
        if prob is not None:
            brier_errors.append((prob - (1.0 if is_ai_true else 0.0)) ** 2)

        if res["classification"] == "inconclusive":
            inconclusive_on_pure += 1
            # Treat inconclusive conservatively based on 0.5 threshold for strict binary metric
            pred_ai = (prob or 0.5) >= 0.5
        else:
            pred_ai = res["classification"] == "ai_leaning"

        pure_true.append(is_ai_true)
        pure_pred.append(pred_ai)

    ai_metrics = compute_binary_metrics(pure_true, pure_pred)
    ai_metrics["brier_score"] = round(sum(brier_errors) / max(1, len(brier_errors)), 4)
    ai_metrics["inconclusive_on_pure"] = inconclusive_on_pure
    ai_metrics["hybrid_cases_total"] = hybrid_total
    ai_metrics["hybrid_cautiously_flagged"] = hybrid_cautious

    return {
        "note": "Evaluated on strictly held-out datasets disjoint from training corpora.",
        "url_analyzer": {**url_metrics, "cases": url_breakdown},
        "message_analyzer": {**msg_metrics, "cases": msg_breakdown},
        "ai_detector": ai_metrics,
    }


if __name__ == "__main__":
    report = run_all_evaluations()
    print(json.dumps(report, ensure_ascii=False, indent=2))
