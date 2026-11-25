"""Stage 3 tests for Context-Aware Message Phishing Detection."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from analyzer import analyze_message  # noqa: E402


def test_benign_messages_with_trigger_words_not_falsely_flagged():
    benign_free = "أهلاً بالطلبة، الدخول مجاني لحضور الندوة العلمية حول الأمن السيبراني يوم الأربعاء في القاعة الكبرى."
    res_free = analyze_message(benign_free)
    assert res_free["verdict"] == "safe", f"False positive on free workshop: {res_free['reasons']}"
    assert res_free["score"] == 0

    benign_urgent = "تنويه عاجل لطلبة المرحلة الرابعة: تم تأجيل امتحان المشروع إلى يوم الأحد القادم."
    res_urgent = analyze_message(benign_urgent)
    assert res_urgent["verdict"] == "safe", f"False positive on urgent exam notice: {res_urgent['reasons']}"

    benign_prize = "نبارك للطالبة زهراء حصولها على جائزة التفوق العلمي في مؤتمر الجامعة التكنولوجية لهذا العام."
    res_prize = analyze_message(benign_prize)
    assert res_prize["verdict"] == "safe", f"False positive on student award: {res_prize['reasons']}"


def test_subtle_social_engineering_without_buzzwords():
    subtle = (
        "مرحباً، معك فريق الدعم التقني في القسم. لاحظنا عدم مزامنة بريدك الجامعي هذا الأسبوع، "
        "يرجى تأكيد بيانات الدخول عبر البوابة البديلة https://uotech-portal-sync.xyz/sync لضمان استمرار خدمتك."
    )
    res = analyze_message(subtle)
    assert res["verdict"] in {"suspicious", "dangerous"}
    assert res["score"] >= 45
    assert len(res["suspicious_segments"]) >= 1
    assert len(res["links_requiring_verification"]) == 1
    assert res["links_requiring_verification"][0]["needs_separate_intel_check"] is True


def test_iraqi_dialect_scam_and_evidence_bundle():
    iraqi_scam = "خوية حسابك زين كاش راح ينسد هسه، دزلي الرمز الوصلك برسالة حتى أفعلك ياه من http://zaincash-help.top"
    res = analyze_message(iraqi_scam)
    assert res["verdict"] == "dangerous"
    assert res["score"] >= 65
    assert "otp_credential_theft" in res["threat_types"]
    assert res["evidence_bundle"]["confidence"]["calibrated"] is False
    assert res["evidence_bundle"]["confidence"]["calibrated_probability"] is None
    assert len(res["evidence_bundle"]["evidence"]) >= 2
    assert len(res["recommended_actions"]) >= 2
    assert res["scan_timestamp"].endswith("Z")


if __name__ == "__main__":
    test_benign_messages_with_trigger_words_not_falsely_flagged()
    test_subtle_social_engineering_without_buzzwords()
    test_iraqi_dialect_scam_and_evidence_bundle()
    print("Stage 3 tests passed (3/3).")
