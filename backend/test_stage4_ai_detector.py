"""Stage 4 tests for Scientifically Calibrated Arabic & English AI-vs-Human Detector."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ai_detector import analyze_ai_vs_human  # noqa: E402


def test_short_text_returns_inconclusive_no_fake_percentage():
    res = analyze_ai_vs_human("هذه فقرة قصيرة جداً لا تكفي لتحديد أسلوب الكاتب بأي طريقة علمية.")
    assert res["classification"] == "inconclusive"
    assert "Inconclusive" in res["headline_ar"]
    assert res["calibrated_ai_probability"] is None
    assert res["evidence_bundle"]["confidence"]["calibrated"] is False
    assert res["is_probabilistic_only"] is True


def test_structured_human_text_not_penalized_just_for_structure():
    formal_human_en = (
        "When designing distributed storage engines, engineers balance write amplification against read latency. "
        "Earlier log-structured merge trees minimized random disk seeks, yet background compaction often triggered "
        "unexpected tail spikes during peak campus registration hours! Why did we keep RocksDB anyway? "
        "Because bounded memory overhead mattered more than occasional latency jitter on commodity SSDs."
    )
    res_en = analyze_ai_vs_human(formal_human_en)
    assert res_en["language"] == "en"
    assert res_en["classification"] in {"human_leaning", "inconclusive"}, f"Unexpected: {res_en}"
    assert res_en["classification"] != "ai_leaning"

    formal_human_ar = (
        "ناقشتُ مع مشرفي الأسبوع الماضي خطة تطوير نظام تحليل السجلات الجامعية؛ فقد لاحظنا أثناء الاختبار الفعلي "
        "أن الجداول الكبيرة تبطّئ استرجاع التقارير عند نهاية الفصل الدراسي. لماذا حدث ذلك رغم استخدام الفهارس؟ "
        "تبيّن لنا أن الاستعلامات المركّبة كانت تعيد مسح السجلات القديمة، فعدّلنا البنية وحققنا تحسناً فورياً."
    )
    res_ar = analyze_ai_vs_human(formal_human_ar)
    assert res_ar["language"] == "ar"
    assert res_ar["classification"] in {"human_leaning", "inconclusive"}, f"Unexpected: {res_ar}"
    assert res_ar["classification"] != "ai_leaning"


def test_ai_leaning_calibrated_and_hybrid_conflict():
    ai_en = (
        "Moreover, artificial intelligence plays a crucial role in modern educational systems across the globe. "
        "Furthermore, it is worth noting that automated platforms enhance institutional efficiency and data visibility. "
        "On the other hand, stakeholders must delve into ethical governance frameworks in today's rapidly evolving landscape. "
        "In conclusion, strategic innovation remains a testament to sustainable academic progress."
    )
    res_ai = analyze_ai_vs_human(ai_en)
    assert res_ai["classification"] == "ai_leaning"
    assert res_ai["calibrated_ai_probability"] is not None
    assert 0.65 < res_ai["calibrated_ai_probability"] < 0.99
    assert res_ai["evidence_bundle"]["confidence"]["calibrated"] is True

    # Hybrid / Human-edited AI text: mixes personal experience & punctuation with AI connectors
    hybrid_en = (
        "Moreover, artificial intelligence plays a crucial role in today's rapidly evolving landscape. "
        "Wait—honestly, I tested this yesterday in our lab and my Python script crashed twice! "
        "Why did that happen? Furthermore, it is worth noting that messy UTF-8 logs broke our parser, "
        "yet in conclusion we fixed the bug before midnight."
    )
    res_hyb = analyze_ai_vs_human(hybrid_en)
    # Either flagged inconclusive or surfaces conflict explicitly
    assert res_hyb["classification"] == "inconclusive" or len(res_hyb["evidence_bundle"]["conflicts"]) >= 1


if __name__ == "__main__":
    test_short_text_returns_inconclusive_no_fake_percentage()
    test_structured_human_text_not_penalized_just_for_structure()
    test_ai_leaning_calibrated_and_hybrid_conflict()
    print("Stage 4 tests passed (3/3).")
