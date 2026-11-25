"""Stage 2 tests for Advanced URL Threat Intelligence & Technical Analysis."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import threat_intel  # noqa: E402
import url_inspector  # noqa: E402


def test_homograph_mixed_script_and_punycode_detection():
    # Cyrillic 'а' (\u0430) disguised in paypal.com
    spoof = "https://p\u0430ypal.com/login"
    res = url_inspector.inspect_url_forensics(spoof)
    assert res["is_mixed_script_homograph"] is True
    assert "Cyrillic" in res["scripts_detected"]
    assert "Latin" in res["scripts_detected"]
    assert res["matched_brand"] == "PayPal"
    assert res["is_official_brand"] is False
    assert res["classification"] == "malicious"

    # Arabic IDN alone should NOT trigger mixed-script Latin+Cyrillic attack
    arabic_idn = url_inspector.inspect_url_forensics("https://شبكة.عراق")
    assert arabic_idn["is_mixed_script_homograph"] is False


def test_four_state_url_classification_honesty():
    # Unfamiliar non-official domain analyzed statically (no threat intel) -> 'unknown', NEVER 'safe'
    unseen = url_inspector.inspect_url_forensics("https://brand-new-portal-991.com/about")
    assert unseen["classification"] == "unknown"
    assert unseen["evidence_bundle"]["confidence"]["calibrated"] is False
    assert unseen["evidence_bundle"]["confidence"]["calibrated_probability"] is None

    # Shortener -> 'suspicious'
    short = url_inspector.inspect_url_forensics("https://bit.ly/3demo")
    assert short["classification"] == "suspicious"

    # Official domain -> 'no_known_threat'
    official = url_inspector.inspect_url_forensics("https://www.paypal.com/signin")
    assert official["classification"] == "no_known_threat"
    assert official["is_official_brand"] is True


def test_threat_intel_clients_missing_keys_and_hits():
    # Ensure missing keys honestly return not_configured
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("GOOGLE_SAFE_BROWSING_API_KEY", None)
        os.environ.pop("VIRUSTOTAL_API_KEY", None)
        gsb = threat_intel.check_google_safe_browsing("https://example.com")
        vt = threat_intel.check_virustotal("https://example.com")
        assert gsb["status"] == "not_configured"
        assert gsb["env_var"] == "GOOGLE_SAFE_BROWSING_API_KEY"
        assert vt["status"] == "not_configured"
        assert vt["env_var"] == "VIRUSTOTAL_API_KEY"

    # Mocked Google Safe Browsing hit
    with patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_API_KEY": "test-key"}), patch.object(
        threat_intel,
        "_http_json",
        return_value=(200, {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}),
    ):
        gsb_hit = threat_intel.check_google_safe_browsing("http://evil-phish.xyz")
        assert gsb_hit["status"] == "hit"
        assert "SOCIAL_ENGINEERING" in gsb_hit["categories"]

    # Mocked VirusTotal stats parsing
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "vt-key"}), patch.object(
        threat_intel,
        "_http_json",
        return_value=(
            200,
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 5,
                            "suspicious": 1,
                            "harmless": 60,
                            "undetected": 4,
                        }
                    }
                }
            },
        ),
    ):
        vt_hit = threat_intel.check_virustotal("http://evil-phish.xyz")
        assert vt_hit["status"] == "hit"
        assert vt_hit["detection_ratio"] == "5/70"


def test_live_probe_conflict_and_ssrf_guard():
    # SSRF block check
    blocked = url_inspector.probe_url_live("http://127.0.0.1:3000/secret", include_intel=False)
    assert blocked["dns"]["resolved"] is False
    assert blocked["classification"] == "malicious"

    # Source conflict: Threat intel returns clean while static forensics flags strong brand impersonation
    clean_gsb: threat_intel.ThreatSourceResult = {
        "source_id": "google_safe_browsing",
        "source_name": "Google Safe Browsing v4",
        "status": "clean",
        "verdict_detail_ar": "غير مدرج",
        "verdict_detail_en": "Not listed",
        "checked_at": "2026-11-19T12:00:00Z",
        "requires_api_key": True,
        "env_var": "GOOGLE_SAFE_BROWSING_API_KEY",
        "detection_ratio": None,
        "categories": [],
    }
    with patch.object(url_inspector, "_resolve_public_host", return_value=(True, ["93.184.216.34"], None)), patch.object(
        url_inspector, "lookup_dns_records", return_value={"available": True, "a": ["93.184.216.34"], "mx": [], "txt": [], "has_spf": False}
    ), patch.object(
        url_inspector, "lookup_rdap_domain_age", return_value={"available": True, "domain": "paypa1-secure.xyz", "age_days": 5, "registered_at": "2026-11-14T00:00:00Z"}
    ), patch.object(
        url_inspector, "query_all_threat_intel", return_value=[clean_gsb]
    ), patch.object(
        url_inspector, "_inspect_tls", return_value={"available": True, "valid": True, "issuer": "Let's Encrypt", "days_remaining": 85}
    ):
        with patch.object(url_inspector, "_pinned_http_request", return_value=(200, {}, b"")):
            probe = url_inspector.probe_url_live("https://paypa1-secure.xyz/login", include_intel=True)
            assert probe["classification"] == "malicious"
            assert probe["rdap"]["age_days"] == 5
            assert len(probe["evidence_bundle"]["conflicts"]) >= 1


if __name__ == "__main__":
    test_homograph_mixed_script_and_punycode_detection()
    test_four_state_url_classification_honesty()
    test_threat_intel_clients_missing_keys_and_hits()
    test_live_probe_conflict_and_ssrf_guard()
    print("Stage 2 tests passed (4/4).")
