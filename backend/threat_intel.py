"""Real Threat Intelligence, RDAP Domain Age, and DNS-over-HTTPS Lookup Clients.

Strictly avoids fabricated or mock threat responses. Every external check uses explicit
timeouts, returns its exact status (`hit`, `clean`, `not_configured`, `unavailable`, `error`),
and records UTC timestamps and raw summaries.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Literal, TypedDict

from evidence_engine import utc_now_iso

ThreatSourceStatus = Literal["hit", "clean", "not_configured", "unavailable", "error"]


class ThreatSourceResult(TypedDict):
    source_id: str
    source_name: str
    status: ThreatSourceStatus
    verdict_detail_ar: str
    verdict_detail_en: str
    checked_at: str
    requires_api_key: bool
    env_var: str | None
    detection_ratio: str | None
    categories: list[str]


_OPENPHISH_LOCK = threading.Lock()
_OPENPHISH_CACHE: dict[str, Any] = {"fetched_at": 0.0, "urls": set(), "hosts": set(), "error": None}
_OPENPHISH_TTL_SECONDS = 900.0  # 15-minute feed cache

_INTEL_SOURCES_META: list[tuple[str, str, bool, str | None]] = [
    ("google_safe_browsing", "Google Safe Browsing v4", True, "GOOGLE_SAFE_BROWSING_API_KEY"),
    ("virustotal", "VirusTotal API v3", True, "VIRUSTOTAL_API_KEY"),
    ("openphish", "OpenPhish Feed", False, None),
]


def _make_intel_result(
    *,
    source_id: str,
    source_name: str,
    status: ThreatSourceStatus,
    detail_ar: str,
    detail_en: str,
    checked_at: str,
    requires_api_key: bool,
    env_var: str | None,
    detection_ratio: str | None = None,
    categories: list[str] | None = None,
) -> ThreatSourceResult:
    return {
        "source_id": source_id,
        "source_name": source_name,
        "status": status,
        "verdict_detail_ar": detail_ar,
        "verdict_detail_en": detail_en,
        "checked_at": checked_at,
        "requires_api_key": requires_api_key,
        "env_var": env_var,
        "detection_ratio": detection_ratio,
        "categories": list(categories or []),
    }


def _env_key(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val or val.startswith("MY_"):
        return ""
    return val


def _http_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 4.0,
) -> tuple[int, Any]:
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "User-Agent": "Kashf-ThreatIntel/2.0",
            **(headers or {}),
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        status = int(getattr(resp, "status", 200))
        raw = resp.read(262_144).decode("utf-8", errors="replace")
        return status, json.loads(raw) if raw.strip() else {}


def _is_public_domain_for_intel(host: str) -> bool:
    """Reject localhost, .local/.internal, and private/reserved IPs before calling external APIs."""
    clean = (host or "").strip().lower().rstrip(".")
    if (
        not clean
        or clean in {"localhost", "127.0.0.1", "::1", "0.0.0.0", "metadata.google.internal"}
        or clean.endswith((".local", ".internal", ".localhost"))
    ):
        return False
    try:
        ip_obj = ipaddress.ip_address(clean)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except ValueError:
        return "." in clean


def _registrable_domain(host: str) -> str:
    """Extract approximate registrable domain for RDAP lookup."""
    parts = [p for p in host.lower().strip(".").split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    second_level = {"co", "com", "org", "net", "gov", "edu", "ac"}
    if len(parts[-1]) == 2 and parts[-2] in second_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def check_google_safe_browsing(url: str, timeout: float = 4.0) -> ThreatSourceResult:
    """Query Google Safe Browsing v4 threatMatches endpoint when API key is configured."""
    checked_at = utc_now_iso()
    sid, sname, env_var = "google_safe_browsing", "Google Safe Browsing v4", "GOOGLE_SAFE_BROWSING_API_KEY"
    api_key = _env_key(env_var)
    if not api_key:
        return _make_intel_result(
            source_id=sid,
            source_name=sname,
            status="not_configured",
            detail_ar="غير مفعّل — يتطلب إعداد GOOGLE_SAFE_BROWSING_API_KEY في البيئة.",
            detail_en="Not configured — set GOOGLE_SAFE_BROWSING_API_KEY on server.",
            checked_at=checked_at,
            requires_api_key=True,
            env_var=env_var,
        )

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={urllib.parse.quote(api_key)}"
    payload = {
        "client": {"clientId": "kashf-security", "clientVersion": "2.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        _, data = _http_json(
            endpoint,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=json.dumps(payload).encode("utf-8"),
            timeout=timeout,
        )
        matches = data.get("matches") if isinstance(data, dict) else None
        if matches:
            threats = sorted({str(m.get("threatType", "THREAT")) for m in matches if isinstance(m, dict)})
            return _make_intel_result(
                source_id=sid,
                source_name=sname,
                status="hit",
                detail_ar=f"تم رصد تطابق في قوائم Google Safe Browsing ({', '.join(threats)}).",
                detail_en=f"Flagged by Google Safe Browsing ({', '.join(threats)}).",
                checked_at=checked_at,
                requires_api_key=True,
                env_var=env_var,
                categories=threats,
            )
        return _make_intel_result(
            source_id=sid,
            source_name=sname,
            status="clean",
            detail_ar="لم يُرصد في قوائم Google Safe Browsing وقت الفحص (لا يثبت الأمان المطلق).",
            detail_en="No match in Google Safe Browsing at check time (does not prove safe).",
            checked_at=checked_at,
            requires_api_key=True,
            env_var=env_var,
        )
    except urllib.error.HTTPError as err:
        if err.code == 429:
            return _make_intel_result(
                source_id=sid,
                source_name=sname,
                status="unavailable",
                detail_ar="تجاوز حد الاستعلامات لـ Google Safe Browsing (HTTP 429) — حاول لاحقاً.",
                detail_en="Google Safe Browsing rate limit reached (HTTP 429).",
                checked_at=checked_at,
                requires_api_key=True,
                env_var=env_var,
            )
        return _make_intel_result(
            source_id=sid,
            source_name=sname,
            status="error",
            detail_ar=f"خطأ استجابة API (HTTP {err.code}).",
            detail_en=f"API returned HTTP {err.code}.",
            checked_at=checked_at,
            requires_api_key=True,
            env_var=env_var,
        )
    except Exception:
        return _make_intel_result(
            source_id=sid,
            source_name=sname,
            status="unavailable",
            detail_ar="تعذر الاتصال بـ Google Safe Browsing (انتهت المهلة أو الشبكة مقيدة).",
            detail_en="Could not reach Google Safe Browsing (timeout or restricted network).",
            checked_at=checked_at,
            requires_api_key=True,
            env_var=env_var,
        )


def check_virustotal(url: str, timeout: float = 4.0) -> ThreatSourceResult:
    """Query VirusTotal API v3 URL reputation report using base64url URL identifier."""
    checked_at = utc_now_iso()
    sid, sname, env_var = "virustotal", "VirusTotal API v3", "VIRUSTOTAL_API_KEY"
    api_key = _env_key(env_var)
    if not api_key:
        return _make_intel_result(
            source_id=sid,
            source_name=sname,
            status="not_configured",
            detail_ar="غير مفعّل — يتطلب إعداد VIRUSTOTAL_API_KEY في البيئة.",
            detail_en="Not configured — set VIRUSTOTAL_API_KEY on server.",
            checked_at=checked_at,
            requires_api_key=True,
            env_var=env_var,
        )

    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    try:
        _, data = _http_json(
            endpoint,
            method="GET",
            headers={"x-apikey": api_key, "Accept": "application/json"},
            timeout=timeout,
        )
        attrs = ((data or {}).get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected
        ratio = f"{malicious}/{total}" if total > 0 else None

        if malicious > 0 or suspicious > 0:
            return _make_intel_result(
                source_id=sid,
                source_name=sname,
                status="hit",
                detail_ar=f"رصد {malicious} محرك فحص أنه ضار و{suspicious} مشبوه من أصل {total} محرك.",
                detail_en=f"{malicious} engine(s) flagged malicious and {suspicious} suspicious out of {total}.",
                checked_at=checked_at,
                requires_api_key=True,
                env_var=env_var,
                detection_ratio=ratio,
                categories=[k for k in ("malicious", "suspicious") if stats.get(k, 0) > 0],
            )
        return _make_intel_result(
            source_id=sid,
            source_name=sname,
            status="clean",
            detail_ar=f"0/{total} محركات رصدت تهديداً في آخر تحليل مسجل (لا يثبت الأمان).",
            detail_en=f"0/{total} engines flagged threats in recorded scan (does not guarantee safe).",
            checked_at=checked_at,
            requires_api_key=True,
            env_var=env_var,
            detection_ratio=ratio,
        )
    except urllib.error.HTTPError as err:
        if err.code == 404:
            return _make_intel_result(
                source_id=sid,
                source_name=sname,
                status="unavailable",
                detail_ar="الرابط غير مفهرس مسبقاً في قاعدة VirusTotal.",
                detail_en="URL has no prior record in VirusTotal database.",
                checked_at=checked_at,
                requires_api_key=True,
                env_var=env_var,
            )
        if err.code == 429:
            return _make_intel_result(
                source_id=sid,
                source_name=sname,
                status="unavailable",
                detail_ar="تجاوز حد الطلبات المجانية لـ VirusTotal (HTTP 429) — انتظر دقيقة.",
                detail_en="VirusTotal rate limit reached (HTTP 429).",
                checked_at=checked_at,
                requires_api_key=True,
                env_var=env_var,
            )
        return _make_intel_result(
            source_id=sid,
            source_name=sname,
            status="error",
            detail_ar=f"خطأ استجابة VirusTotal (HTTP {err.code}).",
            detail_en=f"VirusTotal returned HTTP {err.code}.",
            checked_at=checked_at,
            requires_api_key=True,
            env_var=env_var,
        )
    except Exception:
        return _make_intel_result(
            source_id=sid,
            source_name=sname,
            status="unavailable",
            detail_ar="تعذر الاتصال بخدمة VirusTotal حالياً.",
            detail_en="VirusTotal API unreachable or timed out.",
            checked_at=checked_at,
            requires_api_key=True,
            env_var=env_var,
        )


def check_urlhaus(url: str, timeout: float = 4.0) -> ThreatSourceResult:
    """Query URLhaus (abuse.ch) malware URL database."""
    checked_at = utc_now_iso()
    sid, sname, env_var = "urlhaus", "URLhaus (abuse.ch)", "URLHAUS_AUTH_KEY"
    auth_key = _env_key(env_var)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if auth_key:
        headers["Auth-Key"] = auth_key

    body = urllib.parse.urlencode({"url": url}).encode("utf-8")
    try:
        _, data = _http_json(
            "https://urlhaus-api.abuse.ch/v1/url/",
            method="POST",
            headers=headers,
            body=body,
            timeout=timeout,
        )
        qstatus = str((data or {}).get("query_status", "")).lower()
        if qstatus == "ok":
            threat = str(data.get("threat") or "malware_download")
            tags = [str(t) for t in (data.get("tags") or []) if t][:5]
            return _make_intel_result(
                source_id=sid,
                source_name=sname,
                status="hit",
                detail_ar=f"مدرج في قاعدة URLhaus للروابط الخبيثة ({threat}).",
                detail_en=f"Listed in URLhaus malware database ({threat}).",
                checked_at=checked_at,
                requires_api_key=False,
                env_var=env_var,
                categories=tags or [threat],
            )
        if qstatus == "no_results":
            return _make_intel_result(
                source_id=sid,
                source_name=sname,
                status="clean",
                detail_ar="غير مدرج في قاعدة URLhaus وقت الفحص.",
                detail_en="Not listed in URLhaus database at check time.",
                checked_at=checked_at,
                requires_api_key=False,
                env_var=env_var,
            )
        return _make_intel_result(
            source_id=sid,
            source_name=sname,
            status="unavailable",
            detail_ar=f"استجابة غير حاسمة من URLhaus ({qstatus or 'unknown'}).",
            detail_en=f"URLhaus returned status: {qstatus or 'unknown'}.",
            checked_at=checked_at,
            requires_api_key=False,
            env_var=env_var,
        )
    except urllib.error.HTTPError as err:
        if err.code in {401, 403} and not auth_key:
            return _make_intel_result(
                source_id=sid,
                source_name=sname,
                status="not_configured",
                detail_ar="طلب URLhaus مفتاح Auth-Key (أضف URLHAUS_AUTH_KEY).",
                detail_en="URLhaus requires an Auth-Key header (set URLHAUS_AUTH_KEY).",
                checked_at=checked_at,
                requires_api_key=True,
                env_var=env_var,
            )
        if err.code == 429:
            return _make_intel_result(
                source_id=sid,
                source_name=sname,
                status="unavailable",
                detail_ar="تجاوز حد الاستعلامات المؤقت لـ URLhaus (HTTP 429).",
                detail_en="URLhaus rate limit reached (HTTP 429).",
                checked_at=checked_at,
                requires_api_key=False,
                env_var=env_var,
            )
        return _make_intel_result(
            source_id=sid,
            source_name=sname,
            status="error",
            detail_ar=f"خطأ HTTP {err.code} من URLhaus.",
            detail_en=f"URLhaus HTTP error {err.code}.",
            checked_at=checked_at,
            requires_api_key=False,
            env_var=env_var,
        )
    except Exception:
        return _make_intel_result(
            source_id=sid,
            source_name=sname,
            status="unavailable",
            detail_ar="تعذر الاتصال بخدمة URLhaus (انتهت المهلة أو الشبكة مقيدة).",
            detail_en="URLhaus unreachable or timed out.",
            checked_at=checked_at,
            requires_api_key=False,
            env_var=env_var,
        )


def _refresh_openphish_cache(timeout: float) -> tuple[set[str], set[str], str | None]:
    now = time.monotonic()
    with _OPENPHISH_LOCK:
        cache_age = now - float(_OPENPHISH_CACHE.get("fetched_at", 0.0))
        if cache_age > _OPENPHISH_TTL_SECONDS or not _OPENPHISH_CACHE.get("urls"):
            try:
                req = urllib.request.Request(
                    "https://openphish.com/feed.txt",
                    headers={"User-Agent": "Kashf-ThreatIntel/2.0"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    raw = resp.read(1_048_576).decode("utf-8", errors="replace")
                parsed_urls = {line.strip().rstrip("/") for line in raw.splitlines() if line.strip()}
                parsed_hosts = {
                    (urllib.parse.urlparse(u).hostname or "").lower()
                    for u in parsed_urls
                }
                parsed_hosts.discard("")
                _OPENPHISH_CACHE["fetched_at"] = now
                _OPENPHISH_CACHE["urls"] = parsed_urls
                _OPENPHISH_CACHE["hosts"] = parsed_hosts
                _OPENPHISH_CACHE["error"] = None
            except Exception as exc:
                _OPENPHISH_CACHE["error"] = type(exc).__name__

        return (
            set(_OPENPHISH_CACHE.get("urls", set())),
            set(_OPENPHISH_CACHE.get("hosts", set())),
            _OPENPHISH_CACHE.get("error"),
        )


def check_openphish(url: str, timeout: float = 4.0) -> ThreatSourceResult:
    """Check URL and hostname against the 15-minute cached OpenPhish public feed."""
    checked_at = utc_now_iso()
    sid, sname = "openphish", "OpenPhish Feed"
    urls_set, hosts_set, err_msg = _refresh_openphish_cache(timeout)

    if not urls_set and err_msg:
        return _make_intel_result(
            source_id=sid,
            source_name=sname,
            status="unavailable",
            detail_ar="تعذر تحديث قائمة OpenPhish العامة حالياً.",
            detail_en="Could not fetch OpenPhish public feed.",
            checked_at=checked_at,
            requires_api_key=False,
            env_var=None,
        )

    norm = url.strip().rstrip("/")
    host = (urllib.parse.urlparse(norm).hostname or "").lower()
    if norm in urls_set:
        return _make_intel_result(
            source_id=sid,
            source_name=sname,
            status="hit",
            detail_ar="تطابق مباشر للرابط في قائمة OpenPhish النشطة للتصيد.",
            detail_en="Exact URL matched in active OpenPhish phishing feed.",
            checked_at=checked_at,
            requires_api_key=False,
            env_var=None,
            categories=["phishing"],
        )
    if host and host in hosts_set:
        return _make_intel_result(
            source_id=sid,
            source_name=sname,
            status="hit",
            detail_ar=f"النطاق ({host}) مدرج في روابط التصيد النشطة لدى OpenPhish.",
            detail_en=f"Host ({host}) has active phishing URLs in OpenPhish feed.",
            checked_at=checked_at,
            requires_api_key=False,
            env_var=None,
            categories=["phishing_host"],
        )

    return _make_intel_result(
        source_id=sid,
        source_name=sname,
        status="clean",
        detail_ar=f"غير موجود في تغذية OpenPhish الحالية ({len(urls_set)} رابط نشط).",
        detail_en=f"Not found in current OpenPhish feed ({len(urls_set)} active URLs).",
        checked_at=checked_at,
        requires_api_key=False,
        env_var=None,
    )


def check_phishtank(url: str, timeout: float = 4.0) -> ThreatSourceResult:
    """Query PhishTank URL lookup API."""
    checked_at = utc_now_iso()
    sid, sname, env_var = "phishtank", "PhishTank API", "PHISHTANK_APP_KEY"
    app_key = _env_key(env_var)
    form: dict[str, str] = {"url": url, "format": "json"}
    if app_key:
        form["app_key"] = app_key

    try:
        _, data = _http_json(
            "https://checkurl.phishtank.com/checkurl/",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=urllib.parse.urlencode(form).encode("utf-8"),
            timeout=timeout,
        )
        results = (data or {}).get("results") or {}
        if bool(results.get("in_database")) and bool(results.get("valid")):
            return _make_intel_result(
                source_id=sid,
                source_name=sname,
                status="hit",
                detail_ar="مؤكد كرابط تصيد إلكتروني في قاعدة PhishTank.",
                detail_en="Verified phishing URL in PhishTank database.",
                checked_at=checked_at,
                requires_api_key=False,
                env_var=env_var,
                categories=["verified_phish"],
            )
        return _make_intel_result(
            source_id=sid,
            source_name=sname,
            status="clean",
            detail_ar="غير مسجل كتصيد مؤكد في PhishTank وقت الفحص.",
            detail_en="Not recorded as verified phish in PhishTank at check time.",
            checked_at=checked_at,
            requires_api_key=False,
            env_var=env_var,
        )
    except urllib.error.HTTPError as err:
        if not app_key and err.code in {403, 429, 509}:
            return _make_intel_result(
                source_id=sid,
                source_name=sname,
                status="not_configured",
                detail_ar="تجاوز الحد العام لـ PhishTank — يُنصح بإعداد PHISHTANK_APP_KEY.",
                detail_en="PhishTank public rate limit hit — set PHISHTANK_APP_KEY.",
                checked_at=checked_at,
                requires_api_key=True,
                env_var=env_var,
            )
        return _make_intel_result(
            source_id=sid,
            source_name=sname,
            status="unavailable",
            detail_ar=f"تعذر الفحص عبر PhishTank (HTTP {err.code}).",
            detail_en=f"PhishTank check unavailable (HTTP {err.code}).",
            checked_at=checked_at,
            requires_api_key=False,
            env_var=env_var,
        )
    except Exception:
        return _make_intel_result(
            source_id=sid,
            source_name=sname,
            status="unavailable",
            detail_ar="تعذر الاتصال بـ PhishTank (انتهت المهلة أو الشبكة مقيدة).",
            detail_en="PhishTank unreachable or timed out.",
            checked_at=checked_at,
            requires_api_key=False,
            env_var=env_var,
        )


def _extract_rdap_metadata(data: Any) -> tuple[str | None, str | None]:
    events = (data or {}).get("events") or []
    reg_raw: str | None = None
    for ev in events:
        if isinstance(ev, dict) and str(ev.get("eventAction", "")).lower() == "registration":
            reg_raw = str(ev.get("eventDate") or "")
            break

    registrar = None
    for ent in (data or {}).get("entities") or []:
        if isinstance(ent, dict) and "registrar" in (ent.get("roles") or []):
            vcard = ent.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        registrar = str(item[3])
                        break
            if registrar:
                break
    return reg_raw, registrar


def lookup_rdap_domain_age(host: str, timeout: float = 3.5) -> dict[str, Any]:
    """Query official RDAP protocol for domain registration date and age in days."""
    if not _is_public_domain_for_intel(host):
        return {"available": False, "domain": host, "age_days": None, "error": "Non-public or IP host"}

    try:
        ipaddress.ip_address(host)
        return {"available": False, "domain": host, "age_days": None, "error": "Raw IP address"}
    except ValueError:
        pass

    domain = _registrable_domain(host)
    endpoint = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
    try:
        _, data = _http_json(
            endpoint,
            headers={"Accept": "application/rdap+json, application/json"},
            timeout=timeout,
        )
        reg_raw, registrar = _extract_rdap_metadata(data)
        if not reg_raw:
            return {
                "available": False,
                "domain": domain,
                "age_days": None,
                "registrar": registrar,
                "error": "No registration event in RDAP record",
            }

        reg_dt = datetime.fromisoformat(reg_raw.replace("Z", "+00:00"))
        if reg_dt.tzinfo is None:
            reg_dt = reg_dt.replace(tzinfo=timezone.utc)
        age_days = max(0, (datetime.now(timezone.utc) - reg_dt).days)
        return {
            "available": True,
            "domain": domain,
            "registered_at": reg_raw,
            "age_days": age_days,
            "registrar": registrar,
            "source": "RDAP (rdap.org)",
        }
    except Exception as exc:
        return {
            "available": False,
            "domain": domain,
            "age_days": None,
            "error": f"RDAP unavailable: {type(exc).__name__}",
        }


def lookup_dns_records(host: str, timeout: float = 3.0) -> dict[str, Any]:
    """Query A, MX, and TXT records via DNS-over-HTTPS with local socket fallback."""
    if not host or host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        return {"available": False, "a": [], "mx": [], "txt": [], "has_spf": False, "error": "Local/internal host"}

    records: dict[str, Any] = {
        "available": False,
        "a": [],
        "mx": [],
        "txt": [],
        "has_spf": False,
        "source": None,
        "error": None,
    }

    for rtype in ("A", "MX", "TXT"):
        try:
            url = (
                f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(host)}"
                f"&type={rtype}"
            )
            _, data = _http_json(url, headers={"Accept": "application/dns-json"}, timeout=timeout)
            answers = (data or {}).get("Answer") or []
            values = [str(ans.get("data", "")).strip() for ans in answers if isinstance(ans, dict) and ans.get("data")]
            if rtype == "A":
                records["a"] = values[:5]
            elif rtype == "MX":
                records["mx"] = values[:4]
            elif rtype == "TXT":
                records["txt"] = [v[:160] for v in values[:4]]
                records["has_spf"] = any("v=spf1" in v.lower() for v in values)
            records["available"] = True
            records["source"] = "Cloudflare DoH (cloudflare-dns.com)"
        except Exception:
            continue

    if not records["a"]:
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            local_ips = list(dict.fromkeys(str(info[4][0]) for info in infos))[:5]
            if local_ips:
                records["a"] = local_ips
                records["available"] = True
                records["source"] = records["source"] or "System DNS Resolver"
        except Exception as exc:
            if not records["available"]:
                records["error"] = str(exc)

    return records


def query_all_threat_intel(url: str, host: str, timeout: float = 4.0) -> list[ThreatSourceResult]:
    """Query all integrated Threat Intelligence sources honestly and independently."""
    if not _is_public_domain_for_intel(host):
        now = utc_now_iso()
        return [
            _make_intel_result(
                source_id=sid,
                source_name=sname,
                status="unavailable",
                detail_ar="تم تخطي الفحص الخارجي لأن الهدف غير عام أو غير صالح.",
                detail_en="External threat-intel lookup skipped for non-public/invalid host.",
                checked_at=now,
                requires_api_key=req_key,
                env_var=env_var,
            )
            for sid, sname, req_key, env_var in _INTEL_SOURCES_META
        ]

    check_functions = (
        check_google_safe_browsing,
        check_virustotal,
        check_openphish,
    )
    with ThreadPoolExecutor(max_workers=len(check_functions)) as executor:
        futures = [executor.submit(fn, url, timeout=timeout) for fn in check_functions]
        return [fut.result() for fut in futures]
