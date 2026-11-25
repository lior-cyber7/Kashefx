"""Pure-Python Isolated Safe URL Sandbox (Static HTTP/HTML Payload Inspector).

Inspects suspicious URLs inside a strict server-side Python environment without executing
JavaScript, running a full browser/OS VM, storing cookies, writing files to disk, or reaching
internal/private networks (pinned-IP SSRF guard). Inspects live HTTP headers, redirect chains,
and static HTML/script payloads (forms, OTP/card harvesters, hidden iframes, meta-refresh,
JS redirects, obfuscation, Telegram webhooks) and falls back to predictive behavioral patterns
when a domain is offline or unreachable.
"""

from __future__ import annotations

import posixpath
import re
import urllib.parse
from html.parser import HTMLParser
from typing import Any

import url_inspector
from url_inspector import UrlForensics, defang_url, inspect_url_forensics

MAX_SANDBOX_BYTES = 131_072  # 128 KB hard read cap

DANGEROUS_DOWNLOAD_EXTS = {
    ".apk",
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".scr",
    ".iso",
    ".dmg",
    ".pkg",
    ".zip",
    ".rar",
    ".7z",
    ".jar",
}

SENSITIVE_FIELD_HINTS = {
    "pass",
    "pwd",
    "otp",
    "pin",
    "cvv",
    "cvc",
    "card",
    "iban",
    "token",
    "code",
    "ssn",
    "secret",
    "كلمة",
    "السر",
    "رمز",
    "بطاقة",
    "التحقق",
}

_BINARY_CONTENT_TYPES = (
    "application/octet-stream",
    "application/vnd.android.package-archive",
    "application/x-msdownload",
    "application/zip",
)

_SAFETY_GUARANTEES = {
    "js_executed": False,
    "cookies_stored": False,
    "files_written": False,
    "ssrf_protected": True,
}


class _SafeSandboxHTMLParser(HTMLParser):
    """Passive HTML tokenizer that extracts DOM indicators without executing anything."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.skip_depth = 0
        self.in_script = False
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None
        self.external_script_hosts: list[str] = []
        self.scripts_count = 0
        self.script_bodies: list[str] = []
        self.iframes: list[dict[str, str]] = []
        self.meta_refresh_url: str | None = None
        self.sensitive_inputs: list[str] = []
        self.password_inputs = 0

    def _handle_input_tag(self, attr_map: dict[str, str]) -> None:
        itype = (attr_map.get("type") or "text").lower().strip()
        iname = (attr_map.get("name") or attr_map.get("id") or "").strip()
        placeholder = attr_map.get("placeholder", "").strip()
        combined = f"{itype} {iname} {placeholder}".lower()

        if itype == "password":
            self.password_inputs += 1
        if itype == "password" or any(h in combined for h in SENSITIVE_FIELD_HINTS):
            label = iname or placeholder or itype
            if label not in self.sensitive_inputs:
                self.sensitive_inputs.append(label[:40])

        if self._current_form is not None and itype != "hidden":
            self._current_form["inputs"].append(f"{itype}:{iname or placeholder or 'field'}")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}

        if t == "title":
            self.in_title = True
        elif t == "script":
            self.scripts_count += 1
            self.in_script = True
            self.skip_depth += 1
            src = attr_map.get("src", "").strip()
            if src:
                parsed_src = urllib.parse.urlparse(src)
                if parsed_src.hostname:
                    self.external_script_hosts.append(parsed_src.hostname.lower())
        elif t in {"style", "noscript", "svg"}:
            self.skip_depth += 1
        elif t == "meta":
            http_equiv = attr_map.get("http-equiv", "").strip().lower()
            content = attr_map.get("content", "")
            if http_equiv == "refresh" and content:
                match = re.search(r"url\s*=\s*['\"]?([^'\"\s;>]+)", content, re.IGNORECASE)
                if match:
                    self.meta_refresh_url = match.group(1).strip()
        elif t == "form":
            self._current_form = {
                "method": (attr_map.get("method") or "GET").upper(),
                "action": attr_map.get("action", "").strip(),
                "inputs": [],
            }
            self.forms.append(self._current_form)
        elif t == "input":
            self._handle_input_tag(attr_map)
        elif t == "iframe":
            style = attr_map.get("style", "").lower().replace(" ", "")
            hidden = (
                "display:none" in style
                or "visibility:hidden" in style
                or attr_map.get("width") in {"0", "1"}
                or attr_map.get("height") in {"0", "1"}
            )
            self.iframes.append({"src": attr_map.get("src", "").strip(), "hidden": "true" if hidden else "false"})

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t == "title":
            self.in_title = False
        elif t == "script":
            self.in_script = False
            self.skip_depth = max(0, self.skip_depth - 1)
        elif t in {"style", "noscript", "svg"}:
            self.skip_depth = max(0, self.skip_depth - 1)
        elif t == "form":
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
        if self.in_script:
            self.script_bodies.append(data)
        elif self.skip_depth == 0:
            cleaned = data.strip()
            if cleaned:
                self.text_parts.append(cleaned)


def inspect_html_payload(html_text: str, base_url: str) -> dict[str, Any]:
    """Statically parse captured HTML/JS inside Python without executing scripts."""
    parser = _SafeSandboxHTMLParser()
    try:
        parser.feed(html_text[:MAX_SANDBOX_BYTES])
        parser.close()
    except Exception:
        pass

    base_host = (urllib.parse.urlparse(base_url).hostname or "").lower()
    form_actions_defanged: list[str] = []
    cross_domain_form = False
    for form in parser.forms:
        abs_action = urllib.parse.urljoin(base_url, form.get("action") or base_url)
        form_actions_defanged.append(defang_url(abs_action))
        action_host = (urllib.parse.urlparse(abs_action).hostname or "").lower()
        if action_host and base_host and action_host != base_host:
            cross_domain_form = True

    combined_scripts = "\n".join(parser.script_bodies) + "\n" + html_text
    obfuscated_hits = len(
        re.findall(r"\b(?:eval|atob|unescape|fromCharCode|document\.write)\s*\(", combined_scripts, re.IGNORECASE)
    )
    js_redirect_detected = bool(
        re.search(r"(?:window\.location|document\.location|location\.href\s*=|location\.replace\s*\()", combined_scripts, re.IGNORECASE)
    )
    exfil_webhook_detected = bool(
        re.search(r"(?:api\.telegram\.org/bot|discord\.com/api/webhooks)", combined_scripts, re.IGNORECASE)
    )
    keylogger_or_clipboard = bool(
        re.search(r"(?:navigator\.clipboard|addEventListener\s*\(\s*['\"](?:keydown|keypress|paste)['\"])", combined_scripts, re.IGNORECASE)
    )

    visible_text = re.sub(r"\s+", " ", " ".join(parser.text_parts)).strip()[:450]
    page_title = re.sub(r"\s+", " ", "".join(parser.title_parts)).strip()[:120]

    return {
        "page_title": page_title,
        "visible_text_preview": visible_text,
        "forms_count": len(parser.forms),
        "password_inputs": parser.password_inputs,
        "sensitive_inputs": parser.sensitive_inputs[:8],
        "form_actions_defanged": form_actions_defanged[:5],
        "cross_domain_form": cross_domain_form,
        "scripts_count": parser.scripts_count,
        "external_script_hosts": list(dict.fromkeys(parser.external_script_hosts))[:8],
        "obfuscated_js_hits": obfuscated_hits,
        "js_redirect_detected": js_redirect_detected,
        "exfil_webhook_detected": exfil_webhook_detected,
        "keylogger_or_clipboard": keylogger_or_clipboard,
        "iframes_count": len(parser.iframes),
        "hidden_iframes_count": sum(1 for f in parser.iframes if f["hidden"] == "true"),
        "meta_refresh_target": defang_url(urllib.parse.urljoin(base_url, parser.meta_refresh_url))
        if parser.meta_refresh_url
        else None,
    }


def _extract_download_extension(url: str, content_disposition: str = "") -> str | None:
    if content_disposition:
        m = re.search(r"filename\*?=['\"]?([^'\";\n]+)", content_disposition, re.IGNORECASE)
        if m:
            ext = posixpath.splitext(m.group(1).strip().lower())[1]
            if ext:
                return ext
    parsed_path = urllib.parse.urlparse(url).path.lower()
    ext = posixpath.splitext(parsed_path)[1]
    return ext if ext in DANGEROUS_DOWNLOAD_EXTS else None


def _build_blocked_sandbox_result(
    *,
    trimmed: str,
    forensics: UrlForensics,
    execution_mode: str,
    sandbox_score: int,
    dns_ips: list[str],
    dns_error: str,
    dom_base_url: str,
    action: dict[str, Any],
) -> dict[str, Any]:
    return {
        "input_url": trimmed,
        "defanged_url": forensics["defanged_url"],
        "execution_mode": execution_mode,
        "sandbox_score": sandbox_score,
        "verdict": "dangerous",
        "forensics": forensics,
        "network_trace": {
            "dns_resolved": False,
            "dns_ips": dns_ips[:4],
            "dns_error": dns_error,
            "tls": {"available": False, "valid": False},
            "redirects": [],
            "final_url": forensics["defanged_url"],
            "http_status": None,
            "content_type": None,
            "server": None,
            "cookies_attempted": 0,
            "download_filename": None,
        },
        "dom_telemetry": inspect_html_payload("", dom_base_url),
        "what_it_tries_to_do": [action],
        "safety_guarantees": dict(_SAFETY_GUARANTEES),
    }


def _extract_live_capture(trace: dict[str, Any]) -> dict[str, Any]:
    redirects: list[dict[str, Any]] = []
    cookies_attempted = 0
    content_type: str | None = None
    server_hdr: str | None = None
    content_disp = ""

    for hop in trace["hops"]:
        redirects.append({"url": defang_url(hop["url"]), "status": hop["status"]})
        hdrs = hop.get("headers")
        if hdrs:
            content_type = hdrs.get("Content-Type")
            server_hdr = hdrs.get("Server")
            content_disp = hdrs.get("Content-Disposition") or ""
            set_cookies = (
                (hdrs.get_all("Set-Cookie") or [])
                if hasattr(hdrs, "get_all")
                else ([hdrs["Set-Cookie"]] if hdrs.get("Set-Cookie") else [])
            )
            cookies_attempted += len(set_cookies)

    raw_bytes = trace.get("last_body") or b""
    live_captured = bool(trace.get("completed_non_redirect"))
    captured_body = ""
    if live_captured and raw_bytes and (
        not content_type
        or any(tok in content_type.lower() for tok in ("text", "html", "json", "javascript"))
    ):
        captured_body = raw_bytes.decode("utf-8", errors="replace")

    return {
        "redirects": redirects,
        "http_status": trace.get("last_status"),
        "content_type": content_type,
        "server": server_hdr,
        "content_disp": content_disp,
        "cookies_attempted": cookies_attempted,
        "captured_body": captured_body,
        "live_captured": live_captured,
        "current_url": trace["current_url"],
        "redirect_ssrf_blocked": bool(trace.get("ssrf_reason")),
        "redirect_ssrf_reason": trace.get("ssrf_reason"),
    }


def _make_sandbox_action(
    action_id: str,
    severity: str,
    observed: bool,
    title_ar: str,
    title_en: str,
    detail_ar: str,
    detail_en: str,
) -> dict[str, Any]:
    return {
        "id": action_id,
        "severity": severity,
        "observed": observed,
        "title_ar": title_ar,
        "title_en": title_en,
        "detail_ar": detail_ar,
        "detail_en": detail_en,
    }


def _collect_observed_behaviors(
    *,
    final_forensics: UrlForensics,
    dom_telemetry: dict[str, Any],
    capture: dict[str, Any],
    download_ext: str | None,
    is_binary_download: bool,
) -> tuple[int, list[dict[str, Any]]]:
    """Collect behaviors directly observed from captured HTTP headers and HTML/JS telemetry."""
    added_score = 0
    actions: list[dict[str, Any]] = []
    live_captured = capture["live_captured"]
    redirects = capture["redirects"]
    current_url = capture["current_url"]
    cookies_attempted = capture["cookies_attempted"]

    if dom_telemetry["exfil_webhook_detected"]:
        added_score += 35
        actions.append(
            _make_sandbox_action(
                "telegram_exfil",
                "high",
                True,
                "يرسل البيانات المسروقة خفية إلى بوت تيليغرام أو Webhook خارجي",
                "Exfiltrates captured input to external Telegram/Discord webhook",
                "كشف صندوق الرمل عنوان إرسال آلي داخل الشيفرة المصدريّة للصفحة (تكنيك شائع في صفحات سرقة الحسابات).",
                "Static script inspection detected an automated Telegram/Discord exfiltration endpoint.",
            )
        )

    if dom_telemetry["password_inputs"] > 0 or dom_telemetry["sensitive_inputs"]:
        added_score += 25
        fields_str = ", ".join(dom_telemetry["sensitive_inputs"][:4]) or "password"
        actions.append(
            _make_sandbox_action(
                "credential_form",
                "high" if not final_forensics["is_official_brand"] else "low",
                True,
                f"يعرض نموذجاً لجمع بيانات حساسة ({fields_str})",
                f"Presents form requesting sensitive fields ({fields_str})",
                (
                    "يرسل النموذج البيانات إلى نطاق مختلف عن عنوان الصفحة!"
                    if dom_telemetry["cross_domain_form"]
                    else "يطلب إدخال كلمة مرور أو رمز تحقق أو بيانات بطاقة بمجرد فتح الصفحة."
                ),
                (
                    "Form submits entered credentials to a third-party domain."
                    if dom_telemetry["cross_domain_form"]
                    else "Page requests login credentials, OTP, or card details upon load."
                ),
            )
        )

    if is_binary_download:
        added_score += 30
        label = download_ext or capture["content_type"]
        actions.append(
            _make_sandbox_action(
                "drive_by_download",
                "high",
                live_captured or bool(download_ext),
                f"يحاول تنزيل ملف تنفيذي أو حزمة ({label})",
                f"Triggers file/payload download ({label})",
                "لو شغلت الرابط مباشرة قد يبدأ بتحميل تطبيق خبيث (APK/EXE/ZIP) على جهازك. أوقفه صندوق الرمل ولم يحفظ أي ملف.",
                "Opening directly may trigger an unsolicited binary download (APK/EXE/archive). Blocked by sandbox.",
            )
        )

    if len(redirects) > 1 or dom_telemetry["meta_refresh_target"] or dom_telemetry["js_redirect_detected"]:
        added_score += 15
        actions.append(
            _make_sandbox_action(
                "silent_redirect",
                "medium",
                True,
                f"يقوم بتحويلك تلقائياً عبر {max(1, len(redirects))} محطات إلى وجهة أخرى",
                f"Auto-redirects visitor across {max(1, len(redirects))} hop(s)",
                f"الوجهة النهائية المعطلة: {defang_url(current_url)}",
                f"Final defanged destination: {defang_url(current_url)}",
            )
        )

    if dom_telemetry["obfuscated_js_hits"] > 0 or dom_telemetry["keylogger_or_clipboard"]:
        added_score += 20
        actions.append(
            _make_sandbox_action(
                "js_obfuscation",
                "high",
                True,
                "يحتوي على أكواد JavaScript مشفّرة أو مستمعة لضغطات المفاتيح/الحافظة",
                "Contains obfuscated JavaScript or clipboard/keystroke listeners",
                f"تم رصد {dom_telemetry['obfuscated_js_hits']} استدعاءات إخفاء (eval/atob) دون تنفيذ أي سطر منها.",
                f"Detected {dom_telemetry['obfuscated_js_hits']} obfuscation calls (eval/atob); zero code executed.",
            )
        )

    if dom_telemetry["hidden_iframes_count"] > 0:
        added_score += 20
        actions.append(
            _make_sandbox_action(
                "hidden_iframe",
                "high",
                True,
                f"يحمّل {dom_telemetry['hidden_iframes_count']} إطارات مخفية (Hidden Iframe)",
                f"Embeds {dom_telemetry['hidden_iframes_count']} hidden iframe(s)",
                "تُستخدم الإطارات المخفية لشن هجمات Clickjacking أو تحميل صفحات خبيثة في الخلفية.",
                "Hidden iframes can cloak clickjacking overlays or silent third-party payloads.",
            )
        )

    if cookies_attempted > 0:
        actions.append(
            _make_sandbox_action(
                "cookie_tracking",
                "low",
                True,
                f"حاول زرع {cookies_attempted} ملفات تعريف تتبع (Cookies)",
                f"Attempted to set {cookies_attempted} tracking/session cookie(s)",
                "تجاهل صندوق الرمل جميع الكوكيز ولم يحفظ شيئاً في متصفحك.",
                "All Set-Cookie headers were discarded inside the isolated sandbox.",
            )
        )

    return added_score, actions


def _collect_predicted_behaviors(forensics: UrlForensics) -> list[dict[str, Any]]:
    """Simulate expected malicious behavior from URL structure when the remote host is unreachable."""
    actions: list[dict[str, Any]] = []
    path_low = (forensics["path"] + " " + " ".join(forensics["suspicious_params"])).lower()

    if forensics["matched_brand"] and not forensics["is_official_brand"]:
        actions.append(
            _make_sandbox_action(
                "predicted_brand_phish",
                "high",
                False,
                f"محاكاة متوقعة: يعرض صفحة مزيفة منتحلة لـ {forensics['matched_brand']}",
                f"Predicted Behavior: Spoofed {forensics['matched_brand']} credential portal",
                "رغم تعطل الخادم حالياً أو كونه نطاقاً وهمياً، تشير بنية الرابط لصفحة تصيّد تسرق تسجيل الدخول أو البطاقة المصرفية.",
                "Even though the host did not answer live HTTP, the domain mimics an official brand to harvest logins.",
            )
        )
    if any(tok in path_low for tok in ("login", "auth", "verify", "update", "otp", "pin", "bank", "signin")):
        actions.append(
            _make_sandbox_action(
                "predicted_login_trap",
                "high",
                False,
                "محاكاة متوقعة: يطلب إدخال كلمة المرور أو رمز التحقق OTP",
                "Predicted Behavior: Requests password, PIN, or OTP verification",
                "المسار أو المعاملات في الرابط مصممة لاقتناص رموز المصادقة وتمريرها للمهاجم.",
                "Path and query tokens indicate a credential or OTP interception trap.",
            )
        )
    if forensics["is_shortener"]:
        actions.append(
            _make_sandbox_action(
                "predicted_shortener",
                "medium",
                False,
                "محاكاة متوقعة: يعيد توجيه الضحية لوجهة مخفية خارجية",
                "Predicted Behavior: Forwards visitor to hidden destination",
                "الروابط المختصرة تخفي الموقع الحقيقي؛ تعذر تتبع الوجهة لأن الخادم لم يستجب.",
                "Shortened URLs mask the final host; remote endpoint did not respond during probe.",
            )
        )
    return actions


def _collect_sandbox_behaviors(
    *,
    forensics: UrlForensics,
    final_forensics: UrlForensics,
    dom_telemetry: dict[str, Any],
    capture: dict[str, Any],
    download_ext: str | None,
    is_binary_download: bool,
    base_score: int,
) -> tuple[int, list[dict[str, Any]]]:
    """Combine observed sandbox findings, offline predictions, and redirect SSRF guards."""
    observed_points, actions = _collect_observed_behaviors(
        final_forensics=final_forensics,
        dom_telemetry=dom_telemetry,
        capture=capture,
        download_ext=download_ext,
        is_binary_download=is_binary_download,
    )
    score = base_score + observed_points
    live_captured = capture["live_captured"]

    if not live_captured:
        actions.extend(_collect_predicted_behaviors(forensics))

    if not forensics["is_https"]:
        actions.append(
            _make_sandbox_action(
                "insecure_http",
                "medium",
                True,
                "ينقل أي بيانات تدخلها عبر اتصال HTTP مكشوف غير مشفّر",
                "Transmits any entered data over unencrypted HTTP",
                "يمكن لأي طرف على نفس الشبكة (Wi-Fi عام) قراءة ما ترسله عبر هذا الرابط.",
                "Traffic lacks TLS encryption and can be intercepted on shared networks.",
            )
        )

    if not actions:
        actions.append(
            _make_sandbox_action(
                "clean_inspection",
                "safe",
                live_captured,
                "لم يظهر أي سلوك خبيث أو نماذج سرقة بيانات في صندوق الرمل",
                "No malicious scripts, credential traps, or risky downloads observed",
                "الصفحة لا تطلب كلمات مرور غير موثوقة ولا تحاول تنزيل ملفات خطرة.",
                "Inspected headers and DOM showed no credential harvesting or payload drops.",
            )
        )

    if capture["redirect_ssrf_blocked"]:
        score = max(score, 94)
        reason = capture["redirect_ssrf_reason"]
        actions.insert(
            0,
            _make_sandbox_action(
                "ssrf_redirect_blocked",
                "high",
                True,
                "أعاد الرابط التوجيه نحو عنوان شبكة داخلي أو مخطط خطر (تم حظر التحويل)",
                "Attempted HTTP redirect to private/internal target or unsafe URI scheme",
                reason or "تم اعتراض إعادة التوجيه لحماية الشبكة الداخلية.",
                reason or "Redirect intercepted by SSRF guard.",
            ),
        )

    return score, actions


def detonate_url_in_sandbox(raw_url: str, timeout: float = 4.0) -> dict[str, Any]:
    """Safely detonate a URL in an isolated Python sandbox and explain what it does."""
    trimmed = (raw_url or "").strip()[:2000]

    bad_scheme = url_inspector._check_explicit_non_http_scheme(trimmed)
    if bad_scheme:
        scheme_forensics = inspect_url_forensics(trimmed)
        return _build_blocked_sandbox_result(
            trimmed=trimmed,
            forensics=scheme_forensics,
            execution_mode="blocked_unsafe_scheme",
            sandbox_score=scheme_forensics["forensic_score"],
            dns_ips=[],
            dns_error=f"Blocked unsafe scheme ({bad_scheme})",
            dom_base_url=trimmed,
            action={
                "id": "unsafe_scheme",
                "severity": "high",
                "observed": True,
                "title_ar": f"محاولة استخدام مخطط غير آمن أو تنفيذي ({bad_scheme})",
                "title_en": f"Unsafe or executable URI scheme attempt ({bad_scheme})",
                "detail_ar": "لو فُتح هذا الرابط لحاول تنفيذ أوامر محلية أو استخدام بروتوكول غير HTTP(S). قام صندوق الرمل بحظره فوراً.",
                "detail_en": "Opening this link would attempt non-HTTP(S) execution or protocol probing; blocked inside the sandbox.",
            },
        )

    forensics = inspect_url_forensics(trimmed)
    host = forensics["host"]
    allowed, ips, dns_error = url_inspector._resolve_public_host(host)

    if not allowed and dns_error and "Blocked" in dns_error:
        return _build_blocked_sandbox_result(
            trimmed=trimmed,
            forensics=forensics,
            execution_mode="blocked_ssrf",
            sandbox_score=90,
            dns_ips=ips,
            dns_error=dns_error,
            dom_base_url=forensics["normalized_url"],
            action={
                "id": "ssrf_local_target",
                "severity": "high",
                "observed": True,
                "title_ar": "يستهدف عنوان شبكة محلي أو داخلي (SSRF / LAN Probe)",
                "title_en": "Targets internal or private network address",
                "detail_ar": "يحاول الرابط الوصول إلى جهاز داخلي أو راوتر أو خدمة محلية. منعه الدرع الأمني لصندوق الرمل تماماً.",
                "detail_en": "This URL points to a private/loopback IP range and was isolated by the SSRF guard.",
            },
        )

    tls_info: dict[str, Any] = {"available": False, "valid": False}
    if allowed:
        port = forensics["port"] or 443
        tls_info = url_inspector._inspect_tls(host, port=port, timeout=min(timeout, 2.5), pinned_ip=ips[0] if ips else None)
        trace = url_inspector.trace_safe_redirects(
            forensics["normalized_url"],
            method="GET",
            max_hops=6,
            timeout=timeout,
            max_bytes=MAX_SANDBOX_BYTES,
            headers={
                "User-Agent": "Kashf-Isolated-Sandbox/1.0 (+no-js; +no-cookies)",
                "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5",
            },
        )
    else:
        trace = {
            "hops": [],
            "current_url": forensics["normalized_url"],
            "last_status": None,
            "last_headers": None,
            "last_body": b"",
            "completed_non_redirect": False,
            "ssrf_reason": None,
        }

    capture = _extract_live_capture(trace)
    current_url = capture["current_url"]
    final_forensics = inspect_url_forensics(current_url)
    dom_telemetry = inspect_html_payload(capture["captured_body"], current_url)
    download_ext = _extract_download_extension(current_url, capture["content_disp"])
    content_type = capture["content_type"]
    is_binary_download = bool(
        download_ext or (content_type and any(b in content_type.lower() for b in _BINARY_CONTENT_TYPES))
    )

    base_score = max(forensics["forensic_score"], final_forensics["forensic_score"])
    raw_score, actions = _collect_sandbox_behaviors(
        forensics=forensics,
        final_forensics=final_forensics,
        dom_telemetry=dom_telemetry,
        capture=capture,
        download_ext=download_ext,
        is_binary_download=is_binary_download,
        base_score=base_score,
    )

    final_score = max(0, min(100, raw_score))
    verdict = "safe" if final_score <= 29 else ("suspicious" if final_score <= 64 else "dangerous")
    execution_mode = (
        "blocked_ssrf"
        if capture["redirect_ssrf_blocked"]
        else ("live_captured" if capture["live_captured"] else "simulated_offline")
    )

    return {
        "input_url": trimmed,
        "defanged_url": forensics["defanged_url"],
        "execution_mode": execution_mode,
        "sandbox_score": final_score,
        "verdict": verdict,
        "forensics": final_forensics,
        "network_trace": {
            "dns_resolved": allowed,
            "dns_ips": ips[:4],
            "dns_error": dns_error,
            "tls": tls_info,
            "redirects": capture["redirects"],
            "final_url": defang_url(current_url),
            "http_status": capture["http_status"],
            "content_type": content_type,
            "server": capture["server"],
            "cookies_attempted": capture["cookies_attempted"],
            "download_filename": download_ext,
        },
        "dom_telemetry": dom_telemetry,
        "what_it_tries_to_do": actions,
        "safety_guarantees": dict(_SAFETY_GUARANTEES),
    }
