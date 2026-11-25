"""Shared pure-Python API routing, validation, security constants, and SPA resolution.

Used by both FastAPI (`main.py`) and the zero-dependency standard-library HTTP server
(`stdlib_server.py`) so every endpoint, status code, and security check stays identical.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from env_loader import load_project_env

load_project_env()

from academic_analyzer import analyze_academic_text, scan_dlp_content  # noqa: E402
from analyzer import analyze_batch, analyze_message, parse_batch_messages  # noqa: E402
from blockchain import (  # noqa: E402
    _init_ledger_table,
    get_dashboard_summary,
    issue_certificate,
    verify_certificate,
)
from db import check_rate_limit, get_community_stats, get_trending, init_db, save_report  # noqa: E402
from dev_console import (  # noqa: E402
    DevAuthError,
    DevRole,
    authenticate_token,
    bootstrap_owner,
    claim_invite,
    create_invite,
    delete_domain_rule,
    get_dev_overview,
    get_public_config,
    get_runtime_settings,
    init_dev_tables,
    login_developer,
    update_developer_access,
    update_runtime_settings,
    upsert_domain_rule,
)
from evaluate_models import run_all_evaluations  # noqa: E402
from quiz import get_quiz_scenarios, verify_quiz_answer  # noqa: E402
from saas_sandbox import (  # noqa: E402
    _init_platform_tables,
    delete_saas_tenant,
    list_saas_tenants,
    list_sandbox_runs,
    register_saas_tenant,
    run_sandbox_benchmark,
)
from ui_content import get_ui_content, render_share_card_svg  # noqa: E402
from url_inspector import probe_url_live  # noqa: E402
from url_sandbox import detonate_url_in_sandbox  # noqa: E402

RATE_LIMIT_MAX_REQUESTS = 30
RATE_LIMIT_WINDOW_SECONDS = 60.0
MAX_REQUEST_BODY_BYTES = 128 * 1024

ALLOWED_CORS_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
)

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com data:; "
    "img-src 'self' blob: data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
}

_TENANT_CODE_RE = re.compile(r"^IQ-UNI-\d{3,6}$")


class ApiError(Exception):
    """Structured HTTP error surfaced cleanly by both FastAPI and stdlib HTTP servers."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def init_all_tables() -> None:
    """Initialize all SQLite tables required across modules."""
    init_db()
    _init_ledger_table()
    _init_platform_tables()
    init_dev_tables()


def resolve_server_bind() -> tuple[str, int]:
    """Resolve bind host and port cleanly for Cloud Run / Docker / local runs."""
    is_container = bool(
        os.environ.get("K_SERVICE")
        or os.environ.get("CLOUD_RUN_JOB")
        or os.environ.get("CLOUD_RUN_EXECUTION")
        or os.environ.get("PORT")
        or Path("/.dockerenv").exists()
    )
    default_host = "0.0.0.0" if is_container else "127.0.0.1"
    host = os.environ.get("HOST", "").strip() or default_host
    try:
        port = int(os.environ.get("PORT", "8000").strip() or "8000")
    except ValueError:
        port = 8000
    return host, port


def enforce_rate_limit(client_ip: str) -> None:
    """Enforce sliding-window SQLite rate limit per client IP."""
    if not check_rate_limit(
        f"api:{client_ip}",
        max_requests=RATE_LIMIT_MAX_REQUESTS,
        window_seconds=RATE_LIMIT_WINDOW_SECONDS,
    ):
        raise ApiError(429, "تم تجاوز الحد المسموح من الطلبات. يرجى المحاولة بعد دقيقة.")


def require_dev_role(auth_header: str | None, allowed_roles: tuple[DevRole, ...]) -> dict[str, Any]:
    """Authenticate Bearer token and verify caller holds one of the allowed RBAC roles."""
    return authenticate_token(auth_header, allowed_roles)


def _as_dict(payload: Any) -> dict[str, Any]:
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise ApiError(400, "Request body must be a JSON object")
    return payload


def _field(data: dict[str, Any], key: str, expected_type: type | tuple[type, ...], default: Any = None) -> Any:
    val = data.get(key, default)
    if val is None:
        return default
    if expected_type is int and isinstance(val, bool):
        raise ApiError(400, f"body.{key}: Input should be a valid integer")
    if expected_type == (int, float) and isinstance(val, bool):
        raise ApiError(400, f"body.{key}: Input should be a valid number")
    if not isinstance(val, expected_type):
        raise ApiError(400, f"body.{key}: Invalid input type")
    return val


def handle_api_request(
    method: str,
    path: str,
    query_params: dict[str, list[str]] | dict[str, str] | None,
    payload: Any,
    client_ip: str,
    auth_header: str | None = None,
) -> dict[str, Any] | list[Any]:
    """Dispatch `/api/*` requests to Python backend modules."""
    m = method.upper()
    norm_path = path.rstrip("/") or "/"
    params = query_params or {}

    def _q(name: str, default: str = "") -> str:
        val = params.get(name)
        if isinstance(val, list):
            return val[0] if val else default
        return val if isinstance(val, str) else default

    try:
        if m == "GET" and norm_path == "/api/health":
            return {"ok": True}

        if m == "GET" and norm_path == "/api/i18n":
            lang = _q("lang", "").strip()
            return get_ui_content(lang if lang in {"ar", "en"} else None)

        if m == "POST" and norm_path == "/api/share-card":
            enforce_rate_limit(client_ip)
            data = _as_dict(payload)
            return render_share_card_svg(
                score=int(round(_field(data, "score", (int, float), 0))),
                verdict=str(_field(data, "verdict", str, "suspicious")),
                category=str(_field(data, "category", str, "other")),
                lang=str(_field(data, "lang", str, "ar")),
            )

        if m == "POST" and norm_path == "/api/analyze":
            enforce_rate_limit(client_ip)
            data = _as_dict(payload)
            text = _field(data, "text", str, "").strip()[:5000]
            if not text:
                raise ApiError(400, "Message text is required")
            raw_url = _field(data, "url", str, None)
            cleaned_url = raw_url.strip()[:2000] if raw_url is not None else None
            use_llm = bool(_field(data, "use_auxiliary_llm", bool, False))
            return analyze_message(text, cleaned_url, use_auxiliary_llm=use_llm)

        if m == "POST" and norm_path == "/api/analyze-batch":
            enforce_rate_limit(client_ip)
            data = _as_dict(payload)
            raw_msgs = _field(data, "messages", list, [])
            cleaned = [msg.strip()[:5000] for msg in raw_msgs if isinstance(msg, str) and msg.strip()]
            raw_text = _field(data, "raw_text", str, None)
            if not cleaned and raw_text and raw_text.strip():
                cleaned = [msg[:5000] for msg in parse_batch_messages(raw_text[:25000]) if msg.strip()]
            cleaned = cleaned[:25]
            if not cleaned:
                raise ApiError(400, "At least one message is required")
            return analyze_batch(cleaned)

        if m == "POST" and norm_path == "/api/inspect-url":
            enforce_rate_limit(client_ip)
            data = _as_dict(payload)
            raw_url = _field(data, "url", str, "").strip()[:2000]
            if len(raw_url) < 3:
                raise ApiError(400, "Valid URL is required")
            settings = get_runtime_settings()
            include_intel = bool(_field(data, "include_intel", bool, True)) and bool(
                settings.get("enable_live_threat_intel", True)
            )
            return probe_url_live(raw_url, include_intel=include_intel)

        if m == "POST" and norm_path == "/api/sandbox-url":
            enforce_rate_limit(client_ip)
            data = _as_dict(payload)
            raw_url = _field(data, "url", str, "").strip()[:2000]
            if len(raw_url) < 3:
                raise ApiError(400, "Valid URL is required")
            if not get_runtime_settings().get("enable_url_sandbox", True):
                raise ApiError(503, "Safe URL Sandbox is currently disabled by administrator settings.")
            return detonate_url_in_sandbox(raw_url)

        if m == "POST" and norm_path == "/api/academic/analyze":
            enforce_rate_limit(client_ip)
            data = _as_dict(payload)
            text = _field(data, "text", str, "").strip()[:15000]
            if len(text) < 10:
                raise ApiError(400, "Academic text must be at least 10 characters")
            raw_ref = _field(data, "reference_text", str, None)
            ref = raw_ref.strip()[:15000] if raw_ref is not None else None
            behavior = _field(data, "behavior", dict, None)
            return analyze_academic_text(text, ref, behavior)

        if m == "POST" and norm_path == "/api/dlp/scan":
            enforce_rate_limit(client_ip)
            data = _as_dict(payload)
            text = _field(data, "text", str, "").strip()[:20000]
            if not text:
                raise ApiError(400, "Content text is required for DLP scan")
            return scan_dlp_content(text)

        if m == "POST" and norm_path == "/api/certificates/issue":
            enforce_rate_limit(client_ip)
            data = _as_dict(payload)
            title = _field(data, "title", str, "").strip()[:160]
            author = _field(data, "author", str, "").strip()[:100]
            institution = _field(data, "institution", str, "").strip()[:120]
            text = _field(data, "text", str, "").strip()[:15000]
            score = _field(data, "originality_score", (int, float), 0)
            if len(title) < 2 or len(author) < 2 or len(text) < 10:
                raise ApiError(400, "Title, author, and text are required")
            if score < 0 or score > 100:
                raise ApiError(400, "originality_score must be between 0 and 100")
            return issue_certificate(
                title=title,
                author=author,
                institution=institution,
                text=text,
                originality_score=int(round(score)),
            )

        if m == "GET" and norm_path == "/api/certificates/verify":
            enforce_rate_limit(client_ip)
            return verify_certificate(_q("q", "").strip()[:128])

        if m == "GET" and norm_path == "/api/dashboard":
            enforce_rate_limit(client_ip)
            return get_dashboard_summary()

        if m == "POST" and norm_path == "/api/sandbox/benchmark":
            enforce_rate_limit(client_ip)
            data = _as_dict(payload)
            return run_sandbox_benchmark(
                _field(data, "department", str, "").strip()[:140],
                int(_field(data, "load_size", int, 30)),
            )

        if m == "GET" and norm_path == "/api/sandbox/runs":
            enforce_rate_limit(client_ip)
            return {"history": list_sandbox_runs()}

        if m == "GET" and norm_path == "/api/saas/tenants":
            enforce_rate_limit(client_ip)
            require_dev_role(auth_header, ("owner", "editor", "viewer"))
            return list_saas_tenants()

        if m == "POST" and norm_path == "/api/saas/tenants":
            enforce_rate_limit(client_ip)
            require_dev_role(auth_header, ("owner", "editor"))
            data = _as_dict(payload)
            university_name = _field(data, "university_name", str, "").strip()[:140]
            if len(university_name) < 2:
                raise ApiError(400, "University name is required")
            return register_saas_tenant(
                university_name=university_name,
                student_count=int(_field(data, "student_count", int, 1000)),
                faculty_count=int(_field(data, "faculty_count", int, 50)),
                plan_tier=str(_field(data, "plan_tier", str, "campus")),
            )

        if m == "DELETE" and norm_path.startswith("/api/saas/tenants/"):
            tenant_code = unquote(norm_path.removeprefix("/api/saas/tenants/")).strip()
            if "/" in tenant_code or not tenant_code:
                raise ApiError(404, f"API endpoint '{norm_path}' not found")
            enforce_rate_limit(client_ip)
            require_dev_role(auth_header, ("owner",))
            if not _TENANT_CODE_RE.match(tenant_code):
                raise ApiError(400, "Invalid tenant code format")
            return delete_saas_tenant(tenant_code)

        if m == "GET" and norm_path == "/api/quiz":
            return {"scenarios": get_quiz_scenarios()}

        if m == "POST" and norm_path == "/api/quiz/verify":
            enforce_rate_limit(client_ip)
            data = _as_dict(payload)
            scenario_id = _field(data, "id", str, "").strip()[:64]
            if not scenario_id:
                raise ApiError(400, "Scenario id is required")
            lang = "en" if _field(data, "lang", str, "ar") == "en" else "ar"
            try:
                return verify_quiz_answer(scenario_id, bool(_field(data, "is_scam", bool, False)), lang)
            except ValueError as exc:
                raise ApiError(404, str(exc)) from exc

        if m == "POST" and norm_path == "/api/report":
            enforce_rate_limit(client_ip)
            data = _as_dict(payload)
            fingerprint = _field(data, "fingerprint", str, "").strip()[:64]
            if len(fingerprint) < 8:
                raise ApiError(400, "Valid fingerprint is required")
            raw_cat = _field(data, "category", str, "other")
            clamped_score = max(0, min(100, int(round(_field(data, "score", (int, float), 0)))))
            return save_report(
                category=raw_cat[:64] if raw_cat else "other",
                score=clamped_score,
                fingerprint=fingerprint,
            )

        if m == "GET" and norm_path == "/api/trending":
            enforce_rate_limit(client_ip)
            return {"items": get_trending(), "stats": get_community_stats()}

        if m == "GET" and norm_path == "/api/evaluation":
            enforce_rate_limit(client_ip)
            return run_all_evaluations()

        if m == "GET" and norm_path == "/api/public-config":
            enforce_rate_limit(client_ip)
            return get_public_config()

        if m == "POST" and norm_path == "/api/dev/bootstrap":
            enforce_rate_limit(client_ip)
            data = _as_dict(payload)
            return bootstrap_owner(
                name=_field(data, "name", str, ""),
                email=_field(data, "email", str, ""),
                password=_field(data, "password", str, ""),
                bootstrap_key=_field(data, "bootstrap_key", str, None),
            )

        if m == "POST" and norm_path == "/api/dev/login":
            enforce_rate_limit(client_ip)
            data = _as_dict(payload)
            return login_developer(
                email=_field(data, "email", str, ""),
                password=_field(data, "password", str, ""),
            )

        if m == "POST" and norm_path == "/api/dev/invite/claim":
            enforce_rate_limit(client_ip)
            data = _as_dict(payload)
            return claim_invite(
                invite_token=_field(data, "invite_token", str, ""),
                name=_field(data, "name", str, ""),
                email=_field(data, "email", str, ""),
                password=_field(data, "password", str, ""),
            )

        if m == "GET" and norm_path == "/api/dev/overview":
            enforce_rate_limit(client_ip)
            return get_dev_overview(require_dev_role(auth_header, ("owner", "editor", "viewer")))

        if m == "PUT" and norm_path == "/api/dev/settings":
            enforce_rate_limit(client_ip)
            actor = require_dev_role(auth_header, ("owner", "editor"))
            return {"settings": update_runtime_settings(actor, _as_dict(payload))}

        if m == "POST" and norm_path == "/api/dev/domain-rules":
            enforce_rate_limit(client_ip)
            actor = require_dev_role(auth_header, ("owner", "editor"))
            data = _as_dict(payload)
            return {
                "domain_rules": upsert_domain_rule(
                    actor,
                    domain=_field(data, "domain", str, ""),
                    rule_type=_field(data, "rule_type", str, "blocklist"),
                    note=_field(data, "note", str, ""),
                )
            }

        if m == "DELETE" and norm_path.startswith("/api/dev/domain-rules/"):
            domain = unquote(norm_path.removeprefix("/api/dev/domain-rules/"))
            if "/" in domain or not domain:
                raise ApiError(404, f"API endpoint '{norm_path}' not found")
            enforce_rate_limit(client_ip)
            return {"domain_rules": delete_domain_rule(require_dev_role(auth_header, ("owner", "editor")), domain=domain)}

        if m == "POST" and norm_path == "/api/dev/invites":
            enforce_rate_limit(client_ip)
            actor = require_dev_role(auth_header, ("owner",))
            data = _as_dict(payload)
            return create_invite(
                actor,
                role=_field(data, "role", str, "viewer"),
                note=_field(data, "note", str, ""),
            )

        if m == "PATCH" and norm_path.startswith("/api/dev/users/"):
            raw_uid = norm_path.removeprefix("/api/dev/users/")
            try:
                user_id = int(raw_uid)
            except ValueError as exc:
                raise ApiError(400, "path.user_id: Input should be a valid integer") from exc
            enforce_rate_limit(client_ip)
            actor = require_dev_role(auth_header, ("owner",))
            data = _as_dict(payload)
            raw_active = _field(data, "active", bool, None)
            return {
                "user": update_developer_access(
                    actor,
                    target_user_id=user_id,
                    role=_field(data, "role", str, None),
                    active=raw_active,
                )
            }

    except DevAuthError as exc:
        raise ApiError(exc.status_code, str(exc)) from exc
    except ValueError as exc:
        raise ApiError(400, str(exc)) from exc

    raise ApiError(404, f"API endpoint '{norm_path}' not found")


def resolve_static_target(dist_dir: Path, raw_path: str) -> tuple[int, Path | None, str | None]:
    """Resolve a built SPA asset or index.html safely while preventing path traversal."""
    dist_resolved = dist_dir.resolve()
    index_file = dist_resolved / "index.html"
    if not index_file.is_file():
        return (
            503,
            None,
            "Frontend build not found in dist/. Run 'npm run build' or use Vite dev server.",
        )

    decoded = unquote(raw_path).lstrip("/")
    if decoded == "api" or decoded.startswith("api/"):
        return 404, None, f"API endpoint '/{decoded}' not found"

    if decoded:
        try:
            candidate = (dist_resolved / decoded).resolve()
        except OSError:
            return 404, None, "Invalid asset path"

        if not candidate.is_relative_to(dist_resolved):
            return 404, None, "Not found"

        if candidate.is_file():
            return 200, candidate, None

        if decoded.startswith(("assets/", "robot-frames/")) or "." in Path(decoded).name:
            return 404, None, "Static asset not found"

    return 200, index_file, None
