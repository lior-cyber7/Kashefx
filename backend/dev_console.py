"""Role-based Python Developer Console, PBKDF2 Auth, HMAC Tokens, Runtime Settings & Domain Rules."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Literal

from db import db_transaction, open_db
from env_loader import load_project_env

load_project_env()

DevRole = Literal["owner", "editor", "viewer"]

TOKEN_TTL_SECONDS = 12 * 3600
INVITE_TTL_SECONDS = 72 * 3600
PBKDF2_ITERATIONS = 210_000

DEFAULT_RUNTIME_SETTINGS: dict[str, Any] = {
    "suspicious_threshold": 30,
    "dangerous_threshold": 65,
    "enable_live_threat_intel": True,
    "enable_url_sandbox": True,
    "enable_auxiliary_llm": False,
    "maintenance_mode": False,
    "maintenance_notice_ar": "",
    "maintenance_notice_en": "",
}

DOMAIN_REGEX = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{1,63})+$")


class DevAuthError(Exception):
    """Domain exception carrying an explicit HTTP status code for RBAC/auth failures."""

    def __init__(self, message: str, status_code: int = 401) -> None:
        super().__init__(message)
        self.status_code = status_code


def _utc_iso(ts: float | None = None) -> str:
    dt = datetime.fromtimestamp(ts if ts is not None else time.time(), tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def init_dev_tables(db_path: str | None = None) -> None:
    """Ensure Developer Console SQLite tables exist."""
    with open_db(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dev_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL,
                last_login_at REAL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dev_invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                created_by_email TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                used_at REAL,
                used_by_email TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dev_settings (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_at REAL NOT NULL,
                updated_by TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dev_domain_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                rule_type TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                created_by TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dev_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                actor_email TEXT NOT NULL,
                actor_role TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dev_secrets (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.commit()


def _get_signing_secret(db_path: str | None = None) -> bytes:
    """Return HMAC token signing key from env var or persistent dev_secrets table."""
    env_secret = os.environ.get("KASHF_DEV_SESSION_SECRET", "").strip()
    if len(env_secret) >= 16:
        return env_secret.encode("utf-8")

    init_dev_tables(db_path)
    with open_db(db_path) as conn:
        row = conn.execute(
            "SELECT value FROM dev_secrets WHERE key = 'session_secret' LIMIT 1"
        ).fetchone()
        if row is not None and row["value"]:
            return str(row["value"]).encode("utf-8")
        generated = secrets.token_hex(32)
        conn.execute(
            "INSERT OR REPLACE INTO dev_secrets (key, value) VALUES ('session_secret', ?)",
            (generated,),
        )
        conn.commit()
        return generated.encode("utf-8")


def _hash_password(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    """Derive PBKDF2-HMAC-SHA256 password hash with a 128-bit random salt."""
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return digest.hex(), salt.hex()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padded = text + "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _sign_token(payload: dict[str, Any], db_path: str | None = None) -> str:
    secret = _get_signing_secret(db_path)
    body = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(secret, body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64url_encode(sig)}"


def _verify_token(token: str, db_path: str | None = None) -> dict[str, Any]:
    """Verify token HMAC signature and expiration timestamp using constant-time comparison."""
    if not token or "." not in token:
        raise DevAuthError("Invalid session token", 401)
    body, sig_part = token.split(".", 1)
    secret = _get_signing_secret(db_path)
    expected_sig = _b64url_encode(
        hmac.new(secret, body.encode("ascii"), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(sig_part, expected_sig):
        raise DevAuthError("Invalid session signature", 401)
    try:
        payload = json.loads(_b64url_decode(body).decode("utf-8"))
    except Exception as exc:
        raise DevAuthError("Malformed session token", 401) from exc
    if float(payload.get("exp", 0)) < time.time():
        raise DevAuthError("Session expired", 401)
    return payload


def _issue_session_for_user(user_data: dict[str, Any], issued_at: float, db_path: str | None = None) -> str:
    return _sign_token(
        {
            "uid": user_data["id"],
            "email": user_data["email"],
            "role": user_data["role"],
            "iat": int(issued_at),
            "exp": int(issued_at + TOKEN_TTL_SECONDS),
        },
        db_path=db_path,
    )


def _log_audit(
    actor_email: str,
    actor_role: str,
    action: str,
    detail: str,
    db_path: str | None = None,
) -> None:
    init_dev_tables(db_path)
    with open_db(db_path) as conn:
        conn.execute(
            "INSERT INTO dev_audit_log (ts, actor_email, actor_role, action, detail) VALUES (?, ?, ?, ?, ?)",
            (time.time(), actor_email, actor_role, action[:80], detail[:300]),
        )
        conn.commit()


def _serialize_user(row: Any) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "name": str(row["name"]),
        "email": str(row["email"]),
        "role": str(row["role"]),
        "active": bool(row["active"]),
        "created_at": _utc_iso(float(row["created_at"])),
        "last_login_at": _utc_iso(float(row["last_login_at"])) if row["last_login_at"] else None,
    }


def _serialize_domain_rule(row: Any) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "domain": str(row["domain"]),
        "rule_type": str(row["rule_type"]),
        "note": str(row["note"]),
        "created_by": str(row["created_by"]),
        "created_at": _utc_iso(float(row["created_at"])),
    }


def _serialize_audit_row(row: Any, actor: dict[str, Any]) -> dict[str, Any]:
    actor_email = str(row["actor_email"])
    visible_email = actor_email if actor["role"] == "owner" or actor_email == actor["email"] else "***"
    return {
        "id": int(row["id"]),
        "ts": _utc_iso(float(row["ts"])),
        "actor_email": visible_email,
        "actor_role": str(row["actor_role"]),
        "action": str(row["action"]),
        "detail": str(row["detail"]),
    }


def _serialize_invite_row(row: Any) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "role": str(row["role"]),
        "note": str(row["note"]),
        "created_by_email": str(row["created_by_email"]),
        "created_at": _utc_iso(float(row["created_at"])),
        "expires_at": _utc_iso(float(row["expires_at"])),
        "used_at": _utc_iso(float(row["used_at"])) if row["used_at"] else None,
        "used_by_email": str(row["used_by_email"]) if row["used_by_email"] else None,
    }


def has_owner_initialized(db_path: str | None = None) -> bool:
    """Return True if at least one developer account has already been created."""
    init_dev_tables(db_path)
    with open_db(db_path) as conn:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM dev_users").fetchone()
        return bool(row and int(row["cnt"]) > 0)


def bootstrap_owner(
    name: str,
    email: str,
    password: str,
    bootstrap_key: str | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Create the initial Owner account when no users exist and KASHF_DEV_BOOTSTRAP_KEY matches."""
    init_dev_tables(db_path)
    clean_name = name.strip()[:80]
    clean_email = email.strip().lower()[:140]
    if len(clean_name) < 2 or "@" not in clean_email or len(password) < 8:
        raise DevAuthError("Valid name, email, and password (8+ chars) are required", 400)

    required_key = os.environ.get("KASHF_DEV_BOOTSTRAP_KEY", "").strip()
    if not required_key:
        raise DevAuthError(
            "KASHF_DEV_BOOTSTRAP_KEY must be configured in environment/.env before creating the first Owner account",
            503,
        )
    if not hmac.compare_digest((bootstrap_key or "").strip(), required_key):
        raise DevAuthError("Invalid bootstrap key", 403)

    now = time.time()
    with db_transaction(db_path) as conn:
        existing = conn.execute("SELECT COUNT(*) AS cnt FROM dev_users").fetchone()
        if existing and int(existing["cnt"]) > 0:
            raise DevAuthError("Owner already initialized. Sign in or request an invite link.", 409)

        pw_hash, salt = _hash_password(password)
        cur = conn.execute(
            """
            INSERT INTO dev_users (name, email, role, password_hash, salt, active, created_at, last_login_at)
            VALUES (?, ?, 'owner', ?, ?, 1, ?, ?)
            """,
            (clean_name, clean_email, pw_hash, salt, now, now),
        )
        user_id = int(cur.lastrowid)
        user_row = conn.execute("SELECT * FROM dev_users WHERE id = ?", (user_id,)).fetchone()

    user_data = _serialize_user(user_row)
    _log_audit(clean_email, "owner", "owner_bootstrap", "Initialized primary owner account", db_path=db_path)
    return {"token": _issue_session_for_user(user_data, now, db_path=db_path), "user": user_data}


def login_developer(
    email: str,
    password: str,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Verify developer email/password with PBKDF2 and issue a signed session token."""
    init_dev_tables(db_path)
    clean_email = email.strip().lower()
    if not clean_email or not password:
        raise DevAuthError("Email and password are required", 400)

    with open_db(db_path) as conn:
        row = conn.execute("SELECT * FROM dev_users WHERE email = ? LIMIT 1", (clean_email,)).fetchone()
        if row is None:
            raise DevAuthError("Invalid credentials", 401)
        if not bool(row["active"]):
            raise DevAuthError("Developer access has been revoked", 403)

        expected_hash, _ = _hash_password(password, str(row["salt"]))
        if not hmac.compare_digest(expected_hash, str(row["password_hash"])):
            raise DevAuthError("Invalid credentials", 401)

        now = time.time()
        conn.execute("UPDATE dev_users SET last_login_at = ? WHERE id = ?", (now, int(row["id"])))
        conn.commit()
        updated = conn.execute("SELECT * FROM dev_users WHERE id = ?", (int(row["id"]),)).fetchone()

    user_data = _serialize_user(updated)
    _log_audit(user_data["email"], user_data["role"], "dev_login", "Authenticated session issued", db_path=db_path)
    return {"token": _issue_session_for_user(user_data, now, db_path=db_path), "user": user_data}


def authenticate_token(
    auth_header: str | None,
    required_roles: tuple[DevRole | str, ...] = ("owner", "editor", "viewer"),
    db_path: str | None = None,
) -> dict[str, Any]:
    """Validate Bearer token signature, active account status, and required RBAC role."""
    if not auth_header:
        raise DevAuthError("Authorization token required", 401)
    token = auth_header.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    payload = _verify_token(token, db_path=db_path)
    uid = int(payload.get("uid", 0))

    init_dev_tables(db_path)
    with open_db(db_path) as conn:
        row = conn.execute("SELECT * FROM dev_users WHERE id = ? LIMIT 1", (uid,)).fetchone()
    if row is None or not bool(row["active"]):
        raise DevAuthError("Developer account inactive or revoked", 403)

    user_data = _serialize_user(row)
    if user_data["role"] not in required_roles:
        raise DevAuthError("Insufficient role permissions for this operation", 403)
    return user_data


def create_invite(
    actor: dict[str, Any],
    role: DevRole | str,
    note: str = "",
    db_path: str | None = None,
) -> dict[str, Any]:
    """Generate a single-use SHA-256 hashed developer invitation link (Owner only)."""
    if actor["role"] != "owner":
        raise DevAuthError("Only the owner can generate developer invite links", 403)
    clean_role: DevRole = "editor" if role == "editor" else "viewer"
    raw_token = f"kdev_{secrets.token_urlsafe(24)}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    now = time.time()
    expires_at = now + INVITE_TTL_SECONDS
    clean_note = note.strip()[:140]

    init_dev_tables(db_path)
    with open_db(db_path) as conn:
        conn.execute(
            """
            INSERT INTO dev_invites (token_hash, role, note, created_by_email, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (token_hash, clean_role, clean_note, actor["email"], now, expires_at),
        )
        conn.commit()

    _log_audit(
        actor["email"],
        actor["role"],
        "invite_created",
        f"Created {clean_role} invite ({clean_note or 'no note'})",
        db_path=db_path,
    )
    return {
        "invite_token": raw_token,
        "role": clean_role,
        "note": clean_note,
        "expires_at": _utc_iso(expires_at),
    }


def claim_invite(
    invite_token: str,
    name: str,
    email: str,
    password: str,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Atomically redeem a single-use invite token and create a new developer account."""
    init_dev_tables(db_path)
    clean_token = invite_token.strip()
    clean_name = name.strip()[:80]
    clean_email = email.strip().lower()[:140]
    if not clean_token or len(clean_name) < 2 or "@" not in clean_email or len(password) < 8:
        raise DevAuthError("Valid invite token, name, email, and password (8+ chars) are required", 400)

    token_hash = hashlib.sha256(clean_token.encode("utf-8")).hexdigest()
    now = time.time()
    with db_transaction(db_path) as conn:
        inv = conn.execute(
            "SELECT * FROM dev_invites WHERE token_hash = ? LIMIT 1",
            (token_hash,),
        ).fetchone()
        if inv is None:
            raise DevAuthError("Invalid invite token", 404)
        if inv["used_at"] is not None:
            raise DevAuthError("Invite token has already been used", 409)
        if float(inv["expires_at"]) < now:
            raise DevAuthError("Invite token has expired", 410)

        existing_user = conn.execute(
            "SELECT id FROM dev_users WHERE email = ? LIMIT 1", (clean_email,)
        ).fetchone()
        if existing_user is not None:
            raise DevAuthError("An account with this email already exists", 409)

        role = str(inv["role"])
        pw_hash, salt = _hash_password(password)
        cur = conn.execute(
            """
            INSERT INTO dev_users (name, email, role, password_hash, salt, active, created_at, last_login_at)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (clean_name, clean_email, role, pw_hash, salt, now, now),
        )
        user_id = int(cur.lastrowid)
        conn.execute(
            "UPDATE dev_invites SET used_at = ?, used_by_email = ? WHERE id = ?",
            (now, clean_email, int(inv["id"])),
        )
        user_row = conn.execute("SELECT * FROM dev_users WHERE id = ?", (user_id,)).fetchone()

    user_data = _serialize_user(user_row)
    _log_audit(clean_email, role, "invite_claimed", f"Joined as {role} via invite link", db_path=db_path)
    return {"token": _issue_session_for_user(user_data, now, db_path=db_path), "user": user_data}


def update_developer_access(
    actor: dict[str, Any],
    target_user_id: int,
    role: DevRole | str | None = None,
    active: bool | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Update a developer account's role or active flag (Owner only)."""
    if actor["role"] != "owner":
        raise DevAuthError("Only the owner can modify team permissions", 403)
    if target_user_id == actor["id"] and (active is False or (role and role != "owner")):
        raise DevAuthError("Owner cannot revoke or demote their own active session", 400)

    init_dev_tables(db_path)
    with open_db(db_path) as conn:
        row = conn.execute("SELECT * FROM dev_users WHERE id = ? LIMIT 1", (target_user_id,)).fetchone()
        if row is None:
            raise DevAuthError("Developer account not found", 404)

        next_role = role if role in ("owner", "editor", "viewer") else str(row["role"])
        next_active = int(active) if active is not None else int(row["active"])
        conn.execute(
            "UPDATE dev_users SET role = ?, active = ? WHERE id = ?",
            (next_role, next_active, target_user_id),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM dev_users WHERE id = ?", (target_user_id,)).fetchone()

    _log_audit(
        actor["email"],
        actor["role"],
        "role_updated",
        f"Updated {updated['email']} -> role={next_role}, active={bool(next_active)}",
        db_path=db_path,
    )
    return _serialize_user(updated)


def get_runtime_settings(db_path: str | None = None) -> dict[str, Any]:
    """Load dynamic runtime thresholds and feature toggles with safe defaults."""
    merged = dict(DEFAULT_RUNTIME_SETTINGS)
    try:
        init_dev_tables(db_path)
        with open_db(db_path) as conn:
            rows = conn.execute("SELECT key, value_json FROM dev_settings").fetchall()
        for row in rows:
            key = str(row["key"])
            if key in merged:
                merged[key] = json.loads(str(row["value_json"]))
    except Exception:
        return merged
    return merged


def update_runtime_settings(
    actor: dict[str, Any],
    updates: dict[str, Any],
    db_path: str | None = None,
) -> dict[str, Any]:
    """Validate and persist runtime thresholds/toggles (Editor or Owner role)."""
    if actor["role"] not in ("owner", "editor"):
        raise DevAuthError("Editor or Owner role required to modify application settings", 403)

    current = get_runtime_settings(db_path=db_path)
    if "suspicious_threshold" in updates:
        val = int(updates["suspicious_threshold"])
        current["suspicious_threshold"] = max(15, min(55, val))
    if "dangerous_threshold" in updates:
        val = int(updates["dangerous_threshold"])
        current["dangerous_threshold"] = max(max(current["suspicious_threshold"] + 10, 50), min(90, val))
    for bool_key in (
        "enable_live_threat_intel",
        "enable_url_sandbox",
        "enable_auxiliary_llm",
        "maintenance_mode",
    ):
        if bool_key in updates:
            current[bool_key] = bool(updates[bool_key])
    for str_key in ("maintenance_notice_ar", "maintenance_notice_en"):
        if str_key in updates and isinstance(updates[str_key], str):
            current[str_key] = updates[str_key].strip()[:240]

    init_dev_tables(db_path)
    now = time.time()
    with open_db(db_path) as conn:
        for k, v in current.items():
            conn.execute(
                """
                INSERT OR REPLACE INTO dev_settings (key, value_json, updated_at, updated_by)
                VALUES (?, ?, ?, ?)
                """,
                (k, json.dumps(v, ensure_ascii=False), now, actor["email"]),
            )
        conn.commit()

    _log_audit(
        actor["email"],
        actor["role"],
        "settings_updated",
        f"suspicious>={current['suspicious_threshold']}, dangerous>={current['dangerous_threshold']}, maintenance={current['maintenance_mode']}",
        db_path=db_path,
    )
    return current


def _clean_domain(raw: str) -> str:
    cleaned = raw.strip().lower()
    cleaned = re.sub(r"^https?://", "", cleaned)
    cleaned = cleaned.split("/", 1)[0].split(":", 1)[0].strip(".")
    if cleaned.startswith("www."):
        cleaned = cleaned[4:]
    return cleaned


def list_domain_rules(db_path: str | None = None) -> list[dict[str, Any]]:
    """List custom allowlist/blocklist domain rules ordered newest-first."""
    try:
        init_dev_tables(db_path)
        with open_db(db_path) as conn:
            rows = conn.execute(
                "SELECT id, domain, rule_type, note, created_by, created_at FROM dev_domain_rules ORDER BY created_at DESC"
            ).fetchall()
        return [_serialize_domain_rule(r) for r in rows]
    except Exception:
        return []


def get_domain_rules_map(db_path: str | None = None) -> dict[str, set[str]]:
    """Return blocklist and allowlist domain sets for quick analyzer lookup."""
    rules = list_domain_rules(db_path=db_path)
    blocklist = {r["domain"] for r in rules if r["rule_type"] == "blocklist"}
    allowlist = {r["domain"] for r in rules if r["rule_type"] == "allowlist"}
    return {"blocklist": blocklist, "allowlist": allowlist}


def upsert_domain_rule(
    actor: dict[str, Any],
    domain: str,
    rule_type: str,
    note: str = "",
    db_path: str | None = None,
) -> list[dict[str, Any]]:
    """Insert or update a custom domain rule (Editor or Owner role)."""
    if actor["role"] not in ("owner", "editor"):
        raise DevAuthError("Editor or Owner role required to modify domain rules", 403)
    clean = _clean_domain(domain)
    if not clean or not DOMAIN_REGEX.match(clean):
        raise DevAuthError("Invalid domain format (example: evil-domain.xyz)", 400)
    clean_type = "allowlist" if rule_type == "allowlist" else "blocklist"
    clean_note = note.strip()[:140]
    now = time.time()

    init_dev_tables(db_path)
    with open_db(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO dev_domain_rules (domain, rule_type, note, created_by, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (clean, clean_type, clean_note, actor["email"], now),
        )
        conn.commit()

    _log_audit(
        actor["email"],
        actor["role"],
        "domain_rule_added",
        f"{clean_type}: {clean}",
        db_path=db_path,
    )
    return list_domain_rules(db_path=db_path)


def delete_domain_rule(
    actor: dict[str, Any],
    domain: str,
    db_path: str | None = None,
) -> list[dict[str, Any]]:
    """Delete a custom domain rule by domain name (Editor or Owner role)."""
    if actor["role"] not in ("owner", "editor"):
        raise DevAuthError("Editor or Owner role required to delete domain rules", 403)
    clean = _clean_domain(domain)
    init_dev_tables(db_path)
    with open_db(db_path) as conn:
        conn.execute("DELETE FROM dev_domain_rules WHERE domain = ?", (clean,))
        conn.commit()

    _log_audit(actor["email"], actor["role"], "domain_rule_removed", f"Removed {clean}", db_path=db_path)
    return list_domain_rules(db_path=db_path)


def get_public_config(db_path: str | None = None) -> dict[str, Any]:
    """Return non-sensitive runtime status flags for the public frontend shell."""
    settings = get_runtime_settings(db_path=db_path)
    return {
        "maintenance_mode": bool(settings["maintenance_mode"]),
        "maintenance_notice_ar": str(settings["maintenance_notice_ar"]),
        "maintenance_notice_en": str(settings["maintenance_notice_en"]),
        "enable_url_sandbox": bool(settings["enable_url_sandbox"]),
        "enable_live_threat_intel": bool(settings["enable_live_threat_intel"]),
        "has_owner_initialized": has_owner_initialized(db_path=db_path),
        "bootstrap_key_configured": bool(os.environ.get("KASHF_DEV_BOOTSTRAP_KEY", "").strip()),
    }


def get_dev_overview(
    actor: dict[str, Any],
    db_path: str | None = None,
) -> dict[str, Any]:
    """Assemble role-filtered Developer Console overview without exposing raw secret values."""
    init_dev_tables(db_path)
    with open_db(db_path) as conn:
        user_rows = conn.execute("SELECT * FROM dev_users ORDER BY created_at ASC").fetchall()
        audit_rows = conn.execute(
            "SELECT id, ts, actor_email, actor_role, action, detail FROM dev_audit_log ORDER BY ts DESC LIMIT 30"
        ).fetchall()
        invite_rows = []
        if actor["role"] == "owner":
            invite_rows = conn.execute(
                "SELECT id, role, note, created_by_email, created_at, expires_at, used_at, used_by_email FROM dev_invites ORDER BY created_at DESC LIMIT 20"
            ).fetchall()

    users_list = []
    for row in user_rows:
        serialized = _serialize_user(row)
        if actor["role"] != "owner" and serialized["id"] != actor["id"]:
            serialized["email"] = "***"
        users_list.append(serialized)

    audit_list = [_serialize_audit_row(r, actor) for r in audit_rows]
    invites_list = [_serialize_invite_row(r) for r in invite_rows]

    api_keys_configured = {
        "GEMINI_API_KEY": bool(os.environ.get("GEMINI_API_KEY", "").strip()),
        "GOOGLE_SAFE_BROWSING_API_KEY": bool(os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()),
        "VIRUSTOTAL_API_KEY": bool(os.environ.get("VIRUSTOTAL_API_KEY", "").strip()),
    }

    return {
        "user": actor,
        "backend_stack": {
            "python_version": platform.python_version(),
            "architecture": "Python FastAPI + SQLite",
            "github_safe_env": True,
            "api_keys_configured": api_keys_configured,
        },
        "settings": get_runtime_settings(db_path=db_path),
        "domain_rules": list_domain_rules(db_path=db_path),
        "users": users_list,
        "invites": invites_list,
        "audit_log": audit_list,
    }
