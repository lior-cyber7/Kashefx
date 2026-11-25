"""Unit & security tests for Python Developer Console RBAC, invite links, domain rules, and runtime thresholds."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dev_console  # noqa: E402
from analyzer import analyze_message  # noqa: E402
from url_inspector import inspect_url_forensics  # noqa: E402


def _assert_raises_status(fn, expected_status: int) -> None:
    try:
        fn()
    except dev_console.DevAuthError as exc:
        assert exc.status_code == expected_status, f"Expected HTTP {expected_status}, got {exc.status_code}: {exc}"
        return
    raise AssertionError(f"Expected DevAuthError({expected_status}) but succeeded")


def test_dev_console_rbac_and_invites() -> None:
    fd, temp_db = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    prev_bootstrap_key = os.environ.pop("KASHF_DEV_BOOTSTRAP_KEY", None)
    try:
        assert dev_console.has_owner_initialized(db_path=temp_db) is False

        # 0. Bootstrap must be blocked when KASHF_DEV_BOOTSTRAP_KEY is not configured
        _assert_raises_status(
            lambda: dev_console.bootstrap_owner(
                name="Hydar Najah",
                email="hydrnjah52@gmail.com",
                password="StrongPassword!2025",
                db_path=temp_db,
            ),
            503,
        )

        # Configure bootstrap key & reject wrong key
        os.environ["KASHF_DEV_BOOTSTRAP_KEY"] = "test-bootstrap-secret-2025"
        _assert_raises_status(
            lambda: dev_console.bootstrap_owner(
                name="Hydar Najah",
                email="hydrnjah52@gmail.com",
                password="StrongPassword!2025",
                bootstrap_key="wrong-key",
                db_path=temp_db,
            ),
            403,
        )

        # 1. Owner bootstrap succeeds once with valid key, then locks out
        owner_auth = dev_console.bootstrap_owner(
            name="Hydar Najah",
            email="hydrnjah52@gmail.com",
            password="StrongPassword!2025",
            bootstrap_key="test-bootstrap-secret-2025",
            db_path=temp_db,
        )
        assert owner_auth["user"]["role"] == "owner"
        assert owner_auth["token"]
        assert dev_console.has_owner_initialized(db_path=temp_db) is True

        _assert_raises_status(
            lambda: dev_console.bootstrap_owner(
                "Other",
                "other@example.com",
                "Password!123",
                bootstrap_key="test-bootstrap-secret-2025",
                db_path=temp_db,
            ),
            409,
        )

        # 2. Authenticate owner & create editor + viewer single-use invites
        owner_actor = dev_console.authenticate_token(f"Bearer {owner_auth['token']}", db_path=temp_db)
        editor_inv = dev_console.create_invite(owner_actor, role="editor", note="Senior Dev", db_path=temp_db)
        viewer_inv = dev_console.create_invite(owner_actor, role="viewer", note="Reviewer", db_path=temp_db)
        assert editor_inv["invite_token"].startswith("kdev_")
        assert viewer_inv["role"] == "viewer"

        # 3. Claim invites (single-use check)
        editor_auth = dev_console.claim_invite(
            editor_inv["invite_token"],
            name="Ali Editor",
            email="ali@uotechnology.edu.iq",
            password="EditorPass!2025",
            db_path=temp_db,
        )
        assert editor_auth["user"]["role"] == "editor"
        _assert_raises_status(
            lambda: dev_console.claim_invite(
                editor_inv["invite_token"],
                name="Replay",
                email="replay@example.com",
                password="EditorPass!2025",
                db_path=temp_db,
            ),
            409,
        )

        viewer_auth = dev_console.claim_invite(
            viewer_inv["invite_token"],
            name="Noor Viewer",
            email="noor@uotechnology.edu.iq",
            password="ViewerPass!2025",
            db_path=temp_db,
        )
        assert viewer_auth["user"]["role"] == "viewer"

        # 4. Enforce RBAC: viewer cannot change settings, add domain rules, or create invites
        viewer_actor = dev_console.authenticate_token(viewer_auth["token"], db_path=temp_db)
        _assert_raises_status(
            lambda: dev_console.update_runtime_settings(viewer_actor, {"suspicious_threshold": 25}, db_path=temp_db),
            403,
        )
        _assert_raises_status(
            lambda: dev_console.upsert_domain_rule(viewer_actor, "bad-example.xyz", "blocklist", db_path=temp_db),
            403,
        )
        _assert_raises_status(
            lambda: dev_console.create_invite(viewer_actor, "viewer", db_path=temp_db),
            403,
        )

        # 5. Editor CAN edit runtime settings & domain rules, CANNOT create invites or edit team roles
        editor_actor = dev_console.authenticate_token(editor_auth["token"], db_path=temp_db)
        updated_settings = dev_console.update_runtime_settings(
            editor_actor,
            {"suspicious_threshold": 35, "dangerous_threshold": 70, "maintenance_mode": True},
            db_path=temp_db,
        )
        assert updated_settings["suspicious_threshold"] == 35
        assert updated_settings["dangerous_threshold"] == 70
        assert updated_settings["maintenance_mode"] is True

        rules = dev_console.upsert_domain_rule(
            editor_actor,
            domain="https://phish-custom-demo.org/login",
            rule_type="blocklist",
            note="Manual SOC hit",
            db_path=temp_db,
        )
        assert any(r["domain"] == "phish-custom-demo.org" and r["rule_type"] == "blocklist" for r in rules)

        _assert_raises_status(
            lambda: dev_console.create_invite(editor_actor, "viewer", db_path=temp_db),
            403,
        )

        # 6. Overview hides secrets & exposes only boolean API key readiness
        overview = dev_console.get_dev_overview(owner_actor, db_path=temp_db)
        assert overview["backend_stack"]["github_safe_env"] is True
        assert all(isinstance(v, bool) for v in overview["backend_stack"]["api_keys_configured"].values())
        assert len(overview["users"]) == 3
        assert len(overview["audit_log"]) >= 5

        # 7. Owner revokes viewer access; viewer token immediately stops working
        dev_console.update_developer_access(
            owner_actor,
            target_user_id=viewer_auth["user"]["id"],
            active=False,
            db_path=temp_db,
        )
        _assert_raises_status(
            lambda: dev_console.authenticate_token(viewer_auth["token"], db_path=temp_db),
            403,
        )
        _assert_raises_status(
            lambda: dev_console.login_developer("noor@uotechnology.edu.iq", "ViewerPass!2025", db_path=temp_db),
            403,
        )
    finally:
        if prev_bootstrap_key is None:
            os.environ.pop("KASHF_DEV_BOOTSTRAP_KEY", None)
        else:
            os.environ["KASHF_DEV_BOOTSTRAP_KEY"] = prev_bootstrap_key
        if os.path.exists(temp_db):
            os.remove(temp_db)


def test_custom_domain_rules_and_thresholds_affect_analyzer() -> None:
    fd, temp_db = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    orig_get_rules = dev_console.get_domain_rules_map
    orig_get_settings = dev_console.get_runtime_settings
    prev_bootstrap_key = os.environ.get("KASHF_DEV_BOOTSTRAP_KEY")
    try:
        os.environ["KASHF_DEV_BOOTSTRAP_KEY"] = "test-bootstrap-secret-2025"
        owner = dev_console.bootstrap_owner(
            "Owner",
            "owner@kashf.iq",
            "OwnerPass!2025",
            bootstrap_key="test-bootstrap-secret-2025",
            db_path=temp_db,
        )
        actor = dev_console.authenticate_token(owner["token"], db_path=temp_db)
        dev_console.upsert_domain_rule(actor, "blocked-by-dev.com", "blocklist", "Test block", db_path=temp_db)
        dev_console.upsert_domain_rule(actor, "trusted-campus-partner.org", "allowlist", "Partner", db_path=temp_db)

        dev_console.get_domain_rules_map = lambda db_path=None: orig_get_rules(db_path=temp_db)  # type: ignore[assignment]
        dev_console.get_runtime_settings = lambda db_path=None: orig_get_settings(db_path=temp_db)  # type: ignore[assignment]

        blocked_url = inspect_url_forensics("https://blocked-by-dev.com/portal")
        assert blocked_url["custom_blocklisted"] is True
        assert blocked_url["classification"] == "malicious"

        allowed_url = inspect_url_forensics("https://trusted-campus-partner.org/notices")
        assert allowed_url["custom_allowlisted"] is True
        assert allowed_url["classification"] == "no_known_threat"

        msg_res = analyze_message("يرجى مراجعة الرابط https://blocked-by-dev.com/portal")
        assert msg_res["score"] >= 55
        assert any(r["id"] == "custom_domain_blocklist" for r in msg_res["reasons"])
    finally:
        if prev_bootstrap_key is None:
            os.environ.pop("KASHF_DEV_BOOTSTRAP_KEY", None)
        else:
            os.environ["KASHF_DEV_BOOTSTRAP_KEY"] = prev_bootstrap_key
        dev_console.get_domain_rules_map = orig_get_rules  # type: ignore[assignment]
        dev_console.get_runtime_settings = orig_get_settings  # type: ignore[assignment]
        if os.path.exists(temp_db):
            os.remove(temp_db)


if __name__ == "__main__":
    test_dev_console_rbac_and_invites()
    print("PASS: test_dev_console_rbac_and_invites")
    test_custom_domain_rules_and_thresholds_affect_analyzer()
    print("PASS: test_custom_domain_rules_and_thresholds_affect_analyzer")
    print("All Stage 6 Developer Console tests passed.")
