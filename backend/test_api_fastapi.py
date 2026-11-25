"""FastAPI single-server contract, static-asset, SPA fallback, and security header tests."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BACKEND_DIR))

try:
    from fastapi.testclient import TestClient  # type: ignore[import-not-found]
    import main  # type: ignore[import-not-found]

    HAS_FASTAPI_TESTCLIENT = True
except Exception:
    TestClient = None  # type: ignore[assignment]
    main = None  # type: ignore[assignment]
    HAS_FASTAPI_TESTCLIENT = False

import asyncio
import db  # noqa: E402
import dev_console  # noqa: E402
import main as backend_main  # noqa: E402


@unittest.skipUnless(HAS_FASTAPI_TESTCLIENT, "fastapi and httpx are required for FastAPI TestClient checks")
class FastApiSingleServerTests(unittest.TestCase):
    def setUp(self) -> None:
        fd, self.temp_db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.prev_db = os.environ.get("KASHF_DB_PATH")
        self.prev_bootstrap = os.environ.get("KASHF_DEV_BOOTSTRAP_KEY")
        os.environ["KASHF_DB_PATH"] = self.temp_db
        os.environ["KASHF_DEV_BOOTSTRAP_KEY"] = "test-bootstrap-secret-2025"

        self.temp_dist = Path(tempfile.mkdtemp(prefix="kashf_dist_"))
        (self.temp_dist / "assets").mkdir(parents=True, exist_ok=True)
        (self.temp_dist / "robot-frames").mkdir(parents=True, exist_ok=True)
        (self.temp_dist / "index.html").write_text(
            "<!doctype html><html><body><div id='root'>Kashf SPA</div></body></html>",
            encoding="utf-8",
        )
        (self.temp_dist / "assets" / "app.js").write_text("console.log('kashf');", encoding="utf-8")
        (self.temp_dist / "robot-frames" / "poster.webp").write_bytes(b"RIFFtestWEBP")

        self.dist_patch = patch.object(main, "DIST_DIR", self.temp_dist)
        self.dist_patch.start()
        self.client = TestClient(main.app)
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        self.dist_patch.stop()
        if self.prev_db is None:
            os.environ.pop("KASHF_DB_PATH", None)
        else:
            os.environ["KASHF_DB_PATH"] = self.prev_db
        if self.prev_bootstrap is None:
            os.environ.pop("KASHF_DEV_BOOTSTRAP_KEY", None)
        else:
            os.environ["KASHF_DEV_BOOTSTRAP_KEY"] = self.prev_bootstrap
        for suffix in ("", "-wal", "-shm"):
            p = f"{self.temp_db}{suffix}"
            if os.path.exists(p):
                os.remove(p)
        for root_dir, dirs, files in os.walk(self.temp_dist, topdown=False):
            for name in files:
                os.remove(os.path.join(root_dir, name))
            for name in dirs:
                os.rmdir(os.path.join(root_dir, name))
        os.rmdir(self.temp_dist)

    def test_static_assets_spa_fallback_and_api_404_isolation(self) -> None:
        root_res = self.client.get("/")
        self.assertEqual(root_res.status_code, 200)
        self.assertIn("Kashf SPA", root_res.text)
        self.assertEqual(root_res.headers.get("x-frame-options"), "DENY")
        self.assertEqual(root_res.headers.get("x-content-type-options"), "nosniff")
        csp = root_res.headers.get("content-security-policy", "")
        self.assertIn("default-src 'self'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)

        js_res = self.client.get("/assets/app.js")
        self.assertEqual(js_res.status_code, 200)
        self.assertIn("console.log('kashf')", js_res.text)

        webp_res = self.client.get("/robot-frames/poster.webp")
        self.assertEqual(webp_res.status_code, 200)
        self.assertEqual(webp_res.content, b"RIFFtestWEBP")

        spa_res = self.client.get("/academic/history")
        self.assertEqual(spa_res.status_code, 200)
        self.assertIn("Kashf SPA", spa_res.text)

        missing_asset = self.client.get("/assets/does-not-exist.js")
        self.assertEqual(missing_asset.status_code, 404)

        missing_api = self.client.get("/api/nonexistent-endpoint")
        self.assertEqual(missing_api.status_code, 404)
        self.assertIn("detail", missing_api.json())

        traversal = self.client.get("/..%2Fbackend%2Fmain.py")
        self.assertIn(traversal.status_code, {200, 404})
        self.assertNotIn("FastAPI", traversal.text)

    def test_api_routes_and_server_ts_contract_parity(self) -> None:
        health = self.client.get("/api/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json(), {"ok": True})

        # Empty message returns 400 (not 422)
        empty = self.client.post("/api/analyze", json={"text": "   "})
        self.assertEqual(empty.status_code, 400)

        # Oversized text > 5000 is truncated safely instead of 422
        long_text = "مبروك ربحت جائزة http://paypa1-secure.xyz/login " + ("a" * 5200)
        analyzed = self.client.post("/api/analyze", json={"text": long_text})
        self.assertEqual(analyzed.status_code, 200)
        analyzed_json = analyzed.json()
        self.assertEqual(analyzed_json["verdict"], "dangerous")
        self.assertIn("ar", analyzed_json["family_warning"])
        self.assertIn("en", analyzed_json["family_warning"])

        # Batch filters empty items and slices to 25 items cleanly
        batch_payload = {"messages": ["", "   "] + [f"Hello team message #{i}" for i in range(30)]}
        batch_res = self.client.post("/api/analyze-batch", json=batch_payload)
        self.assertEqual(batch_res.status_code, 200)
        self.assertEqual(batch_res.json()["total"], 25)

        # Raw text batch parsing in Python (WhatsApp multi-line export)
        raw_batch_res = self.client.post(
            "/api/analyze-batch",
            json={
                "raw_text": (
                    "[11/12/2026, 9:15 PM] Unknown: مبروك ربحت 5000$ اضغط bit.ly/demo\n"
                    "[11/12/2026, 9:16 PM] Ahmed: لا تفتح هذا الرابط ابداً"
                )
            },
        )
        self.assertEqual(raw_batch_res.status_code, 200)
        self.assertEqual(raw_batch_res.json()["total"], 2)

        # SSRF blocked via /api/sandbox-url and /api/inspect-url
        sbx = self.client.post("/api/sandbox-url", json={"url": "http://127.0.0.1:8080/admin"})
        self.assertEqual(sbx.status_code, 200)
        self.assertEqual(sbx.json()["execution_mode"], "blocked_ssrf")

        # Academic + Certificate issue & verify + Dashboard
        acad = self.client.post(
            "/api/academic/analyze",
            json={
                "text": "هذا بحث أكاديمي أصيل يناقش حماية الطلبة من الروابط المزيفة في الجامعات العراقية.",
                "behavior": {
                    "keystrokes": 25,
                    "pasted_chars": 0,
                    "total_chars": 85,
                    "intervals_ms": [90, 140, 210, 120, 175],
                },
            },
        )
        self.assertEqual(acad.status_code, 200)
        self.assertEqual(acad.json()["behavior"]["status"], "human_verified")
        self.assertGreater(acad.json()["behavior"]["interval_std_ms"], 20)

        cert = self.client.post(
            "/api/certificates/issue",
            json={
                "title": "FastAPI Single Server Audit",
                "author": "Test Author",
                "institution": "",
                "text": "Research paper content verifying hash-chain certificate issuance via FastAPI.",
                "originality_score": 92,
            },
        )
        self.assertEqual(cert.status_code, 200)
        cert_id = cert.json()["cert_id"]
        self.assertTrue(cert_id.startswith("ACAD-0001-"))

        verify = self.client.get(f"/api/certificates/verify?q={cert_id}")
        self.assertEqual(verify.status_code, 200)
        self.assertTrue(verify.json()["found"])

        dash = self.client.get("/api/dashboard")
        self.assertEqual(dash.status_code, 200)
        self.assertGreaterEqual(dash.json()["certificates_issued"], 1)

        # DLP, Quiz, Report, Trending, Sandbox/SaaS, Evaluation, Public Config
        dlp = self.client.post("/api/dlp/scan", json={"text": "SECRET_KEY=top_secret_val_999"})
        self.assertEqual(dlp.status_code, 200)
        self.assertGreaterEqual(len(dlp.json()["dlp_findings"]), 1)

        quiz = self.client.get("/api/quiz")
        self.assertEqual(quiz.status_code, 200)
        self.assertEqual(len(quiz.json()["scenarios"]), 20)

        rep = self.client.post(
            "/api/report",
            json={"category": "otp_theft", "score": 150, "fingerprint": "abc12345def67890"},
        )
        self.assertEqual(rep.status_code, 200)
        self.assertTrue(rep.json()["ok"])

        trending = self.client.get("/api/trending")
        self.assertEqual(trending.status_code, 200)
        self.assertGreaterEqual(trending.json()["stats"]["total_reports"], 1)

        # SaaS tenant listing & mutations require RBAC (viewer/editor/owner read, editor/owner create, owner delete)
        self.assertEqual(self.client.get("/api/saas/tenants").status_code, 401)
        self.assertEqual(
            self.client.post(
                "/api/saas/tenants",
                json={"university_name": "Unauthorized Uni", "student_count": 1000, "faculty_count": 50},
            ).status_code,
            401,
        )
        self.assertEqual(self.client.delete("/api/saas/tenants/IQ-UNI-001").status_code, 401)

        owner_auth = dev_console.bootstrap_owner(
            "Owner", "owner@uotechnology.edu.iq", "StrongPass!2025", bootstrap_key="test-bootstrap-secret-2025"
        )
        owner_actor = dev_console.authenticate_token(owner_auth["token"])
        editor_inv = dev_console.create_invite(owner_actor, role="editor", note="Ed")
        viewer_inv = dev_console.create_invite(owner_actor, role="viewer", note="Vw")
        editor_auth = dev_console.claim_invite(editor_inv["invite_token"], "Ed", "ed@uotechnology.edu.iq", "EditorPass!2025")
        viewer_auth = dev_console.claim_invite(viewer_inv["invite_token"], "Vw", "vw@uotechnology.edu.iq", "ViewerPass!2025")

        self.assertEqual(
            self.client.get(
                "/api/saas/tenants",
                headers={"Authorization": f"Bearer {viewer_auth['token']}"},
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                "/api/saas/tenants",
                json={"university_name": "Viewer Blocked", "student_count": 1000, "faculty_count": 50},
                headers={"Authorization": f"Bearer {viewer_auth['token']}"},
            ).status_code,
            403,
        )
        saas = self.client.post(
            "/api/saas/tenants",
            json={"university_name": "الجامعة التكنولوجية", "student_count": 12000, "faculty_count": 500},
            headers={"Authorization": f"Bearer {editor_auth['token']}"},
        )
        self.assertEqual(saas.status_code, 200)
        code = saas.json()["tenants"][0]["tenant_code"]
        self.assertEqual(
            self.client.delete(
                f"/api/saas/tenants/{code}",
                headers={"Authorization": f"Bearer {editor_auth['token']}"},
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.delete(
                f"/api/saas/tenants/{code}",
                headers={"Authorization": f"Bearer {owner_auth['token']}"},
            ).status_code,
            200,
        )

        pub = self.client.get("/api/public-config")
        self.assertEqual(pub.status_code, 200)

    def test_body_size_limit_and_rate_limit_enforcement(self) -> None:
        oversized = self.client.post("/api/dlp/scan", json={"text": "A" * (130 * 1024)})
        self.assertEqual(oversized.status_code, 413)

        with db.get_connection(self.temp_db) as conn:
            now = __import__("time").time()
            conn.executemany(
                "INSERT INTO rate_limits (key, ts) VALUES (?, ?)",
                [("api:testclient", now) for _ in range(30)],
            )
            conn.commit()
        limited = self.client.post("/api/analyze", json={"text": "hello world"})
        self.assertEqual(limited.status_code, 429)


class StdlibHttpServerTests(unittest.TestCase):
    def setUp(self) -> None:
        import threading
        import stdlib_server

        fd, self.temp_db = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.prev_db = os.environ.get("KASHF_DB_PATH")
        self.prev_bootstrap = os.environ.get("KASHF_DEV_BOOTSTRAP_KEY")
        os.environ["KASHF_DB_PATH"] = self.temp_db
        os.environ["KASHF_DEV_BOOTSTRAP_KEY"] = "test-bootstrap-secret-2025"

        self.temp_dist = Path(tempfile.mkdtemp(prefix="kashf_stdlib_dist_"))
        (self.temp_dist / "assets").mkdir(parents=True, exist_ok=True)
        (self.temp_dist / "robot-frames").mkdir(parents=True, exist_ok=True)
        (self.temp_dist / "index.html").write_text(
            "<!doctype html><html><body><div id='root'>Kashf SPA</div></body></html>",
            encoding="utf-8",
        )
        (self.temp_dist / "assets" / "app.js").write_text("console.log('kashf');", encoding="utf-8")
        (self.temp_dist / "robot-frames" / "poster.webp").write_bytes(b"RIFFtestWEBP")

        self.httpd = stdlib_server.create_stdlib_server(
            "127.0.0.1",
            0,
            dist_dir_getter=lambda: self.temp_dist,
        )
        self.base_url = f"http://127.0.0.1:{self.httpd.server_port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        if self.prev_db is None:
            os.environ.pop("KASHF_DB_PATH", None)
        else:
            os.environ["KASHF_DB_PATH"] = self.prev_db
        if self.prev_bootstrap is None:
            os.environ.pop("KASHF_DEV_BOOTSTRAP_KEY", None)
        else:
            os.environ["KASHF_DEV_BOOTSTRAP_KEY"] = self.prev_bootstrap
        for suffix in ("", "-wal", "-shm"):
            p = f"{self.temp_db}{suffix}"
            if os.path.exists(p):
                os.remove(p)
        for root_dir, dirs, files in os.walk(self.temp_dist, topdown=False):
            for name in files:
                os.remove(os.path.join(root_dir, name))
            for name in dirs:
                os.rmdir(os.path.join(root_dir, name))
        os.rmdir(self.temp_dist)

    def _request(
        self,
        method: str,
        path: str,
        json_body: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        import json
        import urllib.error
        import urllib.request

        req_headers = dict(headers or {})
        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
        req = urllib.request.Request(f"{self.base_url}{path}", data=data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
        except urllib.error.HTTPError as err:
            return err.code, {k.lower(): v for k, v in err.headers.items()}, err.read()

    def test_stdlib_static_spa_and_api_contract(self) -> None:
        import json

        status, hdrs, body = self._request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Kashf SPA", body)
        self.assertEqual(hdrs.get("x-frame-options"), "DENY")
        self.assertEqual(hdrs.get("x-content-type-options"), "nosniff")
        csp = hdrs.get("content-security-policy", "")
        self.assertIn("default-src 'self'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)

        status, _, body = self._request("GET", "/assets/app.js")
        self.assertEqual(status, 200)
        self.assertIn(b"console.log('kashf')", body)

        status, _, body = self._request("GET", "/academic/history")
        self.assertEqual(status, 200)
        self.assertIn(b"Kashf SPA", body)

        status, _, _ = self._request("GET", "/assets/missing.js")
        self.assertEqual(status, 404)

        status, _, body = self._request("GET", "/api/nonexistent")
        self.assertEqual(status, 404)
        self.assertIn("detail", json.loads(body))

        status, _, body = self._request("GET", "/..%2Fbackend%2Fmain.py")
        self.assertIn(status, {200, 404})
        self.assertNotIn(b"FastAPI", body)

        status, _, body = self._request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})

        status, _, _ = self._request("POST", "/api/analyze", {"text": "   "})
        self.assertEqual(status, 400)

        status, _, body = self._request(
            "POST",
            "/api/analyze",
            {"text": "مبروك ربحت جائزة http://paypa1-secure.xyz/login"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["verdict"], "dangerous")

        status, _, body = self._request(
            "POST",
            "/api/analyze-batch",
            {"raw_text": "msg 1 http://paypa1-secure.xyz\n\nmsg 2 normal meeting"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["total"], 2)

        status, _, body = self._request("POST", "/api/sandbox-url", {"url": "http://127.0.0.1:8080/admin"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["execution_mode"], "blocked_ssrf")

        # SaaS tenant listing & mutations require RBAC (viewer/editor/owner read, editor/owner create, owner delete)
        status, _, _ = self._request("GET", "/api/saas/tenants")
        self.assertEqual(status, 401)
        status, _, _ = self._request(
            "POST",
            "/api/saas/tenants",
            {"university_name": "Unauthorized Uni", "student_count": 1000, "faculty_count": 50},
        )
        self.assertEqual(status, 401)
        status, _, _ = self._request("DELETE", "/api/saas/tenants/IQ-UNI-001")
        self.assertEqual(status, 401)

        owner_auth = dev_console.bootstrap_owner(
            "Owner", "owner@uotechnology.edu.iq", "StrongPass!2025", bootstrap_key="test-bootstrap-secret-2025"
        )
        owner_actor = dev_console.authenticate_token(owner_auth["token"])
        editor_inv = dev_console.create_invite(owner_actor, role="editor", note="Ed")
        viewer_inv = dev_console.create_invite(owner_actor, role="viewer", note="Vw")
        editor_auth = dev_console.claim_invite(editor_inv["invite_token"], "Ed", "ed@uotechnology.edu.iq", "EditorPass!2025")
        viewer_auth = dev_console.claim_invite(viewer_inv["invite_token"], "Vw", "vw@uotechnology.edu.iq", "ViewerPass!2025")

        status, _, _ = self._request(
            "GET",
            "/api/saas/tenants",
            headers={"Authorization": f"Bearer {viewer_auth['token']}"},
        )
        self.assertEqual(status, 200)

        status, _, _ = self._request(
            "POST",
            "/api/saas/tenants",
            {"university_name": "Viewer Uni", "student_count": 1000, "faculty_count": 50},
            headers={"Authorization": f"Bearer {viewer_auth['token']}"},
        )
        self.assertEqual(status, 403)

        status, _, body = self._request(
            "POST",
            "/api/saas/tenants",
            {"university_name": "الجامعة التكنولوجية", "student_count": 12000, "faculty_count": 500},
            headers={"Authorization": f"Bearer {editor_auth['token']}"},
        )
        self.assertEqual(status, 200)
        tenant_code = json.loads(body)["tenants"][0]["tenant_code"]

        status, _, listed_body = self._request(
            "GET",
            "/api/saas/tenants",
            headers={"Authorization": f"Bearer {viewer_auth['token']}"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(listed_body)["tenants"][0]["tenant_code"], tenant_code)

        status, _, _ = self._request(
            "DELETE",
            f"/api/saas/tenants/{tenant_code}",
            headers={"Authorization": f"Bearer {editor_auth['token']}"},
        )
        self.assertEqual(status, 403)

        status, _, _ = self._request(
            "DELETE",
            f"/api/saas/tenants/{tenant_code}",
            headers={"Authorization": f"Bearer {owner_auth['token']}"},
        )
        self.assertEqual(status, 200)

        status, _, _ = self._request("POST", "/api/dlp/scan", {"text": "A" * (130 * 1024)})
        self.assertEqual(status, 413)

        # Chunked transfer-encoding without Content-Length: valid vs oversized 413 vs malformed 400
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=5)
        small_chunk = b'{"text": "hello chunked"}'
        conn.putrequest("POST", "/api/dlp/scan")
        conn.putheader("Transfer-Encoding", "chunked")
        conn.putheader("Content-Type", "application/json")
        conn.endheaders()
        conn.send(f"{len(small_chunk):x}\r\n".encode("ascii") + small_chunk + b"\r\n0\r\n\r\n")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        conn.close()

        conn2 = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=5)
        big_chunk = b'{"text": "' + (b"B" * (135 * 1024)) + b'"}'
        conn2.putrequest("POST", "/api/dlp/scan")
        conn2.putheader("Transfer-Encoding", "chunked")
        conn2.putheader("Content-Type", "application/json")
        conn2.endheaders()
        try:
            conn2.send(f"{len(big_chunk):x}\r\n".encode("ascii") + big_chunk + b"\r\n0\r\n\r\n")
            resp2 = conn2.getresponse()
            self.assertEqual(resp2.status, 413)
        finally:
            conn2.close()

        with db.get_connection(self.temp_db) as conn:
            now = __import__("time").time()
            conn.executemany(
                "INSERT INTO rate_limits (key, ts) VALUES (?, ?)",
                [("api:127.0.0.1", now) for _ in range(30)],
            )
            conn.commit()
        for method_name, path_name, payload_obj in [
            ("POST", "/api/analyze", {"text": "hello world"}),
            ("GET", "/api/trending", None),
            ("GET", "/api/dashboard", None),
            ("GET", "/api/sandbox/runs", None),
            ("GET", "/api/saas/tenants", None),
            ("GET", "/api/public-config", None),
            ("GET", "/api/dev/overview", None),
            ("POST", "/api/quiz/verify", {"id": "q1", "is_scam": True, "lang": "en"}),
        ]:
            status, _, _ = self._request(method_name, path_name, payload_obj)
            self.assertEqual(status, 429, f"Expected 429 on {method_name} {path_name}")

        # Lightweight static/read endpoints stay responsive without rate-limit blocking
        status, _, _ = self._request("GET", "/api/quiz")
        self.assertEqual(status, 200)
        status, _, _ = self._request("GET", "/api/health")
        self.assertEqual(status, 200)


class AsgiStreamingBodyGuardTests(unittest.TestCase):
    """Verify FastAPI/ASGI SecurityAndBodyLimitMiddleware rejects oversized chunked streams early."""

    def test_streaming_limit_stops_reading_after_max_bytes_without_content_length(self) -> None:
        chunks_delivered = 0
        chunk_size = 32 * 1024

        async def oversized_receive():
            nonlocal chunks_delivered
            chunks_delivered += 1
            return {"type": "http.request", "body": b"X" * chunk_size, "more_body": True}

        sent_messages: list[dict] = []

        async def capture_send(msg: dict) -> None:
            sent_messages.append(msg)

        app_called = False

        async def dummy_asgi_app(scope, receive, send):
            nonlocal app_called
            app_called = True

        middleware = backend_main.SecurityAndBodyLimitMiddleware(dummy_asgi_app, max_body_bytes=128 * 1024)
        scope = {"type": "http", "method": "POST", "path": "/api/dlp/scan", "headers": []}
        asyncio.run(middleware(scope, oversized_receive, capture_send))

        self.assertFalse(app_called)
        self.assertEqual(chunks_delivered, 5)  # 4*32KB=128KB accepted, stopped immediately on 5th chunk (160KB)
        self.assertEqual(sent_messages[0]["status"], 413)
        resp_headers = {k.decode("ascii"): v.decode("latin-1") for k, v in sent_messages[0]["headers"]}
        self.assertIn("default-src 'self'", resp_headers.get("content-security-policy", ""))

    def test_streaming_valid_chunked_payload_replays_cleanly_and_adds_csp(self) -> None:
        events = [
            {"type": "http.request", "body": b'{"text":', "more_body": True},
            {"type": "http.request", "body": b' "safe"}', "more_body": False},
        ]

        async def valid_receive():
            return events.pop(0) if events else {"type": "http.disconnect"}

        sent_messages: list[dict] = []
        replayed_bodies: list[bytes] = []

        async def capture_send(msg: dict) -> None:
            sent_messages.append(msg)

        async def echo_app(scope, receive, send):
            msg = await receive()
            replayed_bodies.append(msg["body"])
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": b'{"ok":true}', "more_body": False})

        middleware = backend_main.SecurityAndBodyLimitMiddleware(echo_app, max_body_bytes=128 * 1024)
        scope = {"type": "http", "method": "POST", "path": "/api/analyze", "headers": []}
        asyncio.run(middleware(scope, valid_receive, capture_send))

        self.assertEqual(replayed_bodies, [b'{"text": "safe"}'])
        self.assertEqual(sent_messages[0]["status"], 200)
        resp_headers = {k.decode("ascii"): v.decode("latin-1") for k, v in sent_messages[0]["headers"]}
        self.assertIn("default-src 'self'", resp_headers.get("content-security-policy", ""))
        self.assertEqual(resp_headers.get("x-frame-options"), "DENY")


if __name__ == "__main__":
    unittest.main(verbosity=2)
