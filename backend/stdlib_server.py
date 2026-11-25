"""Zero-dependency Python stdlib ThreadingHTTPServer fallback for Kashf × AcadShield AI.

Allows the single Python backend + dist/ React SPA to boot and pass Cloud Run
deployments even in containers without pip/FastAPI/Uvicorn installed.
"""

from __future__ import annotations

import json
import mimetypes
import signal
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from api_router import (
    ALLOWED_CORS_ORIGINS,
    MAX_REQUEST_BODY_BYTES,
    SECURITY_HEADERS,
    ApiError,
    handle_api_request,
    init_all_tables,
    resolve_static_target,
)

mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("image/webp", ".webp")
mimetypes.add_type("image/svg+xml", ".svg")
mimetypes.add_type("application/json", ".json")


class KashfStdlibHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[BaseHTTPRequestHandler],
        dist_dir_getter: Callable[[], Path],
    ) -> None:
        self.dist_dir_getter = dist_dir_getter
        super().__init__(server_address, RequestHandlerClass)


class KashfRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: KashfStdlibHTTPServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _send_common_headers(self) -> None:
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        origin = self.headers.get("Origin")
        if origin in ALLOWED_CORS_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _send_json(self, status_code: int, body: Any, close_conn: bool = False) -> None:
        encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self._send_common_headers()
        if close_conn or status_code == 413:
            self.close_connection = True
            self.send_header("Connection", "close")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(encoded)
            self.wfile.flush()

    def _read_json_body(self) -> Any:
        raw_len = self.headers.get("Content-Length")
        body_bytes = b""
        if raw_len is not None:
            try:
                content_length = int(raw_len)
            except ValueError as exc:
                raise ApiError(400, "Invalid Content-Length header") from exc
            if content_length < 0:
                raise ApiError(400, "Invalid Content-Length header")
            if content_length > MAX_REQUEST_BODY_BYTES:
                if content_length <= 512 * 1024:
                    remaining = content_length
                    while remaining > 0:
                        chunk = self.rfile.read(min(remaining, 65536))
                        if not chunk:
                            break
                        remaining -= len(chunk)
                raise ApiError(413, "Request payload too large (max 128 KB)")
            if content_length > 0:
                body_bytes = self.rfile.read(content_length)
        elif "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            chunks: list[bytes] = []
            total = 0
            while True:
                size_line = self.rfile.readline(64).strip()
                if not size_line:
                    break
                try:
                    chunk_size = int(size_line.split(b";", 1)[0], 16)
                except ValueError as exc:
                    raise ApiError(400, "Invalid chunked encoding") from exc
                if chunk_size < 0:
                    raise ApiError(400, "Invalid chunked encoding")
                if chunk_size == 0:
                    self.rfile.readline(64)
                    break
                total += chunk_size
                if total > MAX_REQUEST_BODY_BYTES:
                    raise ApiError(413, "Request payload too large (max 128 KB)")
                chunk = self.rfile.read(chunk_size)
                if len(chunk) != chunk_size:
                    raise ApiError(400, "Incomplete chunked request body")
                chunks.append(chunk)
                self.rfile.read(2)
            body_bytes = b"".join(chunks)

        if len(body_bytes) > MAX_REQUEST_BODY_BYTES:
            raise ApiError(413, "Request payload too large (max 128 KB)")

        if not body_bytes.strip():
            return {}
        try:
            return json.loads(body_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiError(400, f"Invalid JSON payload: {exc}") from exc

    def _client_ip(self) -> str:
        return self.client_address[0] if self.client_address else "unknown"

    def _handle(self, method: str) -> None:
        parsed = urlsplit(self.path)
        req_path = parsed.path or "/"
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        if req_path == "/api" or req_path.startswith("/api/"):
            try:
                payload = (
                    self._read_json_body()
                    if method in {"POST", "PUT", "PATCH"}
                    else {}
                )
                result = handle_api_request(
                    method=method,
                    path=req_path,
                    query_params=query_params,
                    payload=payload,
                    client_ip=self._client_ip(),
                    auth_header=self.headers.get("Authorization"),
                )
                self._send_json(200, result)
            except ApiError as exc:
                self._send_json(exc.status_code, {"detail": exc.detail}, close_conn=(exc.status_code == 413))
            except Exception:
                self._send_json(500, {"detail": "Internal server error"}, close_conn=True)
            return

        if method not in {"GET", "HEAD"}:
            self._send_json(405, {"detail": "Method not allowed"})
            return

        status, file_path, error_detail = resolve_static_target(
            self.server.dist_dir_getter(), req_path
        )
        if status != 200 or file_path is None:
            self._send_json(status, {"detail": error_detail or "Not found"})
            return

        mime_type, _ = mimetypes.guess_type(str(file_path))
        content_type = mime_type or "application/octet-stream"
        if content_type.startswith("text/") or content_type == "application/javascript":
            content_type = f"{content_type}; charset=utf-8"

        data = file_path.read_bytes()
        self.send_response(200)
        self._send_common_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(data)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._send_common_headers()
        origin = self.headers.get("Origin")
        if origin in ALLOWED_CORS_ORIGINS:
            self.send_header(
                "Access-Control-Allow-Methods",
                "GET, POST, PUT, PATCH, DELETE, OPTIONS",
            )
            self.send_header(
                "Access-Control-Allow-Headers",
                self.headers.get("Access-Control-Request-Headers") or "*",
            )
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        self._handle("GET")

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle("HEAD")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._handle("PUT")

    def do_PATCH(self) -> None:  # noqa: N802
        self._handle("PATCH")

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle("DELETE")


def create_stdlib_server(
    host: str,
    port: int,
    dist_dir_getter: Callable[[], Path] | None = None,
) -> KashfStdlibHTTPServer:
    """Create configured stdlib ThreadingHTTPServer after initializing SQLite tables."""
    init_all_tables()
    getter = dist_dir_getter or (lambda: Path(__file__).resolve().parent.parent / "dist")
    return KashfStdlibHTTPServer((host, port), KashfRequestHandler, getter)


def run_stdlib_server(
    host: str,
    port: int,
    dist_dir_getter: Callable[[], Path] | None = None,
) -> None:
    """Run blocking stdlib HTTP server cleanly until SIGINT/SIGTERM."""
    httpd = create_stdlib_server(host, port, dist_dir_getter=dist_dir_getter)

    def _shutdown(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGTERM, _shutdown)
    except (ValueError, OSError):
        pass

    print(
        f"Kashf × AcadShield Python server (stdlib HTTP fallback) listening on http://{host}:{port}",
        flush=True,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
