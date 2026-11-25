"""Single-server Python entrypoint for Kashf × AcadShield AI.

Uses FastAPI + Uvicorn when installed and falls back to the zero-dependency
Python stdlib HTTP server (`stdlib_server.py`) in minimal environments.
"""

from __future__ import annotations

import json
import mimetypes
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent
DIST_DIR = PROJECT_ROOT / "dist"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("image/webp", ".webp")
mimetypes.add_type("image/svg+xml", ".svg")
mimetypes.add_type("application/json", ".json")

from api_router import (  # noqa: E402
    ALLOWED_CORS_ORIGINS,
    MAX_REQUEST_BODY_BYTES,
    SECURITY_HEADERS,
    ApiError,
    handle_api_request,
    init_all_tables,
    resolve_server_bind,
    resolve_static_target,
)

async def read_limited_asgi_body(receive: Any, max_bytes: int = MAX_REQUEST_BODY_BYTES) -> tuple[bytes, bool]:
    """Read ASGI request body chunks incrementally without buffering oversized payloads."""
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        msg_type = message.get("type")
        if msg_type == "http.disconnect":
            break
        if msg_type != "http.request":
            continue
        chunk = message.get("body", b"")
        if chunk:
            total += len(chunk)
            if total > max_bytes:
                return b"", True
            chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks), False


class SecurityAndBodyLimitMiddleware:
    """ASGI middleware enforcing streaming body size limits and standard security headers."""

    def __init__(self, app: Any, max_body_bytes: int = MAX_REQUEST_BODY_BYTES) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def _send_json_error(self, send: Any, status_code: int, detail: str) -> None:
        payload = json.dumps({"detail": detail}, ensure_ascii=False).encode("utf-8")
        headers = [
            (b"content-type", b"application/json; charset=utf-8"),
            (b"content-length", str(len(payload)).encode("ascii")),
            *((k.lower().encode("ascii"), v.encode("latin-1")) for k, v in SECURITY_HEADERS.items()),
        ]
        await send({"type": "http.response.start", "status": status_code, "headers": headers})
        await send({"type": "http.response.body", "body": payload, "more_body": False})

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        next_receive = receive
        method = str(scope.get("method", "GET")).upper()
        if method in {"POST", "PUT", "PATCH"}:
            for name, raw_val in scope.get("headers") or ():
                if name.lower() == b"content-length":
                    try:
                        declared_size = int(raw_val.decode("ascii"))
                    except (UnicodeDecodeError, ValueError):
                        await self._send_json_error(send, 400, "Invalid Content-Length header")
                        return
                    if declared_size < 0:
                        await self._send_json_error(send, 400, "Invalid Content-Length header")
                        return
                    if declared_size > self.max_body_bytes:
                        await self._send_json_error(send, 413, "Request payload too large (max 128 KB)")
                        return

            raw_body, too_large = await read_limited_asgi_body(receive, self.max_body_bytes)
            if too_large:
                await self._send_json_error(send, 413, "Request payload too large (max 128 KB)")
                return

            sent_body = False

            async def replay_receive() -> dict[str, Any]:
                nonlocal sent_body
                if not sent_body:
                    sent_body = True
                    return {"type": "http.request", "body": raw_body, "more_body": False}
                return await receive()

            next_receive = replay_receive

        sec_headers = [(k.lower().encode("ascii"), v.encode("latin-1")) for k, v in SECURITY_HEADERS.items()]
        sec_keys = {k for k, _ in sec_headers}

        async def send_with_security_headers(message: dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                existing = [
                    (k, v)
                    for k, v in (message.get("headers") or [])
                    if k.lower() not in sec_keys
                ]
                message = {**message, "headers": existing + sec_headers}
            await send(message)

        await self.app(scope, next_receive, send_with_security_headers)


try:
    from fastapi import FastAPI, HTTPException, Request  # noqa: E402
    from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
    from fastapi.responses import FileResponse, JSONResponse  # noqa: E402

    HAS_FASTAPI = True
except ModuleNotFoundError:
    HAS_FASTAPI = False


if HAS_FASTAPI:

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        init_all_tables()
        yield

    app: FastAPI | None = FastAPI(title="Kashf × AcadShield API", version="3.0.0", lifespan=lifespan)

    app.add_middleware(SecurityAndBodyLimitMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(ALLOWED_CORS_ORIGINS),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    @app.exception_handler(ApiError)
    async def api_error_exception_handler(_request: Request, exc: ApiError):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.api_route(
        "/api/{full_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    )
    async def api_dispatch(request: Request, full_path: str):
        payload: Any = {}
        if request.method in {"POST", "PUT", "PATCH"}:
            raw_body = await request.body()
            if raw_body.strip():
                try:
                    payload = json.loads(raw_body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ApiError(400, f"Invalid JSON payload: {exc}") from exc

        client_ip = request.client.host if request.client and request.client.host else "unknown"
        return handle_api_request(
            method=request.method,
            path=f"/api/{full_path}",
            query_params=dict(request.query_params),
            payload=payload,
            client_ip=client_ip,
            auth_header=request.headers.get("authorization"),
        )

    def _serve_spa_or_asset(full_path: str):
        status, target_file, error_detail = resolve_static_target(DIST_DIR, full_path)
        if status == 503:
            return JSONResponse(status_code=503, content={"detail": error_detail})
        if status != 200 or target_file is None:
            raise HTTPException(status_code=status, detail=error_detail or "Not found")
        if target_file.name == "index.html":
            return FileResponse(target_file, media_type="text/html")
        return FileResponse(target_file)

    @app.get("/", include_in_schema=False)
    def serve_spa_root():
        return _serve_spa_or_asset("")

    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_spa_fallback(full_path: str):
        return _serve_spa_or_asset(full_path)

else:
    app = None


if __name__ == "__main__":
    bind_host, bind_port = resolve_server_bind()
    if HAS_FASTAPI and app is not None:
        try:
            import uvicorn

            uvicorn.run(app, host=bind_host, port=bind_port)
        except ModuleNotFoundError:
            from stdlib_server import run_stdlib_server

            run_stdlib_server(bind_host, bind_port, dist_dir_getter=lambda: DIST_DIR)
    else:
        from stdlib_server import run_stdlib_server

        run_stdlib_server(bind_host, bind_port, dist_dir_getter=lambda: DIST_DIR)
