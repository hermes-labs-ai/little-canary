"""
little_canary.server — Persistent HTTP server for Little Canary

Keeps the SecurityPipeline warm in memory behind a local HTTP adapter. Runtime
latency depends on the selected model, endpoint, and host; no fixed latency is
asserted.

Endpoints:
    GET  /health  — Pipeline health check (canary availability, mode)
    POST /check   — Analyze text for prompt injection
                    Body: {"text": "..."}
                    Response: serialized PipelineVerdict with coverage state

Usage:
    from little_canary.server import run_server
    run_server(port=18421, mode="advisory", canary_model="qwen2.5:1.5b")
"""

import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Optional

from .pipeline import SecurityPipeline

logger = logging.getLogger("little_canary.server")

# Module-level reference so the handler class can access it.
_pipeline: Optional[SecurityPipeline] = None

# Bound request bodies before allocating or parsing them. This limit covers the
# JSON envelope; the structural filter retains its separate text-length policy.
MAX_REQUEST_BYTES = 64 * 1024


class _CanaryHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the canary detection server."""

    def log_message(self, fmt, *args):
        # Suppress default stderr logging; we use the stdlib logger instead.
        pass

    # -- GET /health --------------------------------------------------------

    def do_GET(self):
        if self.path == "/health":
            health = (
                _pipeline.health_check()
                if _pipeline
                else {
                    "status": "degraded",
                    "ready": False,
                    "degraded": True,
                    "error": "not initialized",
                }
            )
            self._json_response(200, health)
        else:
            self.send_response(404)
            self.end_headers()

    # -- POST /check --------------------------------------------------------

    def do_POST(self):
        if self.path != "/check":
            self.send_response(404)
            self.end_headers()
            return

        content_type = self.headers.get_content_type()
        if content_type != "application/json":
            self._json_response(415, {"error": "content type must be application/json"})
            return

        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            self._json_response(411, {"error": "content length required"})
            return

        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            self._json_response(400, {"error": "invalid content length"})
            return

        if length <= 0:
            self._json_response(400, {"error": "request body must not be empty"})
            return
        if length > MAX_REQUEST_BYTES:
            self._json_response(
                413,
                {"error": "request body too large", "max_request_bytes": MAX_REQUEST_BYTES},
            )
            return

        try:
            raw_body = self.rfile.read(length)
            body = json.loads(raw_body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json_response(400, {"error": "malformed JSON"})
            return

        if not isinstance(body, dict):
            self._json_response(400, {"error": "request body must be a JSON object"})
            return
        if "text" not in body:
            self._json_response(400, {"error": "text is required"})
            return

        text = body["text"]
        if not isinstance(text, str):
            self._json_response(400, {"error": "text must be a string"})
            return
        if text == "":
            self._json_response(400, {"error": "text must not be empty"})
            return
        if _pipeline is None:
            self._json_response(503, {"error": "pipeline unavailable"})
            return

        try:
            verdict = _pipeline.check(text)
        except Exception as exc:
            logger.error("Pipeline check failed (%s)", type(exc).__name__)
            self._json_response(503, {"error": "pipeline check failed"})
            return

        self._json_response(200, verdict.to_dict())

    # -- helpers ------------------------------------------------------------

    def _json_response(self, code: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def create_server(
    port: int = 18421,
    mode: str = "advisory",
    canary_model: str = "qwen2.5:1.5b",
    ollama_url: str = "http://127.0.0.1:11434",
) -> HTTPServer:
    """Create and return an HTTPServer (without starting it).

    Useful for tests that need to control the server lifecycle.
    """
    global _pipeline

    _pipeline = SecurityPipeline(
        canary_model=canary_model,
        ollama_url=ollama_url,
        mode=mode,
    )
    return HTTPServer(("127.0.0.1", port), _CanaryHandler)


def run_server(
    port: int = 18421,
    mode: str = "advisory",
    canary_model: str = "qwen2.5:1.5b",
    ollama_url: str = "http://127.0.0.1:11434",
) -> None:
    """Start the Little Canary HTTP detection server (blocking).

    Parameters
    ----------
    port : int
        TCP port to bind on localhost (default 18421).
    mode : str
        Pipeline mode — ``block``, ``advisory``, or ``full``.
    canary_model : str
        Ollama model tag for the sacrificial canary probe.
    ollama_url : str
        Explicit Ollama origin (loopback by default).
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    server = create_server(
        port=port,
        mode=mode,
        canary_model=canary_model,
        ollama_url=ollama_url,
    )

    assert _pipeline is not None
    health = _pipeline.health_check()
    logger.info("🐤 Little Canary server starting...")
    logger.info("   Mode: %s", mode)
    logger.info("   Model: %s", canary_model)
    logger.info("   Ollama: %s", health.get("endpoint_origin", "invalid"))
    logger.info("   Available: %s", health.get("canary_available", "unknown"))
    logger.info("   Port: %s", port)
    if health.get("ready"):
        logger.info("🐤 Canary server ready on http://127.0.0.1:%d", port)
    else:
        logger.warning(
            "🐤 Canary server listening — DEGRADED on http://127.0.0.1:%d",
            port,
        )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("🐤 Shutting down...")
        server.shutdown()
