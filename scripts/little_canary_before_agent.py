#!/usr/bin/env python3
"""Gemini CLI BeforeAgent adapter for Little Canary's loopback HTTP server."""

from __future__ import annotations

import json
import os
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

DEFAULT_ENDPOINT = "http://127.0.0.1:18421/check"
DEFAULT_TIMEOUT_MS = 3000
MAX_HOOK_INPUT_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
DIRECT_OPENER = build_opener(ProxyHandler({}))


def _output(decision: str, reason: str, *, system_message: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"decision": decision, "reason": reason}
    if system_message:
        result["systemMessage"] = system_message
    return result


def _failure(reason: str, failure_mode: str) -> dict[str, Any]:
    message = f"Little Canary screening unavailable: {reason}."
    if failure_mode == "deny":
        return _output("deny", f"{message} Prompt denied by configured fail-closed policy.")
    return _output(
        "allow",
        f"{message} Prompt allowed by configured fail-open policy.",
        system_message=f"{message} Gemini CLI continued because Little Canary is fail-open.",
    )


def _failure_mode(env: dict[str, str]) -> str:
    failure_mode = env.get("LITTLE_CANARY_FAILURE_MODE", "allow").strip().lower()
    if failure_mode not in {"allow", "deny"}:
        raise ValueError("failure mode must be 'allow' or 'deny'")
    return failure_mode


def _settings(env: dict[str, str]) -> tuple[str, int]:
    endpoint = env.get("LITTLE_CANARY_ENDPOINT", DEFAULT_ENDPOINT)
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.path != "/check"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("endpoint must be an HTTP loopback /check URL without credentials or query data")

    try:
        timeout_ms = int(env.get("LITTLE_CANARY_TIMEOUT_MS", str(DEFAULT_TIMEOUT_MS)))
    except ValueError as exc:
        raise ValueError("timeout must be an integer from 100 to 5000 milliseconds") from exc
    if not 100 <= timeout_ms <= 5000:
        raise ValueError("timeout must be an integer from 100 to 5000 milliseconds")

    return endpoint, timeout_ms


def _read_json_response(response: Any) -> dict[str, Any]:
    payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ValueError("response exceeded 65536 bytes")
    decoded = json.loads(payload)
    if not isinstance(decoded, dict):
        raise ValueError("response was not a JSON object")
    return decoded


def evaluate(
    hook_input: dict[str, Any],
    env: dict[str, str],
    *,
    opener: Any = DIRECT_OPENER.open,
) -> dict[str, Any]:
    try:
        failure_mode = _failure_mode(env)
    except ValueError as exc:
        return _failure(f"invalid adapter configuration ({exc})", "allow")
    try:
        endpoint, timeout_ms = _settings(env)
    except ValueError as exc:
        return _failure(f"invalid adapter configuration ({exc})", failure_mode)

    if hook_input.get("hook_event_name") != "BeforeAgent":
        return _failure("unexpected hook event", failure_mode)
    prompt = hook_input.get("prompt")
    if not isinstance(prompt, str):
        return _failure("prompt was not a string", failure_mode)

    request = Request(
        endpoint,
        data=json.dumps({"text": prompt}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with opener(request, timeout=timeout_ms / 1000) as response:
            verdict = _read_json_response(response)
    except (
        HTTPError,
        URLError,
        TimeoutError,
        OSError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        return _failure(type(exc).__name__, failure_mode)

    safe = verdict.get("safe")
    degraded = verdict.get("degraded")
    canary_status = verdict.get("canary_status")
    if not isinstance(safe, bool) or not isinstance(degraded, bool) or not isinstance(canary_status, str):
        return _failure("verdict omitted required coverage fields", failure_mode)
    if not safe:
        return _output("deny", "Little Canary rejected this prompt before the Gemini agent started.")
    if degraded or canary_status != "exercised":
        return _failure("behavioral coverage was not exercised", failure_mode)

    advisory = verdict.get("advisory")
    if isinstance(advisory, dict) and advisory.get("flagged") is True:
        return _output(
            "allow",
            "Little Canary allowed this prompt with an advisory.",
            system_message="Little Canary flagged this prompt but the server's routing policy allowed it.",
        )
    return _output("allow", "Little Canary allowed this prompt after exercised screening.")


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_HOOK_INPUT_BYTES + 1)
    failure_mode = os.environ.get("LITTLE_CANARY_FAILURE_MODE", "allow").strip().lower()
    if failure_mode not in {"allow", "deny"}:
        failure_mode = "allow"
    if len(raw) > MAX_HOOK_INPUT_BYTES:
        result = _failure("hook input exceeded 1048576 bytes", failure_mode)
    else:
        try:
            hook_input = json.loads(raw)
            if not isinstance(hook_input, dict):
                raise ValueError("hook input was not a JSON object")
            result = evaluate(hook_input, dict(os.environ))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            result = _failure(str(exc), failure_mode)
    sys.stdout.write(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
