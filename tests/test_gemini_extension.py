from __future__ import annotations

import json
import subprocess
import sys
from io import BytesIO
from pathlib import Path
from urllib.error import URLError
from urllib.request import ProxyHandler

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from little_canary_before_agent import DIRECT_OPENER, evaluate  # noqa: E402


class _Response:
    def __init__(self, body: dict[str, object]):
        self._body = BytesIO(json.dumps(body).encode())

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, size: int) -> bytes:
        return self._body.read(size)


class _RawResponse(_Response):
    def __init__(self, body: bytes):
        self._body = BytesIO(body)


def _input(prompt: str = "summarize this") -> dict[str, object]:
    return {"hook_event_name": "BeforeAgent", "prompt": prompt}


def test_default_loopback_client_disables_environment_proxies() -> None:
    proxy_handlers = [handler for handler in DIRECT_OPENER.handlers if isinstance(handler, ProxyHandler)]
    assert proxy_handlers == []


def _opener(verdict: dict[str, object]):
    def open_request(request, timeout):
        assert request.full_url == "http://127.0.0.1:18421/check"
        assert timeout == 3
        assert json.loads(request.data) == {"text": _input()["prompt"]}
        return _Response(verdict)

    return open_request


def test_exercised_safe_verdict_allows_agent() -> None:
    result = evaluate(
        _input(),
        {},
        opener=_opener({"safe": True, "degraded": False, "canary_status": "exercised"}),
    )
    assert result == {
        "decision": "allow",
        "reason": "Little Canary allowed this prompt after exercised screening.",
    }


def test_unsafe_verdict_denies_agent() -> None:
    result = evaluate(
        _input(),
        {},
        opener=_opener({"safe": False, "degraded": False, "canary_status": "exercised"}),
    )
    assert result["decision"] == "deny"
    assert "before the Gemini agent started" in result["reason"]


@pytest.mark.parametrize("failure_mode, expected", [("allow", "allow"), ("deny", "deny")])
def test_degraded_coverage_obeys_explicit_failure_policy(failure_mode: str, expected: str) -> None:
    result = evaluate(
        _input(),
        {"LITTLE_CANARY_FAILURE_MODE": failure_mode},
        opener=_opener({"safe": True, "degraded": True, "canary_status": "failed"}),
    )
    assert result["decision"] == expected
    assert "coverage was not exercised" in result["reason"]


def test_transport_failure_is_bounded_and_fail_open_by_default() -> None:
    def unavailable(_request, timeout):
        assert timeout == 3
        raise URLError("offline")

    result = evaluate(_input(), {}, opener=unavailable)
    assert result["decision"] == "allow"
    assert "fail-open" in result["reason"]
    assert "continued" in result["systemMessage"]


def test_transport_failure_can_be_configured_fail_closed() -> None:
    def unavailable(_request, timeout):
        assert timeout == 3
        raise URLError("offline")

    result = evaluate(
        _input(),
        {"LITTLE_CANARY_FAILURE_MODE": "deny"},
        opener=unavailable,
    )
    assert result["decision"] == "deny"
    assert "configured fail-closed policy" in result["reason"]


def test_non_loopback_endpoint_is_rejected_without_network_call() -> None:
    result = evaluate(_input(), {"LITTLE_CANARY_ENDPOINT": "https://example.com/check"})
    assert result["decision"] == "allow"
    assert "invalid adapter configuration" in result["reason"]


def test_invalid_endpoint_obeys_fail_closed_policy() -> None:
    result = evaluate(
        _input(),
        {
            "LITTLE_CANARY_ENDPOINT": "https://example.com/check",
            "LITTLE_CANARY_FAILURE_MODE": "deny",
        },
    )
    assert result["decision"] == "deny"


@pytest.mark.parametrize("body", [b"not-json", b"x" * (64 * 1024 + 1)])
def test_malformed_or_oversized_response_is_not_treated_as_pass(body: bytes) -> None:
    result = evaluate(_input(), {}, opener=lambda *_args, **_kwargs: _RawResponse(body))
    assert result["decision"] == "allow"
    assert "screening unavailable" in result["reason"]
    assert "exercised screening" not in result["reason"]


def test_command_protocol_emits_single_gemini_hook_json_object() -> None:
    hook = ROOT / "scripts" / "little_canary_before_agent.py"
    proc = subprocess.run(
        [sys.executable, str(hook)],
        input=json.dumps(_input()),
        text=True,
        capture_output=True,
        env={
            "PATH": "/usr/bin:/bin",
            "LITTLE_CANARY_ENDPOINT": "https://example.com/check",
            "LITTLE_CANARY_TIMEOUT_MS": "100",
        },
        check=True,
    )
    output = json.loads(proc.stdout)
    assert output["decision"] == "allow"
    assert output["reason"].endswith("configured fail-open policy.")
    assert proc.stderr == ""
