"""Claude Code plugin packaging and UserPromptSubmit adapter tests (offline)."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from io import BytesIO
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler

import pytest

from little_canary import __version__
from little_canary.server import MAX_REQUEST_BYTES

ROOT = Path(__file__).resolve().parents[1]
MARKETPLACE_FILE = ROOT / ".claude-plugin" / "marketplace.json"
PLUGIN_ROOT = ROOT / "plugins" / "claude-code"
PLUGIN_MANIFEST = PLUGIN_ROOT / ".claude-plugin" / "plugin.json"
HOOKS_FILE = PLUGIN_ROOT / "hooks" / "hooks.json"
HOOK_SCRIPT = PLUGIN_ROOT / "scripts" / "little_canary_user_prompt_submit.py"
sys.path.insert(0, str(HOOK_SCRIPT.parent))

from little_canary_user_prompt_submit import DIRECT_OPENER, evaluate  # noqa: E402


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
    return {"hook_event_name": "UserPromptSubmit", "prompt": prompt, "source": "user"}


def _opener(verdict: dict[str, object]):
    def open_request(request, timeout):
        assert request.full_url == "http://127.0.0.1:18421/check"
        assert timeout == 3
        assert json.loads(request.data) == {"text": _input()["prompt"]}
        return _Response(verdict)

    return open_request


def _exercised(safe: bool, **extra: object) -> dict[str, object]:
    verdict: dict[str, object] = {"safe": safe, "degraded": False, "canary_status": "exercised"}
    verdict.update(extra)
    return verdict


# --- packaging ---------------------------------------------------------------


def test_marketplace_points_at_the_self_contained_plugin_directory() -> None:
    marketplace = json.loads(MARKETPLACE_FILE.read_text())
    (entry,) = marketplace["plugins"]
    assert entry["name"] == "little-canary"
    assert entry["source"] == "./plugins/claude-code"
    # Relative sources resolve against the marketplace root (the repository), not .claude-plugin/.
    assert (ROOT / entry["source"]).resolve() == PLUGIN_ROOT
    assert PLUGIN_MANIFEST.is_file()


def test_repository_root_is_a_marketplace_but_not_a_plugin() -> None:
    # Only the marketplace manifest lives at the repository root. Without a root plugin.json,
    # Claude Code never treats the repository itself as a plugin, so the Gemini CLI files
    # (hooks/hooks.json, gemini-extension.json) are never scanned or copied on install.
    assert sorted(path.name for path in (ROOT / ".claude-plugin").iterdir()) == ["marketplace.json"]
    gemini_hooks = ROOT / "hooks" / "hooks.json"
    assert PLUGIN_ROOT not in gemini_hooks.parents
    assert list(json.loads(gemini_hooks.read_text())["hooks"]) == ["BeforeAgent"]


def test_plugin_manifest_tracks_package_identity() -> None:
    manifest = json.loads(PLUGIN_MANIFEST.read_text())
    assert manifest["name"] == json.loads(MARKETPLACE_FILE.read_text())["plugins"][0]["name"]
    assert manifest["version"] == __version__
    assert manifest["repository"] == "https://github.com/hermes-labs-ai/little-canary"
    # Claude Code loads hooks/hooks.json from the plugin root automatically and refuses to load a
    # plugin whose manifest "hooks" field names that same file again ("Duplicate hooks file").
    assert "hooks" not in manifest
    assert HOOKS_FILE == PLUGIN_ROOT / "hooks" / "hooks.json"


def test_plugin_hooks_register_only_the_prompt_gate_with_a_bounded_timeout() -> None:
    hooks = json.loads(HOOKS_FILE.read_text())["hooks"]
    assert list(hooks) == ["UserPromptSubmit"]
    (matcher,) = hooks["UserPromptSubmit"]
    (hook,) = matcher["hooks"]
    assert hook["type"] == "command"
    assert hook["command"] == 'python3 "${CLAUDE_PLUGIN_ROOT}/scripts/little_canary_user_prompt_submit.py"'
    assert HOOK_SCRIPT.is_file()
    assert 5 <= hook["timeout"] <= 10  # seconds; must exceed the adapter's 5000 ms ceiling


def test_plugin_directory_is_self_contained() -> None:
    # Claude Code copies only the plugin directory into its cache, so every file the hook
    # needs must live under plugins/claude-code and must not reach above it.
    expected = {
        PLUGIN_ROOT / ".claude-plugin" / "plugin.json",
        HOOKS_FILE,
        HOOK_SCRIPT,
    }
    actual = {path for path in PLUGIN_ROOT.rglob("*") if path.is_file() and "__pycache__" not in path.parts}
    assert actual == expected
    for path in (PLUGIN_MANIFEST, HOOKS_FILE):
        assert ".." not in path.read_text()


def test_hook_script_depends_only_on_the_standard_library() -> None:
    # The cached plugin has no access to this repository or to little_canary's dependencies.
    tree = ast.parse(HOOK_SCRIPT.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"__future__", "json", "os", "sys", "typing", "urllib"}


# --- adapter -----------------------------------------------------------------


def test_default_loopback_client_disables_environment_proxies() -> None:
    proxy_handlers = [handler for handler in DIRECT_OPENER.handlers if isinstance(handler, ProxyHandler)]
    assert proxy_handlers == []


def test_exercised_safe_verdict_emits_no_decision() -> None:
    assert evaluate(_input(), {}, opener=_opener(_exercised(True))) == {}


def test_unsafe_verdict_blocks_prompt() -> None:
    result = evaluate(_input(), {}, opener=_opener(_exercised(False)))
    assert result["decision"] == "block"
    assert "before Claude Code started the turn" in result["reason"]


def test_flagged_but_allowed_verdict_is_visible_to_user_without_blocking() -> None:
    result = evaluate(_input(), {}, opener=_opener(_exercised(True, advisory={"flagged": True})))
    assert "decision" not in result
    assert "flagged this prompt" in result["systemMessage"]


@pytest.mark.parametrize("failure_mode, blocked", [("allow", False), ("deny", True)])
def test_degraded_coverage_obeys_explicit_failure_policy(failure_mode: str, blocked: bool) -> None:
    result = evaluate(
        _input(),
        {"LITTLE_CANARY_FAILURE_MODE": failure_mode},
        opener=_opener({"safe": True, "degraded": True, "canary_status": "failed"}),
    )
    assert (result.get("decision") == "block") is blocked
    text = result["reason"] if blocked else result["systemMessage"]
    assert "behavioral coverage was not exercised" in text


def test_transport_failure_is_bounded_and_fail_open_by_default() -> None:
    def open_request(_request, timeout):
        assert timeout == 3
        raise URLError("connection refused")

    result = evaluate(_input(), {}, opener=open_request)
    assert "decision" not in result
    assert result["systemMessage"].startswith("Little Canary screening unavailable: URLError.")
    assert "fail-open" in result["systemMessage"]


def test_transport_failure_can_be_configured_fail_closed() -> None:
    def open_request(_request, timeout):
        raise URLError("connection refused")

    result = evaluate(_input(), {}, opener=open_request)  # default policy is allow
    assert "decision" not in result
    result = evaluate(_input(), {"LITTLE_CANARY_FAILURE_MODE": "deny"}, opener=open_request)
    assert result == {
        "decision": "block",
        "reason": "Little Canary screening unavailable: URLError. Prompt blocked by configured fail-closed policy.",
    }


@pytest.mark.parametrize("failure_mode, blocked", [("allow", False), ("deny", True)])
def test_server_request_ceiling_rejection_follows_failure_policy(failure_mode: str, blocked: bool) -> None:
    # The loopback server refuses JSON bodies above MAX_REQUEST_BYTES with HTTP 413. Such prompts
    # are never screened; the adapter reports the rejection under the configured failure policy.
    assert MAX_REQUEST_BYTES == 64 * 1024
    oversized = "a" * MAX_REQUEST_BYTES

    def open_request(request, timeout):
        assert len(request.data) > MAX_REQUEST_BYTES
        raise HTTPError(request.full_url, 413, "Payload Too Large", None, BytesIO(b"{}"))  # type: ignore[arg-type]

    result = evaluate(_input(oversized), {"LITTLE_CANARY_FAILURE_MODE": failure_mode}, opener=open_request)
    assert (result.get("decision") == "block") is blocked
    text = result["reason"] if blocked else result["systemMessage"]
    assert text.startswith("Little Canary screening unavailable: HTTPError.")


def test_non_loopback_endpoint_is_rejected_without_network_call() -> None:
    def open_request(_request, timeout):
        raise AssertionError("network call must not happen")

    result = evaluate(_input(), {"LITTLE_CANARY_ENDPOINT": "https://example.com/check"}, opener=open_request)
    assert "decision" not in result
    assert "invalid adapter configuration" in result["systemMessage"]


def test_unexpected_hook_event_obeys_failure_policy() -> None:
    def open_request(_request, timeout):
        raise AssertionError("network call must not happen")

    result = evaluate(
        {"hook_event_name": "PreToolUse", "prompt": "x"},
        {"LITTLE_CANARY_FAILURE_MODE": "deny"},
        opener=open_request,
    )
    assert result["decision"] == "block"
    assert "unexpected hook event" in result["reason"]


@pytest.mark.parametrize("body", [b"[]", b"not json", b"{" + b" " * 70000 + b"}"])
def test_malformed_or_oversized_response_is_not_treated_as_pass(body: bytes) -> None:
    def open_request(_request, timeout):
        return _RawResponse(body)

    result = evaluate(_input(), {"LITTLE_CANARY_FAILURE_MODE": "deny"}, opener=open_request)
    assert result["decision"] == "block"


def test_command_protocol_emits_single_claude_hook_json_object() -> None:
    proc = subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)],
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
    assert "decision" not in output
    assert output["systemMessage"].endswith("Claude Code continued because Little Canary is fail-open.")
    assert proc.stderr == ""


def test_command_protocol_never_emits_bare_text_on_malformed_input() -> None:
    proc = subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)],
        input="not json",
        text=True,
        capture_output=True,
        env={"PATH": "/usr/bin:/bin", "LITTLE_CANARY_FAILURE_MODE": "deny"},
        check=True,
    )
    output = json.loads(proc.stdout)
    assert output["decision"] == "block"
    assert proc.stderr == ""


def test_command_protocol_reports_invalid_failure_mode_instead_of_coercing_it() -> None:
    proc = subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)],
        input="not json",
        text=True,
        capture_output=True,
        env={"PATH": "/usr/bin:/bin", "LITTLE_CANARY_FAILURE_MODE": "bogus"},
        check=True,
    )
    output = json.loads(proc.stdout)
    assert "decision" not in output
    assert "invalid adapter configuration (failure mode must be 'allow' or 'deny')" in output["systemMessage"]
    assert proc.stderr == ""
