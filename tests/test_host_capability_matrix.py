"""Host capability matrix acceptance tests (offline, no model call).

The matrix in ``docs/host-capability-matrix.json`` is a set of claims about
what seven hosts can do with an inbound prompt. These tests exist so that a
claim cannot drift away from the artifact that is supposed to back it: every
row that says Little Canary ships an adapter has to point at a real file that
registers the named event, every row that says a host cannot refuse a prompt
has to not ship a blocking adapter for it, and the Claude Code / Codex adapter
has to stay inside the wire schema Codex actually accepts.
"""

from __future__ import annotations

import json
import sys
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.error import URLError

import pytest

from little_canary import __version__

ROOT = Path(__file__).resolve().parents[1]
MATRIX_FILE = ROOT / "docs" / "host-capability-matrix.json"
MATRIX_DOC = ROOT / "docs" / "host-capability-matrix.md"
README = ROOT / "README.md"
EVIDENCE_DIR = ROOT / "docs" / "host-evidence"
CODEX_SCHEMA_FILE = EVIDENCE_DIR / "codex-0.154.0-user-prompt-submit.command.output.schema.json"
COPILOT_EVIDENCE_FILE = EVIDENCE_DIR / "copilot-cli-1.0.84-5-hook-outputs.d.ts"

CLAUDE_HOOK_SCRIPT = ROOT / "plugins" / "claude-code" / "scripts" / "little_canary_user_prompt_submit.py"
sys.path.insert(0, str(CLAUDE_HOOK_SCRIPT.parent))

from little_canary_user_prompt_submit import evaluate as claude_evaluate  # noqa: E402

MATRIX = json.loads(MATRIX_FILE.read_text())
HOSTS = {host["id"]: host for host in MATRIX["hosts"]}
HOST_IDS = sorted(HOSTS)

# Hosts whose inbound adapter is a file-registered command hook, and the
# manifest plus event name each one has to register.
COMMAND_HOOK_MANIFESTS = {
    "claude-code": (Path("plugins/claude-code/hooks/hooks.json"), "UserPromptSubmit"),
    "codex-cli": (Path("plugins/claude-code/hooks/hooks.json"), "UserPromptSubmit"),
    "gemini-cli": (Path("hooks/hooks.json"), "BeforeAgent"),
}


class _Response:
    def __init__(self, body: dict[str, Any]):
        self._body = BytesIO(json.dumps(body).encode())

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def read(self, size: int) -> bytes:
        return self._body.read(size)


def _opener_returning(body: dict[str, Any]):
    def _open(_request: Any, timeout: float | None = None) -> _Response:
        return _Response(body)

    return _open


def _opener_raising(exc: Exception):
    def _open(_request: Any, timeout: float | None = None):
        raise exc

    return _open


# --- matrix shape -------------------------------------------------------


def test_matrix_declares_its_schema_and_matches_the_package_version():
    assert MATRIX["schema"] == "little-canary-host-capability-matrix/v1"
    assert MATRIX["little_canary_version"] == __version__


def test_matrix_host_ids_are_unique():
    ids = [host["id"] for host in MATRIX["hosts"]]
    assert sorted(ids) == sorted(set(ids))


@pytest.mark.parametrize("host_id", HOST_IDS)
def test_every_host_row_is_complete(host_id):
    host = HOSTS[host_id]
    for key in ("name", "observed_version", "doc_anchor", "inbound", "outbound_tool_execution", "caveats"):
        assert key in host, f"{host_id} is missing {key}"
    inbound = host["inbound"]
    for key in ("shipped", "event", "interception_point", "deny_channel", "runtime_certified", "runtime_evidence"):
        assert key in inbound, f"{host_id}.inbound is missing {key}"
    assert isinstance(inbound["shipped"], bool)
    assert isinstance(inbound["deny_channel"], bool)
    assert isinstance(inbound["runtime_certified"], bool)
    assert host["caveats"], f"{host_id} records no caveats"


@pytest.mark.parametrize("host_id", HOST_IDS)
def test_a_certified_row_carries_its_evidence(host_id):
    """`runtime_certified` is a claim; it has to name what was observed."""
    inbound = HOSTS[host_id]["inbound"]
    assert inbound["runtime_evidence"].strip(), f"{host_id} claims a status with no evidence text"
    if inbound["runtime_certified"]:
        assert inbound["shipped"], f"{host_id} cannot be runtime certified without a shipped adapter"


# --- claims must match shipped artifacts --------------------------------


@pytest.mark.parametrize("host_id", HOST_IDS)
def test_shipped_claim_matches_the_filesystem(host_id):
    host = HOSTS[host_id]
    artifact = host["shipped_artifact"]
    if host["inbound"]["shipped"] or host["outbound_tool_execution"]["shipped"]:
        assert artifact, f"{host_id} claims a shipped adapter but names no artifact"
        assert (ROOT / artifact).exists(), f"{host_id} names a missing artifact: {artifact}"
    else:
        assert artifact is None, f"{host_id} ships nothing but names {artifact}"


@pytest.mark.parametrize("host_id", sorted(COMMAND_HOOK_MANIFESTS))
def test_command_hook_hosts_register_their_declared_event(host_id):
    manifest_path, event = COMMAND_HOOK_MANIFESTS[host_id]
    assert HOSTS[host_id]["inbound"]["event"] == event
    manifest = json.loads((ROOT / manifest_path).read_text())
    assert event in manifest["hooks"], f"{manifest_path} does not register {event}"
    entries = manifest["hooks"][event]
    assert entries and entries[0]["hooks"], f"{manifest_path} registers {event} with no command"


def test_no_copilot_artifact_is_shipped():
    """Copilot cannot refuse a prompt, so nothing may imply that it can."""
    copilot = HOSTS["github-copilot"]
    assert copilot["inbound"]["deny_channel"] is False
    assert copilot["inbound"]["shipped"] is False
    assert copilot["shipped_artifact"] is None
    assert not (ROOT / ".github" / "hooks").exists(), "a .github/hooks manifest would be a Copilot hook claim"


def test_hermes_agent_is_the_only_outbound_tool_gate():
    """Inbound screening and outbound tool blocking stay distinct."""
    shipping_outbound = [
        host_id for host_id, host in HOSTS.items() if host["outbound_tool_execution"]["shipped"]
    ]
    assert shipping_outbound == ["hermes-agent"]
    hermes = HOSTS["hermes-agent"]
    assert hermes["inbound"]["deny_channel"] is False, "pre_llm_call has no deny channel"
    assert hermes["outbound_tool_execution"]["host_event"] == "pre_tool_call"


@pytest.mark.parametrize("host_id", HOST_IDS)
def test_a_host_without_a_deny_channel_declares_no_deny_wire(host_id):
    inbound = HOSTS[host_id]["inbound"]
    if inbound["deny_channel"]:
        assert inbound["deny_wire"], f"{host_id} claims a deny channel but describes no wire form"
    else:
        assert inbound.get("deny_wire") is None, f"{host_id} has no deny channel but names a deny wire"


# --- Codex wire compatibility -------------------------------------------


def _codex_schema() -> dict[str, Any]:
    return json.loads(CODEX_SCHEMA_FILE.read_text())


def test_vendored_codex_schema_is_the_blocking_contract():
    schema = _codex_schema()
    assert schema["additionalProperties"] is False
    assert schema["definitions"]["BlockDecisionWire"]["enum"] == ["block"]
    assert "decision" in schema["properties"]


def _claude_adapter_outputs() -> list[dict[str, Any]]:
    """Every distinct object shape the shipped adapter can emit."""
    env = {"LITTLE_CANARY_ENDPOINT": "http://127.0.0.1:18421/check"}
    hook_input = {"hook_event_name": "UserPromptSubmit", "prompt": "hello"}
    exercised = {"safe": True, "degraded": False, "canary_status": "exercised"}
    outputs = [
        # refused
        claude_evaluate(
            hook_input,
            env,
            opener=_opener_returning({"safe": False, "degraded": False, "canary_status": "exercised"}),
        ),
        # clean pass
        claude_evaluate(hook_input, env, opener=_opener_returning(exercised)),
        # flagged but routed through
        claude_evaluate(
            hook_input,
            env,
            opener=_opener_returning({**exercised, "advisory": {"flagged": True}}),
        ),
        # fail-open on a transport error
        claude_evaluate(hook_input, env, opener=_opener_raising(URLError("down"))),
        # fail-closed on a transport error
        claude_evaluate(
            hook_input,
            {**env, "LITTLE_CANARY_FAILURE_MODE": "deny"},
            opener=_opener_raising(URLError("down")),
        ),
        # coverage that never ran
        claude_evaluate(
            hook_input,
            env,
            opener=_opener_returning({"safe": True, "degraded": True, "canary_status": "failed"}),
        ),
    ]
    return outputs


def test_adapter_emits_a_block_and_a_bare_allow():
    outputs = _claude_adapter_outputs()
    assert outputs[0]["decision"] == "block"
    assert outputs[1] == {}
    assert outputs[4]["decision"] == "block"


@pytest.mark.parametrize("index", range(6))
def test_every_adapter_output_validates_against_the_codex_schema(index):
    """Codex sets additionalProperties:false, so an extra key breaks Codex."""
    schema = _codex_schema()
    allowed = set(schema["properties"])
    output = _claude_adapter_outputs()[index]
    extra = set(output) - allowed
    assert not extra, f"adapter emits {extra}, which Codex rejects"
    if "decision" in output:
        assert output["decision"] in schema["definitions"]["BlockDecisionWire"]["enum"]
    for key in ("reason", "systemMessage", "stopReason"):
        if key in output:
            assert isinstance(output[key], str)


# --- documentation consistency ------------------------------------------


@pytest.mark.parametrize("host_id", HOST_IDS)
def test_every_host_has_a_readme_section(host_id):
    assert HOSTS[host_id]["doc_anchor"] in README.read_text(), f"README has no section for {host_id}"


@pytest.mark.parametrize("host_id", HOST_IDS)
def test_every_host_is_named_in_the_matrix_page(host_id):
    assert HOSTS[host_id]["name"] in MATRIX_DOC.read_text()


def test_matrix_page_and_evidence_files_are_present():
    assert MATRIX_DOC.exists()
    assert CODEX_SCHEMA_FILE.exists()
    assert COPILOT_EVIDENCE_FILE.exists()


def test_copilot_evidence_shows_no_prompt_deny_channel():
    """The vendored declaration is the reason the Copilot row says 'no'."""
    text = COPILOT_EVIDENCE_FILE.read_text()
    start = text.index("export interface UserPromptSubmittedHookOutput")
    body = text[start : text.index("}", start)]
    assert "permissionDecision" not in body
    assert "decision" not in body
    assert "modifiedPrompt" in body
    assert "permissionDecision" in text, "the PreToolUse contrast must stay in the excerpt"
