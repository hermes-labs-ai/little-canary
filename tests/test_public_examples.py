"""Pin the facts quoted in docs/examples/ to the committed sources they cite."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "docs" / "examples"


def _load(rel: str):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def test_example_files_exist_and_are_indexed():
    index = (EXAMPLES / "README.md").read_text(encoding="utf-8")
    files = sorted(p.name for p in EXAMPLES.glob("0*.md"))
    assert len(files) == 4
    for name in files:
        assert name in index
        text = (EXAMPLES / name).read_text(encoding="utf-8")
        for heading in ("## Input", "## Output", "## Limits"):
            assert heading in text, (name, heading)


def test_replay_example_matches_recorded_fixture():
    fixture = _load("little_canary/data/demo_replay.json")
    assert fixture["fixture_kind"] == "recorded_live_output"
    cases = {c["id"]: c for c in fixture["cases"]}
    text = (EXAMPLES / "01-recorded-canary-compromise.md").read_text(encoding="utf-8")
    for case_id in ("clean", "c1-05"):
        assert cases[case_id]["input"] in text
    assert cases["c1-05"]["response"] in text
    assert fixture["capture"]["model_digest"][:12] in text
    assert fixture["capture"]["model"] in text


def test_jailbench_example_matches_committed_cases():
    probe = _load("benchmarks/jailbench_injection_cases.json")
    cases = {c["id"]: c for c in probe["cases"]}
    text = (EXAMPLES / "02-jailbench-sandwich-pair.md").read_text(encoding="utf-8")
    assert probe["source_commit"] in text
    for case_id in ("jb-inj-01", "benign_control-jb-inj-01"):
        case = cases[case_id]
        digest = hashlib.sha256(case["prompt"].encode("utf-8")).hexdigest()
        assert digest == case["source_input_sha256"]
        assert digest[:12] in text
    assert cases["jb-inj-01"]["prompt"] in text
    assert cases["benign_control-jb-inj-01"]["prompt"] in text


def test_jailbench_pair_structural_verdicts_are_reproducible():
    from little_canary.structural_filter import StructuralFilter

    probe = _load("benchmarks/jailbench_injection_cases.json")
    cases = {c["id"]: c for c in probe["cases"]}
    flt = StructuralFilter()
    for case_id in ("jb-inj-01", "benign_control-jb-inj-01"):
        result = flt.check(cases[case_id]["prompt"])
        assert result.blocked, case_id
        assert result.reasons == [
            "Direct injection (instruction override)",
            "Injection: fake system prompt update",
        ]


def test_copilot_example_matches_matrix_and_host_evidence():
    matrix = _load("docs/host-capability-matrix.json")
    host = next(h for h in matrix["hosts"] if h["id"] == "github-copilot")
    assert host["inbound"]["deny_channel"] is False
    assert host["inbound"]["shipped"] is False
    assert host["inbound"]["runtime_certified"] is False
    assert host["observed_version"] == "1.0.84-5"
    evidence = (ROOT / "docs/host-evidence/copilot-cli-1.0.84-5-hook-outputs.d.ts").read_text(
        encoding="utf-8"
    )
    assert 'permissionDecision?: "allow" | "deny" | "ask";' in evidence
    assert "modifiedPrompt?: string;" in evidence
    text = (EXAMPLES / "04-copilot-cannot-refuse.md").read_text(encoding="utf-8")
    assert "1.0.84-5" in text


_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


@contextlib.contextmanager
def _refusing_port():
    """Hold a bound, non-listening loopback port: connects are refused and no other process can take it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        yield sock.getsockname()[1]


@contextlib.contextmanager
def _fake_proxy():
    """A local listener that records connections, keeping at most 32 leading bytes of each."""
    hits: list[bytes] = []
    stop = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        srv.settimeout(0.1)

        def serve() -> None:
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except OSError:
                    continue
                with conn:
                    conn.settimeout(0.5)
                    try:
                        hits.append(conn.recv(32))
                    except OSError:
                        hits.append(b"")

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            yield srv.getsockname()[1], hits
        finally:
            stop.set()
            thread.join(timeout=2)


def _poisoned_env(proxy_port: int) -> dict:
    env = {k: v for k, v in os.environ.items() if k.lower() not in {v.lower() for v in _PROXY_VARS} | {"no_proxy"}}
    for name in _PROXY_VARS:
        env[name] = f"http://127.0.0.1:{proxy_port}"
    return env


def _documented_command(text: str, batch: Path, port: int) -> list:
    """The example's own bash command, with the batch file and unused port filled in."""
    block = text.split("```bash\n", 1)[1].split("```", 1)[0]
    assert "<UNUSED_PORT>" in block and "127.0.0.1:9" not in block
    for name in _PROXY_VARS:
        assert f"-u {name} " in block, name
    assert "NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 " in block and "--timeout 1" in block
    argv = shlex.split(block.replace("<UNUSED_PORT>", str(port)))
    assert argv[0] == "env" and argv.count("little-canary") == 1
    at = argv.index("little-canary")
    tail = [str(batch) if a == "batch.jsonl" else a for a in argv[at + 1:]]
    return argv[:at] + [sys.executable, "-m", "little_canary.cli"] + tail


def _fenced_jsonl(text: str) -> str:
    block = text.split("```json\n", 1)[1].split("```", 1)[0]
    return block


def test_replay_example_output_claims_match_demo_run():
    out = subprocess.run(
        [sys.executable, "-m", "little_canary.cli", "demo", "--json"],
        capture_output=True, text=True, cwd=ROOT, check=True,
    )
    result = json.loads(out.stdout)
    cases = {c["id"]: c for c in result["cases"]}
    text = (EXAMPLES / "01-recorded-canary-compromise.md").read_text(encoding="utf-8")
    assert result["command_status"] == "REPLAY VERIFIED" and "`REPLAY VERIFIED`" in text
    assert result["canary_exercised_this_run"] is False and "canary_exercised_this_run: false" in text
    assert cases["c1-05"]["verdict"] == "BLOCK" and cases["c1-05"]["risk"] == 1.0
    assert "`risk 1.0`, verdict `BLOCK`" in text
    for signal in set(cases["c1-05"]["signals"]):
        assert f"`{signal}`" in text
    assert cases["c1-05"]["signals"].count("canary_compromise") == 2 and "(twice)" in text
    assert result["egress"] == "none" and "`egress: none`" in text
    fixture = _load("little_canary/data/demo_replay.json")
    assert fixture["capture"]["runtime_version"].replace("little-canary ", "`little-canary ") + "`" in text
    assert cases["clean"]["verdict"] == "PASS" and cases["clean"]["risk"] == 0.0
    assert "risk `0.0`, verdict `PASS`" in text


def test_jailbench_example_output_claims_match_structural_run():
    text = (EXAMPLES / "02-jailbench-sandwich-pair.md").read_text(encoding="utf-8")
    assert "Direct injection (instruction override); Injection: fake system prompt update" in text
    assert text.count("| `block` |") == 2
    for case_id in ("jb-inj-01", "benign_control-jb-inj-01"):
        assert f"| `{case_id}` | `block` |" in text
    assert "same two reasons" in text and "`skipped_after_block`" in text


def test_batch_example_output_claims_match_offline_screen_run(tmp_path):
    text = (EXAMPLES / "03-batch-coverage-hold.md").read_text(encoding="utf-8")
    fenced = _fenced_jsonl(text)
    rows = [json.loads(line) for line in fenced.splitlines() if line.strip()]
    fixture = _load("little_canary/data/demo_replay.json")
    probe = _load("benchmarks/jailbench_injection_cases.json")
    replay_clean = next(c for c in fixture["cases"] if c["id"] == "clean")["input"]
    jailbench = next(c for c in probe["cases"] if c["id"] == "jb-inj-01")
    assert [r["id"] for r in rows] == ["clean", "jb-inj-01"]
    assert rows[0]["text"] == replay_clean
    assert rows[1]["text"] == jailbench["prompt"]
    assert hashlib.sha256(rows[1]["text"].encode("utf-8")).hexdigest() == jailbench["source_input_sha256"]
    batch = tmp_path / "batch.jsonl"
    batch.write_text(fenced, encoding="utf-8")
    with _refusing_port() as port, _fake_proxy() as (proxy_port, proxy_hits):
        argv = _documented_command(text, batch, port)
        run = subprocess.run(
            argv, capture_output=True, text=True, cwd=ROOT, env=_poisoned_env(proxy_port)
        )
    assert proxy_hits == [], "the documented command sent traffic to a proxy despite poisoned proxy variables"
    result = json.loads(run.stdout)
    items = {i["id"]: i for i in result["items"]}
    assert run.returncode == 2 and "Exit status `2`" in text
    assert result["counts"]["block"] == 1 and result["counts"]["degraded"] == 1
    assert result["counts"]["pass"] == 0 and "`block 1`, `degraded 1`, `pass 0`" in text
    clean, inj = items["clean"], items["jb-inj-01"]
    assert clean["state"] == "degraded" and "`clean` → `degraded`" in text
    assert clean["verdict"]["canary_status"] == "failed" and "`canary_status` is `failed`" in text
    quoted = "Input allowed by fail-open policy because behavioral coverage failed; not inspected-safe"
    assert quoted in clean["verdict"]["summary"] and quoted in text
    assert inj["state"] == "block" and "`jb-inj-01` → `block` by the structural filter (canary skipped)" in text
    assert inj["verdict"]["canary_status"] == "skipped_after_block"
    assert inj["verdict"]["blocked_by"] == "structural_filter"
    assert "France" not in run.stdout and "cooking" not in run.stdout
    assert "Unreleased" in text


def test_copilot_example_output_claims_match_matrix():
    matrix = _load("docs/host-capability-matrix.json")
    host = next(h for h in matrix["hosts"] if h["id"] == "github-copilot")
    text = (EXAMPLES / "04-copilot-cannot-refuse.md").read_text(encoding="utf-8")
    versions = re.findall(r"1\.0\.\d+-\d+", text)
    assert len(versions) >= 2 and set(versions) == {host["observed_version"]}
    assert f"`deny_channel: {str(host['inbound']['deny_channel']).lower()}`" in text
    assert f"`shipped: {str(host['inbound']['shipped']).lower()}`" in text
    outbound = host["outbound_tool_execution"]
    assert outbound["host_deny_channel"] is True
    assert f"`{outbound['host_event']}` event does have a host deny channel" in text
    assert host["shipped_artifact"] is None
    assert "ships **no Copilot artifact**" in text
    assert "abridged" in text and "verbatim" not in text
