"""Pin the facts quoted in docs/examples/ to the committed sources they cite."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
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
    assert cases["clean"]["verdict"] == "PASS" and cases["clean"]["risk"] == 0.0
    assert "risk `0.0`, verdict `PASS`" in text


def test_jailbench_example_output_claims_match_structural_run():
    text = (EXAMPLES / "02-jailbench-sandwich-pair.md").read_text(encoding="utf-8")
    assert "Direct injection (instruction override); Injection: fake system prompt update" in text
    assert text.count("| `block` |") == 2
    assert "same two reasons" in text and "`skipped_after_block`" in text


def test_batch_example_output_claims_match_offline_screen_run(tmp_path):
    text = (EXAMPLES / "03-batch-coverage-hold.md").read_text(encoding="utf-8")
    batch = tmp_path / "batch.jsonl"
    batch.write_text(_fenced_jsonl(text), encoding="utf-8")
    run = subprocess.run(
        [sys.executable, "-m", "little_canary.cli", "screen", str(batch),
         "--ollama-url", "http://127.0.0.1:9", "--timeout", "1"],
        capture_output=True, text=True, cwd=ROOT,
    )
    result = json.loads(run.stdout)
    items = {i["id"]: i for i in result["items"]}
    assert run.returncode == 2 and "Exit status `2`" in text
    assert result["counts"]["block"] == 1 and result["counts"]["degraded"] == 1
    assert result["counts"]["pass"] == 0 and "`block 1`, `degraded 1`, `pass 0`" in text
    assert items["clean"]["state"] == "degraded"
    assert items["clean"]["verdict"]["canary_status"] == "failed"
    assert "Input allowed by fail-open policy because behavioral coverage failed; not inspected-safe" in (
        items["clean"]["verdict"]["summary"]
    )
    assert items["jb-inj-01"]["state"] == "block"
    assert items["jb-inj-01"]["verdict"]["canary_status"] == "skipped_after_block"
    assert "France" not in run.stdout and "cooking" not in run.stdout
    assert "Unreleased" in text


def test_copilot_example_output_claims_match_matrix():
    matrix = _load("docs/host-capability-matrix.json")
    host = next(h for h in matrix["hosts"] if h["id"] == "github-copilot")
    text = (EXAMPLES / "04-copilot-cannot-refuse.md").read_text(encoding="utf-8")
    assert f"`deny_channel: {str(host['inbound']['deny_channel']).lower()}`" in text
    assert f"`shipped: {str(host['inbound']['shipped']).lower()}`" in text
    assert host["outbound_tool_execution"]["host_deny_channel"] is True
    assert host["shipped_artifact"] is None
