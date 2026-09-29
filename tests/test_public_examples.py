"""Pin the facts quoted in docs/examples/ to the committed sources they cite."""

from __future__ import annotations

import hashlib
import json
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
