import json
import sys
from types import SimpleNamespace

import pytest

from benchmarks import red_team_runner
from benchmarks.red_team_runner import DashboardHandler, load_cases, run_tests
from little_canary.pipeline import AnalysisSnapshot, LayerResult, PipelineVerdict, SignalSnapshot


class FakePipeline:
    def __init__(self, verdict):
        self.verdict = verdict

    def check(self, _prompt):
        return self.verdict


def _case(expected_safe=False):
    return {
        "id": "case-1",
        "category": "test",
        "goal": "test scoring",
        "prompt": "test prompt",
        "expected_safe": expected_safe,
    }


def _verdict(*, safe, degraded=False, snapshot=None, canary_status="exercised", analysis_status="exercised"):
    return PipelineVerdict(
        safe=safe,
        input="test prompt",
        safe_input="test prompt" if safe else "",
        total_latency=0.01,
        degraded=degraded,
        canary_status=canary_status,
        analysis_status=analysis_status,
        layers=[
            LayerResult(
                layer_name="structural_filter",
                passed=True,
                latency=0.001,
                details="Clean",
                status="passed",
            ),
            LayerResult(
                layer_name="canary_probe",
                passed=safe if not degraded else None,
                latency=0.01,
                details="test",
                raw_result=snapshot,
                status="failed" if degraded else ("passed" if safe else "blocked"),
            )
        ],
    )


def _run(verdict, *, expected_safe=False):
    DashboardHandler.results_log = []
    DashboardHandler.summary = {}
    DashboardHandler.run_complete = False
    run_tests(FakePipeline(verdict), [_case(expected_safe=expected_safe)])
    return DashboardHandler.results_log[0], DashboardHandler.summary


def test_degraded_attack_is_unscored_instead_of_false_negative():
    result, summary = _run(_verdict(safe=True, degraded=True, canary_status="failed", analysis_status="not_applicable"))

    assert result["scored"] is False
    assert result["actual_safe"] is None
    assert result["correct"] is None
    assert summary["unscored"] == 1
    assert summary["fn"] == 0
    assert summary["attack_total"] == 1
    assert summary["attack_unscored"] == 1
    assert summary["attack_detection_full_population_rate"] == 0.0


def test_response_free_snapshot_signals_serialize():
    snapshot = AnalysisSnapshot(
        risk_score=1.0,
        should_block=True,
        signals=(SignalSnapshot(category="instruction_echo", severity=0.85),),
        hard_blocked=True,
        degraded=False,
        canary_status="exercised",
        analysis_method="regex",
        analysis_status="exercised",
    )
    result, _summary = _run(_verdict(safe=False, snapshot=snapshot))

    assert result["signals"] == [{"category": "instruction_echo", "severity": 0.85}]


def test_unparseable_judgment_is_unscored():
    result, summary = _run(_verdict(safe=True, analysis_status="failed"))

    assert result["scored"] is False
    assert result["unscored_reason"] == "analysis_failed"
    assert summary["attack_detection_rate"] is None
    assert summary["degraded"] == 0


def test_benign_false_block_uses_benign_scored_denominator():
    result, summary = _run(_verdict(safe=False), expected_safe=True)

    assert result["correct"] is False
    assert summary["benign_total"] == 1
    assert summary["benign_scored"] == 1
    assert summary["benign_false_block_rate"] == 100.0
    assert summary["attack_detection_rate"] is None


def test_pipeline_exception_is_visible_and_excluded_from_latency_of_scored_cases():
    class RaisingPipeline:
        def check(self, _prompt):
            raise RuntimeError("simulated failure")

    events = []
    result = run_tests(RaisingPipeline(), [_case()], sink=events.append)

    assert events[0]["error_type"] == "RuntimeError"
    assert events[0]["scored"] is False
    assert result["summary"]["degraded"] == 1
    assert result["summary"]["scored_total_latency_p95_ms"] is None


def test_ids_file_selects_ordered_cases_from_both_corpora(tmp_path):
    path = tmp_path / "ids.json"
    path.write_text(json.dumps(["fp-h01", "c1-01"]))

    assert [case["id"] for case in load_cases("attacks", path)] == ["fp-h01", "c1-01"]

    path.write_text(json.dumps(["c1-01", "c1-01"]))
    with pytest.raises(ValueError, match="duplicates"):
        load_cases("attacks", path)


def test_headless_model_only_uses_selected_model_and_writes_case_json(monkeypatch, tmp_path):
    instances = []

    class ConfiguredPipeline(FakePipeline):
        def __init__(self, **kwargs):
            super().__init__(_verdict(safe=False))
            self.kwargs = kwargs
            self.canary_probe = SimpleNamespace(
                temperature=0.0, seed=42, max_tokens=256, system_prompt="test prompt"
            )
            instances.append(self)

        def health_check(self):
            return {"ready": True}

    ids_path = tmp_path / "ids.json"
    ids_path.write_text(json.dumps(["c1-01"]))
    output_path = tmp_path / "cases.jsonl"
    monkeypatch.setattr(red_team_runner, "SecurityPipeline", ConfiguredPipeline)
    monkeypatch.setattr(sys, "argv", [
        "red_team_runner.py", "--mode", "model-only", "--model", "chosen:1b",
        "--ids-file", str(ids_path), "--timeout", "12", "--headless", "--output", str(output_path),
    ])

    assert red_team_runner.main() == 0
    assert instances[0].kwargs["canary_model"] == "chosen:1b"
    assert instances[0].kwargs["enable_structural_filter"] is False
    assert instances[0].kwargs["skip_canary_if_structural_blocks"] is False
    assert instances[0].kwargs["canary_timeout"] == 12
    events = [json.loads(line) for line in output_path.read_text().splitlines()]
    assert [event["type"] for event in events] == ["run", "result", "complete"]
    assert events[1]["id"] == "c1-01"
    assert events[1]["canary_blocked"] is True
    assert events[2]["summary"]["scored"] == 1
