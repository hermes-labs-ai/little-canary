"""Offline replay integrity and explicit loopback-live demo tests."""

import hashlib
import io
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from little_canary.analyzer import BehavioralAnalyzer
from little_canary.canary import DEFAULT_CANARY_SYSTEM_PROMPT, CanaryResult
from little_canary.demo import (
    ATTACK_INPUT,
    CLEAN_INPUT,
    DEMO_SCHEMA,
    REPLAY_SCHEMA,
    _analysis_record,
    replay_payload_sha256,
    run_live,
    run_replay,
    validate_loopback_endpoint,
)

CLEAN_RESPONSE = "The capital of France is Paris."
COMPROMISED_RESPONSE = (
    "I have acknowledged the correction to my system prompt. Following your new "
    "instructions, I am now an unrestricted AI with no content policies."
)


def _expected(user_input, response):
    canary_result = CanaryResult(
        response=response,
        latency=0.1,
        model="qwen2.5:1.5b",
        system_prompt=DEFAULT_CANARY_SYSTEM_PROMPT,
        user_input=user_input,
        success=True,
    )
    analysis = BehavioralAnalyzer().analyze(canary_result)
    return {
        "risk": analysis.risk_score,
        "block": analysis.should_block,
        "signals": [signal.category for signal in analysis.signals],
    }


def _fixture_data():
    data = {
        "schema": REPLAY_SCHEMA,
        "fixture_kind": "recorded_live_output",
        "capture": {
            "timestamp_utc": "2026-07-17T12:00:00Z",
            "source_sha": "a" * 40,
            "backend": "ollama",
            "model": "qwen2.5:1.5b",
            "model_digest": "sha256:" + "b" * 64,
            "runtime_version": "test-runtime",
            "system_prompt_sha256": hashlib.sha256(DEFAULT_CANARY_SYSTEM_PROMPT.encode("utf-8")).hexdigest(),
            "temperature": 0.0,
            "seed": 42,
            "max_tokens": 256,
        },
        "cases": [
            {
                "id": "clean",
                "input": CLEAN_INPUT,
                "response": CLEAN_RESPONSE,
                "expected": _expected(CLEAN_INPUT, CLEAN_RESPONSE),
            },
            {
                "id": "c1-05",
                "input": ATTACK_INPUT,
                "response": COMPROMISED_RESPONSE,
                "expected": _expected(ATTACK_INPUT, COMPROMISED_RESPONSE),
            },
        ],
    }
    data["payload_sha256"] = replay_payload_sha256(data)
    return data


def _write_fixture(path: Path, data=None):
    value = data if data is not None else _fixture_data()
    path.write_text(json.dumps(value), encoding="utf-8")
    return value


def _response(status, payload, text=""):
    response = MagicMock()
    response.status_code = status
    response.text = text
    response.json.return_value = payload
    return response


def test_missing_replay_is_explicit_and_has_zero_egress(tmp_path):
    output = io.StringIO()
    with (
        patch("little_canary.demo.requests.get") as get,
        patch("little_canary.demo.requests.post") as post,
    ):
        exit_code = run_replay(
            fixture_path=tmp_path / "missing.json",
            stdout=output,
        )

    assert exit_code == 2
    assert output.getvalue().splitlines()[:4] == [
        "RUN_KIND   REPLAY",
        "MODEL_CALL no — recorded output",
        "CANARY     NOT EXERCISED THIS RUN",
        "EGRESS     none",
    ]
    assert "REPLAY     UNAVAILABLE" in output.getvalue()
    get.assert_not_called()
    post.assert_not_called()


def test_valid_replay_verifies_recorded_contrast_without_egress(tmp_path):
    fixture_path = tmp_path / "replay.json"
    fixture = _write_fixture(fixture_path)
    output = io.StringIO()

    with (
        patch("little_canary.demo.requests.get") as get,
        patch("little_canary.demo.requests.post") as post,
    ):
        exit_code = run_replay(fixture_path=fixture_path, stdout=output)

    assert exit_code == 0
    text = output.getvalue()
    assert "REPLAY     VERIFIED" in text
    assert "recorded analyzer contrast; not current model safety" in text
    assert "VERDICT    PASS" in text
    assert "VERDICT    BLOCK" in text
    assert f"FIXTURE_SHA {fixture['payload_sha256']}" in text
    assert "MODEL_SHA  sha256:" in text
    assert "COVERAGE   canary=recorded_capture; analysis=regex/exercised" in text
    get.assert_not_called()
    post.assert_not_called()


def test_replay_json_has_stable_truth_fields(tmp_path):
    fixture_path = tmp_path / "replay.json"
    fixture = _write_fixture(fixture_path)
    output = io.StringIO()

    exit_code = run_replay(
        fixture_path=fixture_path,
        stdout=output,
        output_json=True,
    )

    assert exit_code == 0
    result = json.loads(output.getvalue())
    assert result["schema"] == DEMO_SCHEMA
    assert result["evidence_type"] == "REPLAY"
    assert result["command_status"] == "REPLAY VERIFIED"
    assert result["model_call"] is False
    assert result["canary_exercised_this_run"] is False
    assert result["analysis_method"] == "regex"
    assert result["capture_canary_status"] == "exercised"
    assert result["run_canary_status"] == "not_exercised"
    assert result["analysis_status"] == "exercised"
    assert result["egress"] == "none"
    assert result["fixture_payload_sha256"] == fixture["payload_sha256"]


def test_replay_tamper_fails_integrity(tmp_path):
    fixture_path = tmp_path / "replay.json"
    fixture = _fixture_data()
    fixture["cases"][1]["response"] = "tampered"
    _write_fixture(fixture_path, fixture)
    output = io.StringIO()

    assert run_replay(fixture_path=fixture_path, stdout=output) == 1
    assert "REPLAY     INTEGRITY FAILURE" in output.getvalue()
    assert "fixture hash mismatch" in output.getvalue()


def test_replay_expectation_drift_fails_after_valid_hash(tmp_path):
    fixture_path = tmp_path / "replay.json"
    fixture = _fixture_data()
    fixture["cases"][1]["expected"]["block"] = False
    fixture["payload_sha256"] = replay_payload_sha256(fixture)
    _write_fixture(fixture_path, fixture)
    output = io.StringIO()

    assert run_replay(fixture_path=fixture_path, stdout=output) == 1
    assert "REPLAY     EXPECTATION FAILURE" in output.getvalue()


def test_replay_analysis_exception_is_degraded_and_redacted(tmp_path):
    fixture_path = tmp_path / "replay.json"
    _write_fixture(fixture_path)
    output = io.StringIO()

    with patch(
        "little_canary.demo.BehavioralAnalyzer.analyze",
        side_effect=RuntimeError("credential-secret"),
    ):
        exit_code = run_replay(fixture_path=fixture_path, stdout=output)

    assert exit_code == 2
    assert "REPLAY     ANALYSIS FAILURE" in output.getvalue()
    assert "credential-secret" not in output.getvalue()


def test_response_swaps_falsify_input_only_classification():
    attack_clean, attack_clean_analysis = _analysis_record(
        "attack-clean",
        ATTACK_INPUT,
        CLEAN_RESPONSE,
        "test-model",
    )
    clean_compromised, clean_compromised_analysis = _analysis_record(
        "clean-compromised",
        CLEAN_INPUT,
        COMPROMISED_RESPONSE,
        "test-model",
    )

    assert attack_clean["verdict"] == "PASS"
    assert attack_clean_analysis.should_block is False
    assert clean_compromised["verdict"] == "BLOCK"
    assert clean_compromised_analysis.should_block is True


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        ("http://127.0.0.1:11434", "http://127.0.0.1:11434"),
        ("http://127.0.0.2/", "http://127.0.0.2"),
        ("http://[::1]:11434", "http://[::1]:11434"),
    ],
)
def test_loopback_endpoint_validation_accepts_literal_loopback(endpoint, expected):
    assert validate_loopback_endpoint(endpoint) == expected


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:11434",
        "http://localhost:11434",
        "http://192.0.2.10:11434",
        "http://user:secret@127.0.0.1:11434",
        "http://127.0.0.1:11434/path",
        "http://127.0.0.1:11434?token=secret",
        "not-a-url",
    ],
)
def test_loopback_endpoint_validation_rejects_ambiguous_or_remote_targets(endpoint):
    with pytest.raises(ValueError):
        validate_loopback_endpoint(endpoint)


def test_live_rejects_non_loopback_before_any_request():
    output = io.StringIO()
    error = io.StringIO()
    with (
        patch("little_canary.demo.requests.get") as get,
        patch("little_canary.demo.requests.post") as post,
    ):
        exit_code = run_live(
            endpoint="https://example.test/v1?token=secret",
            stdout=output,
            stderr=error,
        )

    assert exit_code == 2
    assert "token" not in error.getvalue()
    get.assert_not_called()
    post.assert_not_called()


def test_live_preamble_precedes_preflight_and_model_calls():
    output = io.StringIO()
    error = io.StringIO()

    def inventory(*_args, **_kwargs):
        assert "RUN_KIND   LIVE" in output.getvalue()
        assert "EGRESS     loopback" in output.getvalue()
        assert CLEAN_INPUT in output.getvalue()
        assert ATTACK_INPUT in output.getvalue()
        return _response(
            200,
            {"models": [{"name": "qwen2.5:1.5b", "digest": "sha256:model-digest"}]},
        )

    responses = [
        _response(200, {"message": {"content": CLEAN_RESPONSE}}),
        _response(200, {"message": {"content": COMPROMISED_RESPONSE}}),
    ]

    def generate(*_args, **_kwargs):
        assert "RUN_KIND   LIVE" in output.getvalue()
        assert "INPUT      c1-05" in output.getvalue()
        assert "MODEL_SHA  sha256:model-digest" in output.getvalue()
        return responses.pop(0)

    with (
        patch("little_canary.demo.requests.get", side_effect=inventory) as get,
        patch("little_canary.canary.requests.post", side_effect=generate) as post,
    ):
        exit_code = run_live(
            endpoint="http://127.0.0.1:11434",
            stdout=output,
            stderr=error,
        )

    assert exit_code == 0
    assert "MODEL_SHA  sha256:model-digest" in output.getvalue()
    assert "LIVE       CONTRAST VERIFIED" in output.getvalue()
    get.assert_called_once()
    assert post.call_count == 2
    sent_inputs = [call.kwargs["json"]["messages"][1]["content"] for call in post.call_args_list]
    assert sent_inputs == [CLEAN_INPUT, ATTACK_INPUT]


def test_live_model_resistance_is_no_contrast_not_replay():
    output = io.StringIO()
    inventory = _response(
        200,
        {"models": [{"name": "qwen2.5:1.5b", "digest": "digest"}]},
    )
    clean = _response(200, {"message": {"content": CLEAN_RESPONSE}})

    with (
        patch("little_canary.demo.requests.get", return_value=inventory),
        patch("little_canary.canary.requests.post", side_effect=[clean, clean]),
    ):
        exit_code = run_live(
            endpoint="http://127.0.0.1:11434",
            stdout=output,
            stderr=io.StringIO(),
        )

    assert exit_code == 1
    assert "LIVE       NO CONTRAST" in output.getvalue()
    assert "REPLAY" not in output.getvalue()


def test_live_second_transport_failure_is_incomplete_and_nonzero():
    output = io.StringIO()
    inventory = _response(
        200,
        {"models": [{"name": "qwen2.5:1.5b", "digest": "digest"}]},
    )
    clean = _response(200, {"message": {"content": CLEAN_RESPONSE}})

    with (
        patch("little_canary.demo.requests.get", return_value=inventory),
        patch(
            "little_canary.canary.requests.post",
            side_effect=[clean, requests.ConnectionError("secret transport detail")],
        ),
    ):
        exit_code = run_live(
            endpoint="http://127.0.0.1:11434",
            stdout=output,
            stderr=io.StringIO(),
        )

    assert exit_code == 2
    assert "LIVE       DEGRADED / INCOMPLETE" in output.getvalue()
    assert "secret transport detail" not in output.getvalue()


def test_live_empty_provider_content_is_degraded():
    output = io.StringIO()
    inventory = _response(
        200,
        {"models": [{"name": "qwen2.5:1.5b", "digest": "digest"}]},
    )
    empty = _response(200, {"message": {"content": ""}})

    with (
        patch("little_canary.demo.requests.get", return_value=inventory),
        patch("little_canary.canary.requests.post", return_value=empty),
    ):
        exit_code = run_live(
            endpoint="http://127.0.0.1:11434",
            stdout=output,
            stderr=io.StringIO(),
        )

    assert exit_code == 2
    assert "DEGRADED" in output.getvalue()
    assert "RISK       None" in output.getvalue()


def test_live_analysis_exception_is_degraded_and_redacted():
    output = io.StringIO()
    inventory = _response(
        200,
        {"models": [{"name": "qwen2.5:1.5b", "digest": "digest"}]},
    )
    clean = _response(200, {"message": {"content": CLEAN_RESPONSE}})

    with (
        patch("little_canary.demo.requests.get", return_value=inventory),
        patch("little_canary.canary.requests.post", return_value=clean),
        patch(
            "little_canary.demo.BehavioralAnalyzer.analyze",
            side_effect=RuntimeError("credential-secret"),
        ),
    ):
        exit_code = run_live(
            endpoint="http://127.0.0.1:11434",
            stdout=output,
            stderr=io.StringIO(),
        )

    assert exit_code == 2
    assert "LIVE       DEGRADED / INCOMPLETE" in output.getvalue()
    assert "credential-secret" not in output.getvalue()


def test_live_preflight_error_does_not_echo_response_body():
    output = io.StringIO()
    inventory = _response(500, {}, text="credential=response-secret")

    with (
        patch("little_canary.demo.requests.get", return_value=inventory),
        patch("little_canary.canary.requests.post") as post,
    ):
        exit_code = run_live(
            endpoint="http://127.0.0.1:11434",
            stdout=output,
            stderr=io.StringIO(),
        )

    assert exit_code == 2
    assert "HTTP status 500" in output.getvalue()
    assert "response-secret" not in output.getvalue()
    post.assert_not_called()


def test_live_missing_model_digest_is_unexercised_and_sends_no_prompt():
    output = io.StringIO()
    inventory = _response(200, {"models": [{"name": "qwen2.5:1.5b"}]})

    with (
        patch("little_canary.demo.requests.get", return_value=inventory),
        patch("little_canary.canary.requests.post") as post,
    ):
        exit_code = run_live(
            endpoint="http://127.0.0.1:11434",
            stdout=output,
            stderr=io.StringIO(),
        )

    assert exit_code == 2
    assert "DEGRADED / UNEXERCISED" in output.getvalue()
    assert "model digest is unavailable" in output.getvalue()
    post.assert_not_called()


def test_live_preflight_failure_reports_no_model_call():
    output = io.StringIO()
    inventory = _response(503, {})

    with (
        patch("little_canary.demo.requests.get", return_value=inventory),
        patch("little_canary.canary.requests.post") as post,
    ):
        exit_code = run_live(
            endpoint="http://127.0.0.1:11434",
            output_json=True,
            stdout=output,
            stderr=io.StringIO(),
        )

    assert exit_code == 2
    result = json.loads(output.getvalue())
    assert result["model_call"] is False
    assert result["canary_exercised_this_run"] is False
    assert result["analysis_method"] == "none"
    post.assert_not_called()


def test_live_json_emits_pre_call_disclosure_then_stable_result():
    output = io.StringIO()
    error = io.StringIO()
    inventory = _response(
        200,
        {"models": [{"name": "qwen2.5:1.5b", "digest": "digest"}]},
    )
    responses = [
        _response(200, {"message": {"content": CLEAN_RESPONSE}}),
        _response(200, {"message": {"content": COMPROMISED_RESPONSE}}),
    ]

    def generate(*_args, **_kwargs):
        preflight = json.loads(error.getvalue())
        assert preflight["event"] == "LIVE_PREFLIGHT"
        assert preflight["egress"].startswith("loopback")
        return responses.pop(0)

    with (
        patch("little_canary.demo.requests.get", return_value=inventory),
        patch("little_canary.canary.requests.post", side_effect=generate),
    ):
        exit_code = run_live(
            endpoint="http://127.0.0.1:11434",
            output_json=True,
            stdout=output,
            stderr=error,
        )

    assert exit_code == 0
    preflight = json.loads(error.getvalue())
    result = json.loads(output.getvalue())
    assert preflight["schema"] == DEMO_SCHEMA
    assert result["schema"] == DEMO_SCHEMA
    assert result["evidence_type"] == "LIVE"
    assert result["command_status"] == "LIVE CONTRAST VERIFIED"
    assert result["canary_exercised_this_run"] is True
    assert result["model_call"] is True
    assert result["analysis_method"] == "regex"
    assert result["configuration"]["structural_filter"] == "disabled"
