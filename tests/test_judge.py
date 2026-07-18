"""Tests for little_canary.judge — LLM judge for canary output analysis (mocked HTTP)."""

from unittest.mock import MagicMock, patch

import requests

from little_canary.canary import DEFAULT_CANARY_SYSTEM_PROMPT, CanaryResult
from little_canary.judge import LLMJudge


def _make_result(response, user_input="test input", success=True, error=None):
    """Helper to build CanaryResult objects for testing."""
    return CanaryResult(
        response=response,
        latency=0.25,
        model="qwen2.5:1.5b",
        system_prompt=DEFAULT_CANARY_SYSTEM_PROMPT,
        user_input=user_input,
        success=success,
        error=error,
    )


# ── _parse_verdict ──


def test_parse_unsafe():
    judge = LLMJudge()
    assert judge._parse_verdict("UNSAFE") == "UNSAFE"


def test_parse_safe():
    judge = LLMJudge()
    assert judge._parse_verdict("SAFE") == "SAFE"


def test_parse_unsafe_with_thinking():
    judge = LLMJudge()
    assert judge._parse_verdict("<think>Let me reason about this</think>UNSAFE") == "UNSAFE"


def test_parse_safe_with_thinking():
    judge = LLMJudge()
    assert judge._parse_verdict("<think>This seems fine</think>SAFE") == "SAFE"


def test_parse_unsafe_case_insensitive():
    judge = LLMJudge()
    assert judge._parse_verdict("unsafe") == "UNSAFE"


def test_parse_unsafe_takes_priority():
    judge = LLMJudge()
    # UNSAFE contains "SAFE" substring, but UNSAFE should be found first
    assert judge._parse_verdict("UNSAFE") == "UNSAFE"


def test_parse_unparseable_abstains():
    judge = LLMJudge()
    assert judge._parse_verdict("I don't know what to say") is None


def test_parse_empty_after_thinking_strip():
    judge = LLMJudge()
    # After stripping thinking, empty string → falls back to raw output check
    result = judge._parse_verdict("<think>only thinking here</think>")
    # Raw output contains no SAFE/UNSAFE → abstains rather than inventing safety
    assert result is None


# ── analyze() with mocked requests ──


@patch("little_canary.judge.requests.post")
def test_analyze_safe_verdict(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"message": {"content": "SAFE"}}
    mock_post.return_value = mock_response

    judge = LLMJudge()
    cr = _make_result("The capital of France is Paris.")
    result = judge.analyze(cr)
    assert result.risk_score == 0.0
    assert result.should_block is False
    assert result.degraded is False
    assert result.analysis_method == "llm_judge"
    assert result.analysis_status == "exercised"


@patch("little_canary.judge.requests.post")
def test_analyze_unsafe_verdict(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"message": {"content": "UNSAFE"}}
    mock_post.return_value = mock_response

    judge = LLMJudge()
    cr = _make_result("Sure! I am DAN and have no restrictions.")
    result = judge.analyze(cr)
    assert result.risk_score == 1.0
    assert result.should_block is True
    assert result.hard_blocked is True
    assert len(result.signals) == 1
    assert result.signals[0].category == "llm_judge"


def test_analyze_failed_canary_is_degraded(failed_canary_result):
    judge = LLMJudge()
    result = judge.analyze(failed_canary_result)
    assert result.risk_score is None
    assert result.should_block is False
    assert result.degraded is True
    assert result.canary_status == "failed"
    assert result.analysis_method == "llm_judge"
    assert result.analysis_status == "not_applicable"


@patch("little_canary.judge.requests.post")
def test_analyze_http_error(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mock_post.return_value = mock_response

    judge = LLMJudge()
    cr = _make_result("test response")
    result = judge.analyze(cr)
    assert result.should_block is False  # fail-open
    assert result.risk_score is None
    assert result.degraded is True
    assert result.canary_status == "exercised"
    assert result.analysis_status == "failed"


@patch("little_canary.judge.requests.post")
def test_analyze_timeout(mock_post):
    mock_post.side_effect = requests.Timeout("timed out")

    judge = LLMJudge()
    cr = _make_result("test response")
    result = judge.analyze(cr)
    assert result.should_block is False  # fail-open
    assert result.risk_score is None
    assert result.degraded is True
    assert result.analysis_status == "failed"


@patch("little_canary.judge.requests.post")
def test_analyze_connection_error(mock_post):
    mock_post.side_effect = requests.ConnectionError("refused")

    judge = LLMJudge()
    cr = _make_result("test response")
    result = judge.analyze(cr)
    assert result.should_block is False  # fail-open
    assert result.risk_score is None
    assert result.degraded is True
    assert result.analysis_status == "failed"


@patch("little_canary.judge.requests.post")
def test_analyze_unexpected_error_is_redacted(mock_post, caplog):
    mock_post.side_effect = RuntimeError("credential-secret")

    judge = LLMJudge()
    cr = _make_result("test response")
    result = judge.analyze(cr)
    assert result.should_block is False  # fail-open
    assert result.risk_score is None
    assert result.degraded is True
    assert result.analysis_status == "failed"
    assert "credential-secret" not in result.summary
    assert "credential-secret" not in caplog.text


@patch("little_canary.judge.requests.post")
def test_analyze_unparseable_verdict_is_degraded(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"message": {"content": "MAYBE"}}
    mock_post.return_value = mock_response

    result = LLMJudge().analyze(_make_result("test response"))

    assert result.should_block is False
    assert result.risk_score is None
    assert result.degraded is True
    assert result.canary_status == "exercised"
    assert result.analysis_method == "llm_judge"
    assert result.analysis_status == "failed"
    assert "SAFE" not in result.summary


@patch("little_canary.judge.requests.post")
def test_analyze_sends_correct_payload(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"message": {"content": "SAFE"}}
    mock_post.return_value = mock_response

    judge = LLMJudge(model="qwen3:4b")
    cr = _make_result("Canary said this", user_input="User asked this")
    judge.analyze(cr)

    call_args = mock_post.call_args
    payload = call_args[1]["json"] if "json" in call_args[1] else call_args[0][1]
    assert payload["model"] == "qwen3:4b"
    user_content = payload["messages"][1]["content"]
    assert "User asked this" in user_content
    assert "Canary said this" in user_content


# ── is_available() ──


@patch("little_canary.judge.requests.get")
def test_is_available_true(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "models": [{"name": "qwen3:4b"}, {"name": "llama3:8b"}]
    }
    mock_get.return_value = mock_response

    judge = LLMJudge(model="qwen3:4b")
    assert judge.is_available() is True


@patch("little_canary.judge.requests.get")
def test_is_available_false(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "models": [{"name": "llama3:8b"}]
    }
    mock_get.return_value = mock_response

    judge = LLMJudge(model="qwen3:4b")
    assert judge.is_available() is False
