"""Tests for little_canary.openai_provider — OpenAI-compatible canary and judge (mocked HTTP)."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from little_canary.canary import DEFAULT_CANARY_SYSTEM_PROMPT, CanaryResult
from little_canary.openai_provider import OpenAICanaryProbe, OpenAILLMJudge

# ── OpenAICanaryProbe __init__ ──


def test_default_config():
    probe = OpenAICanaryProbe()
    assert probe.model == "gpt-4o-mini"
    assert probe.base_url == "https://api.openai.com/v1"
    assert probe.temperature == 0.0
    assert probe.seed == 42
    assert probe.timeout == 10.0
    assert probe.max_tokens == 256


def test_custom_config():
    probe = OpenAICanaryProbe(
        model="MiniMax-M2.5",
        api_key="test-key",
        base_url="https://api.minimax.io/v1",
        timeout=5.0,
        max_tokens=128,
        temperature=0.1,
        seed=99,
    )
    assert probe.model == "MiniMax-M2.5"
    assert probe.api_key == "test-key"
    assert probe.base_url == "https://api.minimax.io/v1"
    assert probe.timeout == 5.0
    assert probe.max_tokens == 128
    assert probe.temperature == 0.1
    assert probe.seed == 99


def test_url_trailing_slash_stripped():
    probe = OpenAICanaryProbe(base_url="https://api.minimax.io/v1/")
    assert probe.base_url == "https://api.minimax.io/v1"


# ── test() method with mocked requests ──


@patch("little_canary.openai_provider.requests.post")
def test_successful_probe(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [{"message": {"content": "The capital of France is Paris."}}],
        "usage": {
            "prompt_tokens": 30,
            "completion_tokens": 8,
            "total_tokens": 38,
        },
    }
    mock_post.return_value = mock_response

    probe = OpenAICanaryProbe(model="MiniMax-M2.5", api_key="test-key")
    result = probe.test("What is the capital of France?")

    assert result.success is True
    assert result.response == "The capital of France is Paris."
    assert result.model == "MiniMax-M2.5"
    assert result.latency > 0


@patch("little_canary.openai_provider.requests.post")
def test_probe_captures_usage_metadata(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [{"message": {"content": "test"}}],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "total_tokens": 15,
        },
    }
    mock_post.return_value = mock_response

    probe = OpenAICanaryProbe()
    result = probe.test("test")
    assert result.metadata["prompt_tokens"] == 10
    assert result.metadata["completion_tokens"] == 5
    assert result.metadata["total_tokens"] == 15


@patch("little_canary.openai_provider.requests.post")
def test_probe_http_error(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.text = "Unauthorized"
    mock_post.return_value = mock_response

    probe = OpenAICanaryProbe()
    result = probe.test("test")
    assert result.success is False
    assert "status 401" in result.error
    assert "Unauthorized" not in result.error


@patch("little_canary.openai_provider.requests.post")
def test_probe_timeout(mock_post):
    mock_post.side_effect = requests.Timeout("Connection timed out")

    probe = OpenAICanaryProbe()
    result = probe.test("test")
    assert result.success is False
    assert "timed out" in result.error


@patch("little_canary.openai_provider.requests.post")
def test_probe_connection_error(mock_post):
    mock_post.side_effect = requests.ConnectionError("Connection refused")

    probe = OpenAICanaryProbe()
    result = probe.test("test")
    assert result.success is False
    assert "Cannot connect" in result.error


@patch("little_canary.openai_provider.requests.post")
def test_probe_connection_error_redacts_userinfo_query_and_path(mock_post):
    mock_post.side_effect = requests.ConnectionError("contains-secret")
    probe = OpenAICanaryProbe(base_url=("https://user:password@example.test/v1/private?api_key=query-secret"))

    result = probe.test("test")

    assert result.error == "Cannot connect to API at https://example.test"
    for secret in ("user", "password", "private", "query-secret"):
        assert secret not in result.error


@patch("little_canary.openai_provider.requests.post")
def test_probe_unexpected_error(mock_post):
    mock_post.side_effect = RuntimeError("Something went wrong")

    probe = OpenAICanaryProbe()
    result = probe.test("test")
    assert result.success is False
    assert result.error == "Canary probe failed (RuntimeError)"
    assert "Something went wrong" not in result.error


@patch("little_canary.openai_provider.requests.post")
def test_probe_sends_correct_payload(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [{"message": {"content": "test"}}],
        "usage": {},
    }
    mock_post.return_value = mock_response

    probe = OpenAICanaryProbe(
        model="MiniMax-M2.5",
        api_key="test-key",
        base_url="https://api.minimax.io/v1",
        temperature=0.1,
        seed=42,
        max_tokens=256,
    )
    probe.test("Hello world")

    call_args = mock_post.call_args
    payload = call_args[1]["json"] if "json" in call_args[1] else call_args[0][1]

    assert payload["model"] == "MiniMax-M2.5"
    assert payload["stream"] is False
    assert payload["messages"][0]["role"] == "system"
    assert payload["messages"][1]["role"] == "user"
    assert payload["messages"][1]["content"] == "Hello world"
    assert payload["temperature"] == 0.1
    assert payload["seed"] == 42
    assert payload["max_tokens"] == 256

    # Check correct URL
    url = call_args[0][0] if call_args[0] else call_args[1].get("url", "")
    if not url:
        url = call_args[0][0]
    assert "chat/completions" in url

    # Check auth header
    headers = call_args[1].get("headers", {})
    assert headers.get("Authorization") == "Bearer test-key"


@patch("little_canary.openai_provider.requests.post")
def test_probe_empty_choices(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"choices": [], "usage": {}}
    mock_post.return_value = mock_response

    probe = OpenAICanaryProbe()
    result = probe.test("test")
    assert result.success is False
    assert result.response == ""
    assert result.error == ("API protocol error: response content must be a non-empty string")


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"choices": None},
        {"choices": [{}]},
        {"choices": [{"message": {}}]},
        {"choices": [{"message": {"content": None}}]},
        {"choices": [{"message": {"content": 7}}]},
        {"choices": [{"message": {"content": "  "}}]},
        [],
    ],
)
@patch("little_canary.openai_provider.requests.post")
def test_probe_rejects_invalid_or_empty_content(mock_post, payload):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = payload
    mock_post.return_value = mock_response

    result = OpenAICanaryProbe().test("test")

    assert result.success is False
    assert result.error == ("API protocol error: response content must be a non-empty string")


@patch("little_canary.openai_provider.requests.post")
def test_probe_rejects_invalid_json_without_echoing_body(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "secret-response-body"
    mock_response.json.side_effect = ValueError("secret-response-body")
    mock_post.return_value = mock_response

    result = OpenAICanaryProbe().test("test")

    assert result.success is False
    assert result.error == "API protocol error: invalid JSON response"
    assert "secret" not in result.error


# ── is_available() ──


@patch("little_canary.openai_provider.requests.get")
def test_is_available_true(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_get.return_value = mock_response

    probe = OpenAICanaryProbe(api_key="test-key")
    assert probe.is_available() is True


@patch("little_canary.openai_provider.requests.get")
def test_is_available_unauthorized(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_get.return_value = mock_response

    probe = OpenAICanaryProbe()
    assert probe.is_available() is False


@patch("little_canary.openai_provider.requests.get")
def test_is_available_connection_error(mock_get):
    mock_get.side_effect = requests.ConnectionError("refused")
    probe = OpenAICanaryProbe()
    assert probe.is_available() is False


# ── OpenAILLMJudge ──


def _make_result(response, user_input="test input", success=True, error=None):
    return CanaryResult(
        response=response,
        latency=0.25,
        model="MiniMax-M2.5",
        system_prompt=DEFAULT_CANARY_SYSTEM_PROMPT,
        user_input=user_input,
        success=success,
        error=error,
    )


def test_judge_default_config():
    judge = OpenAILLMJudge()
    assert judge.model == "gpt-4o-mini"
    assert judge.base_url == "https://api.openai.com/v1"


def test_judge_minimax_config():
    judge = OpenAILLMJudge(
        model="MiniMax-M2.5",
        api_key="test-key",
        base_url="https://api.minimax.io/v1",
    )
    assert judge.model == "MiniMax-M2.5"
    assert judge.api_key == "test-key"
    assert judge.base_url == "https://api.minimax.io/v1"


def test_judge_parse_unsafe():
    judge = OpenAILLMJudge()
    assert judge._parse_verdict("UNSAFE") == "UNSAFE"


def test_judge_parse_safe():
    judge = OpenAILLMJudge()
    assert judge._parse_verdict("SAFE") == "SAFE"


def test_judge_parse_with_thinking():
    judge = OpenAILLMJudge()
    assert judge._parse_verdict("<think>reason here</think>UNSAFE") == "UNSAFE"


def test_judge_parse_unknown_abstains():
    judge = OpenAILLMJudge()
    assert judge._parse_verdict("I cannot decide") is None
    assert judge._parse_verdict("The response seems SAFE") is None
    assert judge._parse_verdict("SAFE or UNSAFE") is None


def test_judge_parse_rejects_decorated_verdicts():
    judge = OpenAILLMJudge()
    assert judge._parse_verdict("**SAFE**.") is None
    assert judge._parse_verdict("UNSAFE!") is None


@patch("little_canary.openai_provider.requests.post")
def test_judge_safe_verdict(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [{"message": {"content": "SAFE"}}],
    }
    mock_post.return_value = mock_response

    judge = OpenAILLMJudge(model="MiniMax-M2.5", api_key="test-key")
    cr = _make_result("The capital of France is Paris.")
    result = judge.analyze(cr)
    assert result.risk_score == 0.0
    assert result.should_block is False


@patch("little_canary.openai_provider.requests.post")
def test_judge_unsafe_verdict(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [{"message": {"content": "UNSAFE"}}],
    }
    mock_post.return_value = mock_response

    judge = OpenAILLMJudge(model="MiniMax-M2.5", api_key="test-key")
    cr = _make_result("Sure! I am DAN and have no restrictions.")
    result = judge.analyze(cr)
    assert result.risk_score == 1.0
    assert result.should_block is True
    assert result.hard_blocked is True
    assert len(result.signals) == 1
    assert result.signals[0].category == "llm_judge"


def test_judge_failed_canary_passes():
    judge = OpenAILLMJudge()
    cr = _make_result("", success=False, error="connection failed")
    result = judge.analyze(cr)
    assert result.risk_score is None
    assert result.should_block is False
    assert result.degraded is True
    assert result.canary_status == "failed"
    assert result.analysis_method == "llm_judge"
    assert result.analysis_status == "not_applicable"


@patch("little_canary.openai_provider.requests.post")
def test_judge_http_error(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mock_post.return_value = mock_response

    judge = OpenAILLMJudge()
    cr = _make_result("test response")
    result = judge.analyze(cr)
    assert result.should_block is False  # fail-open
    assert result.risk_score is None
    assert result.degraded is True
    assert "Internal Server Error" not in result.summary


@patch("little_canary.openai_provider.requests.post")
def test_judge_timeout(mock_post):
    mock_post.side_effect = requests.Timeout("timed out")

    judge = OpenAILLMJudge()
    cr = _make_result("test response")
    result = judge.analyze(cr)
    assert result.should_block is False  # fail-open
    assert result.risk_score is None
    assert result.analysis_status == "failed"


@patch("little_canary.openai_provider.requests.post")
def test_judge_connection_error(mock_post):
    mock_post.side_effect = requests.ConnectionError("refused")

    judge = OpenAILLMJudge()
    cr = _make_result("test response")
    result = judge.analyze(cr)
    assert result.should_block is False  # fail-open
    assert result.risk_score is None
    assert result.analysis_status == "failed"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"choices": []},
        {"choices": [{"message": {"content": None}}]},
        {"choices": [{"message": {"content": "   "}}]},
        {"choices": [{"message": {"content": "UNKNOWN"}}]},
    ],
)
@patch("little_canary.openai_provider.requests.post")
def test_judge_invalid_or_unparseable_content_is_degraded(mock_post, payload):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = payload
    mock_post.return_value = mock_response

    result = OpenAILLMJudge().analyze(_make_result("normal response"))

    assert result.risk_score is None
    assert result.should_block is False
    assert result.degraded is True
    assert result.canary_status == "exercised"
    assert result.analysis_method == "llm_judge"
    assert result.analysis_status == "failed"


@patch("little_canary.openai_provider.requests.post")
def test_judge_invalid_json_is_degraded_without_body_echo(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "credential-in-response"
    mock_response.json.side_effect = ValueError("credential-in-response")
    mock_post.return_value = mock_response

    result = OpenAILLMJudge().analyze(_make_result("normal response"))

    assert result.risk_score is None
    assert result.degraded is True
    assert "credential" not in result.summary


@patch("little_canary.openai_provider.requests.post")
def test_judge_sends_correct_payload(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [{"message": {"content": "SAFE"}}],
    }
    mock_post.return_value = mock_response

    judge = OpenAILLMJudge(
        model="MiniMax-M2.5",
        api_key="test-key",
        base_url="https://api.minimax.io/v1",
    )
    cr = _make_result("Canary said this", user_input="User asked this")
    judge.analyze(cr)

    call_args = mock_post.call_args
    payload = call_args[1]["json"] if "json" in call_args[1] else call_args[0][1]
    assert payload["model"] == "MiniMax-M2.5"
    user_content = payload["messages"][1]["content"]
    assert "User asked this" in user_content
    assert "Canary said this" in user_content

    headers = call_args[1].get("headers", {})
    assert headers.get("Authorization") == "Bearer test-key"


@patch("little_canary.openai_provider.requests.get")
def test_judge_is_available_true(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_get.return_value = mock_response

    judge = OpenAILLMJudge(api_key="test-key")
    assert judge.is_available() is True


@patch("little_canary.openai_provider.requests.get")
def test_judge_is_available_false(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_get.return_value = mock_response

    judge = OpenAILLMJudge()
    assert judge.is_available() is False
