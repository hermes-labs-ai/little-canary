"""Tests for little_canary.canary — the sacrificial LLM probe (mocked HTTP)."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from little_canary.canary import CanaryProbe, CanaryResult

# ── CanaryResult dataclass ──


def test_canary_result_defaults():
    cr = CanaryResult(
        response="test",
        latency=0.1,
        model="test",
        system_prompt="test",
        user_input="test",
        success=True,
    )
    assert cr.metadata == {}
    assert cr.error is None


# ── CanaryProbe __init__ ──


def test_default_config():
    probe = CanaryProbe()
    assert probe.model == "qwen2.5:1.5b"
    assert probe.ollama_url == "http://localhost:11434"
    assert probe.temperature == 0.0
    assert probe.seed == 42
    assert probe.timeout == 10.0
    assert probe.max_tokens == 256


def test_custom_config():
    probe = CanaryProbe(
        model="gemma:2b",
        ollama_url="http://myhost:1234",
        timeout=5.0,
        max_tokens=128,
        temperature=0.1,
        seed=99,
    )
    assert probe.model == "gemma:2b"
    assert probe.ollama_url == "http://myhost:1234"
    assert probe.timeout == 5.0
    assert probe.max_tokens == 128
    assert probe.temperature == 0.1
    assert probe.seed == 99


def test_url_trailing_slash_stripped():
    probe = CanaryProbe(ollama_url="http://localhost:11434/")
    assert probe.ollama_url == "http://localhost:11434"


# ── test() method with mocked requests ──


@patch("little_canary.canary.requests.post")
def test_successful_probe(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "message": {"content": "The capital of France is Paris."},
        "total_duration": 250000000,
        "eval_count": 8,
        "eval_duration": 200000000,
    }
    mock_post.return_value = mock_response

    probe = CanaryProbe()
    result = probe.test("What is the capital of France?")

    assert result.success is True
    assert result.response == "The capital of France is Paris."
    assert result.model == "qwen2.5:1.5b"
    assert result.latency > 0


@patch("little_canary.canary.requests.post")
def test_probe_captures_response_content(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "message": {"content": "Hello world!"},
    }
    mock_post.return_value = mock_response

    probe = CanaryProbe()
    result = probe.test("Say hello")
    assert result.response == "Hello world!"


@patch("little_canary.canary.requests.post")
def test_probe_records_metadata(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "message": {"content": "test"},
        "total_duration": 123456,
        "eval_count": 5,
        "eval_duration": 100000,
    }
    mock_post.return_value = mock_response

    probe = CanaryProbe()
    result = probe.test("test")
    assert result.metadata["total_duration"] == 123456
    assert result.metadata["eval_count"] == 5


@patch("little_canary.canary.requests.post")
def test_probe_http_error(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mock_post.return_value = mock_response

    probe = CanaryProbe()
    result = probe.test("test")
    assert result.success is False
    assert "status 500" in result.error
    assert "Internal Server Error" not in result.error


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"message": {}},
        {"message": {"content": None}},
        {"message": {"content": 7}},
        {"message": {"content": "   "}},
        [],
    ],
)
@patch("little_canary.canary.requests.post")
def test_probe_rejects_invalid_or_empty_content(mock_post, payload):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = payload
    mock_post.return_value = mock_response

    result = CanaryProbe().test("test")

    assert result.success is False
    assert result.response == ""
    assert result.error == ("Ollama protocol error: response content must be a non-empty string")


@patch("little_canary.canary.requests.post")
def test_probe_rejects_invalid_json_without_echoing_body(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "secret-response-body"
    mock_response.json.side_effect = ValueError("secret-response-body")
    mock_post.return_value = mock_response

    result = CanaryProbe().test("test")

    assert result.success is False
    assert result.error == "Ollama protocol error: invalid JSON response"
    assert "secret" not in result.error


@patch("little_canary.canary.requests.post")
def test_probe_timeout(mock_post):
    mock_post.side_effect = requests.Timeout("Connection timed out")

    probe = CanaryProbe()
    result = probe.test("test")
    assert result.success is False
    assert "timed out" in result.error


@patch("little_canary.canary.requests.post")
def test_probe_connection_error(mock_post):
    mock_post.side_effect = requests.ConnectionError("Connection refused")

    probe = CanaryProbe()
    result = probe.test("test")
    assert result.success is False
    assert "Cannot connect" in result.error


@patch("little_canary.canary.requests.post")
def test_probe_connection_error_redacts_userinfo_query_and_path(mock_post):
    mock_post.side_effect = requests.ConnectionError("contains-secret")
    probe = CanaryProbe(ollama_url=("http://user:password@127.0.0.1:11434/private?api_key=query-secret"))

    result = probe.test("test")

    assert result.error == "Cannot connect to Ollama at http://127.0.0.1:11434"
    assert "user" not in result.error
    assert "password" not in result.error
    assert "private" not in result.error
    assert "query-secret" not in result.error


@patch("little_canary.canary.requests.post")
def test_probe_unexpected_error(mock_post):
    mock_post.side_effect = RuntimeError("Something went wrong")

    probe = CanaryProbe()
    result = probe.test("test")
    assert result.success is False
    assert result.error == "Canary probe failed (RuntimeError)"
    assert "Something went wrong" not in result.error


@patch("little_canary.canary.requests.post")
def test_probe_sends_correct_payload(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"message": {"content": "test"}}
    mock_post.return_value = mock_response

    probe = CanaryProbe(model="test-model", temperature=0.0, seed=42, max_tokens=256)
    probe.test("Hello world")

    call_args = mock_post.call_args
    payload = call_args[1]["json"] if "json" in call_args[1] else call_args[0][1]

    assert payload["model"] == "test-model"
    assert payload["stream"] is False
    assert payload["messages"][0]["role"] == "system"
    assert payload["messages"][1]["role"] == "user"
    assert payload["messages"][1]["content"] == "Hello world"
    assert payload["options"]["temperature"] == 0.0
    assert payload["options"]["seed"] == 42
    assert payload["options"]["num_predict"] == 256


# ── is_available() with mocked requests ──


@patch("little_canary.canary.requests.get")
def test_is_available_true(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "models": [
            {"name": "qwen2.5:1.5b"},
            {"name": "llama3:8b"},
        ]
    }
    mock_get.return_value = mock_response

    probe = CanaryProbe(model="qwen2.5:1.5b")
    assert probe.is_available() is True


@patch("little_canary.canary.requests.get")
def test_is_available_model_not_found(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"models": [{"name": "llama3:8b"}]}
    mock_get.return_value = mock_response

    probe = CanaryProbe(model="qwen2.5:1.5b")
    assert probe.is_available() is False


@patch("little_canary.canary.requests.get")
def test_is_available_connection_error(mock_get):
    mock_get.side_effect = requests.ConnectionError("Connection refused")
    probe = CanaryProbe()
    assert probe.is_available() is False


@patch("little_canary.canary.requests.get")
def test_is_available_http_error(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_get.return_value = mock_response

    probe = CanaryProbe()
    assert probe.is_available() is False
