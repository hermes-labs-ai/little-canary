"""Optional real-framework contracts; install requirements-framework-examples.txt.

The checker and downstream callable are local fakes. FastAPI request handling,
TestClient transport, LangChain messages and Runnable composition are real.
"""

from __future__ import annotations

import socket
from unittest.mock import Mock, call

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("langchain_core")

from fastapi.testclient import TestClient  # noqa: E402
from langchain_core.messages import HumanMessage, SystemMessage  # noqa: E402
from langchain_core.runnables import RunnableLambda, RunnableSequence  # noqa: E402

from examples.fastapi_example import create_app  # noqa: E402
from examples.langchain_example import build_chain  # noqa: E402
from little_canary.pipeline import PipelineVerdict, SecurityAdvisory  # noqa: E402


@pytest.fixture(autouse=True)
def offline_frameworks(monkeypatch):
    # Disable optional LangSmith tracing even if enabled in the developer shell.
    monkeypatch.setenv("LANGSMITH_TRACING", "false")
    monkeypatch.setenv("LANGCHAIN_TRACING_V2", "false")

    def deny_connection(*args, **kwargs):
        pytest.fail("Framework contract tests must not open a network connection")

    monkeypatch.setattr(socket.socket, "connect", deny_connection)
    monkeypatch.setattr(socket.socket, "connect_ex", deny_connection)


def verdict(**overrides):
    values = dict(
        safe=True,
        input="Hello",
        safe_input="Hello",
        total_latency=0.0,
        summary="Passed all layers",
        canary_risk_score=0.0,
        advisory=SecurityAdvisory(flagged=False, severity="none", signals=[], message=""),
        degraded=False,
        canary_status="exercised",
        analysis_method="regex",
        analysis_status="exercised",
    )
    values.update(overrides)
    return PipelineVerdict(**values)


def advisory():
    return SecurityAdvisory(
        flagged=True, severity="medium", signals=["instruction_echo"], message="Use caution."
    )


@pytest.mark.parametrize("flagged", [False, True])
def test_real_fastapi_answer_and_advisory(flagged):
    expected = verdict(advisory=advisory()) if flagged else verdict()
    calls = Mock()
    calls.check.return_value = expected
    calls.model.return_value = "local response"

    with TestClient(create_app(checker=calls, model=calls.model)) as client:
        response = client.post("/chat", json={"message": "Hello"})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "answered"
    assert body["allowed"] is True
    assert body["response"] == "local response"
    assert body["verdict"]["degraded"] is False
    assert body["verdict"]["advisory"]["flagged"] is flagged
    prefix = expected.advisory.to_system_prefix()
    assert body["verdict"]["advisory"]["system_prefix"] == prefix
    assert calls.mock_calls == [
        call.check("Hello"),
        call.model(user_message="Hello", system_prompt=prefix),
    ]


@pytest.mark.parametrize(
    ("request_kwargs", "status"),
    [
        ({"json": {}}, 400),
        ({"json": {"message": " \t"}}, 400),
        ({"json": {"message": 123}}, 400),
        ({"json": {"message": None}}, 400),
        ({"json": []}, 422),
        ({"json": "Hello"}, 422),
        ({}, 422),
        ({"content": "{", "headers": {"content-type": "application/json"}}, 422),
    ],
)
def test_real_fastapi_rejects_invalid_body_before_screening(request_kwargs, status):
    checker, model = Mock(), Mock()
    with TestClient(create_app(checker=checker, model=model)) as client:
        response = client.post("/chat", **request_kwargs)
    assert response.status_code == status
    assert "detail" in response.json()
    checker.check.assert_not_called()
    model.assert_not_called()


@pytest.mark.parametrize(
    ("overrides", "status", "http_status"),
    [
        ({"safe": False, "blocked_by": "canary_probe"}, "blocked", 403),
        ({"degraded": True, "canary_status": "failed"}, "degraded", 503),
    ],
)
def test_real_fastapi_holds_before_downstream_model(overrides, status, http_status):
    checker = Mock()
    checker.check.return_value = verdict(**overrides)
    model = Mock()
    with TestClient(create_app(checker=checker, model=model)) as client:
        response = client.post("/chat", json={"message": "Hello"})
    assert response.status_code == http_status
    detail = response.json()["detail"]
    assert detail["status"] == status
    assert detail["allowed"] is False
    assert detail["verdict"]["safe"] is (status != "blocked")
    assert detail["verdict"]["degraded"] is (status == "degraded")
    checker.check.assert_called_once_with("Hello")
    model.assert_not_called()


@pytest.mark.parametrize("flagged", [False, True])
def test_real_langchain_invoke_and_advisory(flagged):
    expected = verdict(advisory=advisory()) if flagged else verdict()
    checker = Mock()
    checker.check.return_value = expected
    received = []

    def downstream(messages):
        checker.check.assert_called_once_with("Hello")
        received.append(messages)
        return "local response"

    chain = build_chain(RunnableLambda(downstream), checker=checker)
    assert isinstance(chain, RunnableSequence)
    result = chain.invoke({"input": "", "question": "Hello"})

    assert result["status"] == "answered"
    assert result["allowed"] is True
    assert result["output"] == "local response"
    assert result["verdict"]["degraded"] is False
    assert result["verdict"]["advisory"]["flagged"] is flagged
    assert len(received) == 1
    messages = received[0]
    assert len(messages) == (2 if flagged else 1)
    assert isinstance(messages[-1], HumanMessage)
    assert messages[-1].content == "Hello"
    if flagged:
        assert isinstance(messages[0], SystemMessage)
        assert messages[0].content == expected.advisory.to_system_prefix()
        assert "SECURITY ADVISORY" in messages[0].content
        assert "Hello" not in messages[0].content


@pytest.mark.parametrize(
    ("overrides", "status"),
    [
        ({"safe": False, "blocked_by": "canary_probe"}, "blocked"),
        ({"degraded": True, "canary_status": "failed"}, "degraded"),
    ],
)
def test_real_langchain_holds_before_downstream_runnable(overrides, status):
    checker = Mock()
    checker.check.return_value = verdict(**overrides)
    downstream = Mock()
    chain = build_chain(RunnableLambda(downstream), checker=checker)

    result = chain.invoke("Hello")

    assert result["status"] == status
    assert result["allowed"] is False
    assert result["verdict"]["safe"] is (status != "blocked")
    assert result["verdict"]["degraded"] is (status == "degraded")
    checker.check.assert_called_once_with("Hello")
    downstream.assert_not_called()


def test_real_langchain_holds_missing_prompt_without_screening():
    checker, downstream = Mock(), Mock()
    result = build_chain(RunnableLambda(downstream), checker=checker).invoke({"question": " "})
    assert result["status"] == "unscreened"
    assert result["allowed"] is False
    assert result["verdict"] is None
    checker.check.assert_not_called()
    downstream.assert_not_called()
