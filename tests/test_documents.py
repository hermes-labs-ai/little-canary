"""Offline document-boundary controls; every classifier request is mocked."""

import io
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from little_canary import cli
from little_canary.documents import DocumentInspectionError, guard_document, inspect_document


def pipeline():
    return SimpleNamespace(
        provider="ollama",
        canary_probe=SimpleNamespace(ollama_url="http://127.0.0.1:11434", timeout=10),
        structural_filter=SimpleNamespace(max_input_length=4000),
    )


def response(decision="INFORMATION", **metadata):
    return Mock(json=Mock(return_value={
        "done": True, "done_reason": "stop", "message": {"content": f'{{"decision":"{decision}"}}'}, **metadata,
    }))


def test_guard_checks_every_overlapping_chunk_and_returns_original(monkeypatch):
    post = Mock(side_effect=[response(), response(), response(), response()])
    monkeypatch.setattr("little_canary.documents.requests.post", post)
    text = "  abcdefghijklmnopqr  "
    assert guard_document(pipeline(), text, chunk_chars=8, overlap=2, context_model="local") == text
    chunks = [call.kwargs["json"]["messages"][1]["content"] for call in post.call_args_list]
    assert chunks == ["Document text:\n" + text[start:start + 8] for start in (0, 6, 12, 18)]
    assert all(call.kwargs["allow_redirects"] is False for call in post.call_args_list)


@pytest.mark.parametrize("failed", [
    requests.ConnectionError("offline"), response(done=False), response("INVALID"),
    Mock(json=Mock(return_value={"done": True, "done_reason": "length"})),
])
def test_failed_later_classifier_chunk_never_forwards(monkeypatch, failed):
    post = Mock(side_effect=[response(), failed])
    monkeypatch.setattr("little_canary.documents.requests.post", post)
    with pytest.raises(DocumentInspectionError) as caught:
        guard_document(pipeline(), "abcdefghijklmno", chunk_chars=8, overlap=2, context_model="local")
    assert caught.value.result.decision == "INSUFFICIENTLY INSPECTED"
    assert caught.value.result.chars_inspected == 8
    assert post.call_count == 2


def test_instruction_chunk_blocks_without_checking_or_forwarding_rest(monkeypatch):
    post = Mock(return_value=response("INSTRUCTION"))
    monkeypatch.setattr("little_canary.documents.requests.post", post)
    with pytest.raises(DocumentInspectionError) as caught:
        guard_document(pipeline(), "abcdefghijklmno", chunk_chars=8, overlap=2, context_model="local")
    assert caught.value.result.decision == "BLOCK"
    assert caught.value.result.inspection == "INCOMPLETE"
    assert post.call_count == 1


def test_budget_hold_never_calls_classifier(monkeypatch):
    post = Mock()
    monkeypatch.setattr("little_canary.documents.requests.post", post)
    result = inspect_document(pipeline(), "x" * 9, chunk_chars=8, overlap=2, max_chars=8, context_model="local")
    assert result.decision == "INSUFFICIENTLY INSPECTED"
    post.assert_not_called()


@pytest.mark.parametrize("verdict,code,decision", [
    (response(), 0, "FORWARD"), (response("INSTRUCTION"), 1, "BLOCK"),
    (requests.ConnectionError("offline"), 2, "INSUFFICIENTLY INSPECTED"),
])
def test_document_cli_reports_decision_without_echoing_document(monkeypatch, capsys, verdict, code, decision):
    monkeypatch.setattr("little_canary.SecurityPipeline", Mock(return_value=pipeline()))
    monkeypatch.setattr("little_canary.documents.requests.post", Mock(side_effect=[verdict]))
    monkeypatch.setattr("sys.stdin", io.StringIO("private document bytes"))
    assert cli.main(["check", "--document", "--context-model", "local"]) == code
    output = capsys.readouterr().out
    assert f"DECISION   {decision}" in output
    assert "private document bytes" not in output
