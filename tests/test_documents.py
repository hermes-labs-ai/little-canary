"""Offline document-boundary controls; every classifier request is mocked."""

import io
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from little_canary import cli
from little_canary.documents import DocumentInspectionError, guard_document, inspect_document
from little_canary.pipeline import PipelineVerdict, SecurityAdvisory


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


@pytest.mark.parametrize("model", ["", "  ", "\t"])
def test_blank_context_model_is_usage_error_before_pipeline(monkeypatch, capsys, model):
    factory = Mock()
    monkeypatch.setattr("little_canary.SecurityPipeline", factory)
    with pytest.raises(SystemExit) as caught:
        cli.main(["check", "--document", "--context-model", model])
    assert caught.value.code == 2
    assert "nonempty model name" in capsys.readouterr().err
    factory.assert_not_called()


@pytest.mark.parametrize("context_model", [None, "local"])
def test_excessive_overlap_holds_before_either_inspection_path(monkeypatch, context_model):
    post = Mock()
    monkeypatch.setattr("little_canary.documents.requests.post", post)
    pipe = pipeline()
    pipe.check = Mock()
    result = inspect_document(pipe, "x" * 24000, overlap=3499, context_model=context_model)
    assert result.decision == "INSUFFICIENTLY INSPECTED"
    assert result.chunks_total == 20501
    assert result.chunks_checked == result.chars_inspected == 0
    post.assert_not_called()
    pipe.check.assert_not_called()


def test_default_document_budget_allows_all_eight_chunks(monkeypatch):
    post = Mock(return_value=response())
    monkeypatch.setattr("little_canary.documents.requests.post", post)
    text = "x" * 24000
    assert guard_document(pipeline(), text, context_model="local") == text
    assert post.call_count == 8


def pipeline_verdict(**overrides):
    values = dict(safe=True, input="private text", safe_input="private text", total_latency=0,
                  canary_status="exercised", analysis_status="exercised", canary_risk_score=0)
    values.update(overrides)
    return PipelineVerdict(**values)


def flagged_verdict():
    return pipeline_verdict(advisory=SecurityAdvisory(True, "low", ["signal"], "Review input"))


def test_default_pipeline_checks_every_chunk_and_returns_original():
    pipe = pipeline()
    pipe.check = Mock(return_value=pipeline_verdict())
    text = "  abcdefghijklmnopqr  "
    assert guard_document(pipe, text, chunk_chars=8, overlap=2) == text
    assert [call.args[0] for call in pipe.check.call_args_list] == [text[start:start + 8] for start in (0, 6, 12, 18)]


@pytest.mark.parametrize("verdict,decision,inspection", [
    (pipeline_verdict(safe=False, blocked_by="structural", canary_status="skipped_after_block"), "BLOCK", "INCOMPLETE"),
    (pipeline_verdict(degraded=True), "INSUFFICIENTLY INSPECTED", "DEGRADED"),
    (pipeline_verdict(canary_status="disabled"), "INSUFFICIENTLY INSPECTED", "INCOMPLETE"),
    (flagged_verdict(), "BLOCK", "FLAGGED"),
])
def test_default_pipeline_holds_second_chunk_without_forwarding_rest(verdict, decision, inspection):
    pipe = pipeline()
    pipe.check = Mock(side_effect=[pipeline_verdict(), verdict])
    with pytest.raises(DocumentInspectionError) as caught:
        guard_document(pipe, "abcdefghijklmnopqr", chunk_chars=8, overlap=2)
    assert caught.value.result.decision == decision
    assert caught.value.result.inspection == inspection
    assert pipe.check.call_count == 2


@pytest.mark.parametrize("verdict,code,decision", [
    (pipeline_verdict(), 0, "FORWARD"),
    (pipeline_verdict(safe=False, blocked_by="structural", canary_status="skipped_after_block"), 1, "BLOCK"),
    (flagged_verdict(), 0, "FORWARD"),
    (pipeline_verdict(degraded=True), 2, "INSUFFICIENTLY INSPECTED"),
    (pipeline_verdict(canary_status="disabled"), 2, "INSUFFICIENTLY INSPECTED"),
])
def test_plain_check_cli_decisions_and_advisory(monkeypatch, capsys, verdict, code, decision):
    pipe = pipeline()
    pipe.check = Mock(return_value=verdict)
    monkeypatch.setattr("little_canary.SecurityPipeline", Mock(return_value=pipe))
    monkeypatch.setattr("sys.stdin", io.StringIO("private document bytes"))
    assert cli.main(["check"]) == code
    pipe.check.assert_called_once_with("private document bytes")
    output = capsys.readouterr().out
    assert f"DECISION   {decision}" in output
    assert ("ADVISORY   Review input" in output) == bool(verdict.advisory)
    assert "private document bytes" not in output
