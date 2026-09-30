"""Ingest eval runner: scoring separates detector errors from coverage holds (offline, no model)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from benchmarks.ingest_eval import run_eval
from little_canary import IngestPolicy, ingest_records
from little_canary.pipeline import PipelineVerdict

SENTINEL = "SENTINEL-4c1e-must-not-appear"


def _clock():
    return datetime(2026, 9, 29, 12, 0, 0, tzinfo=timezone.utc)


def _verdict(text, **kw):
    base = dict(safe=True, input=text, safe_input=text, total_latency=0.25,
                canary_status="exercised", analysis_status="exercised", canary_risk_score=0.0)
    base.update(kw)
    return PipelineVerdict(**base)


class ScriptedPipeline:
    """Exercised pass by default; BLOCK blocks, DEGRADE is fail-open degraded."""

    def check(self, text):
        if "BLOCK" in text:
            return _verdict(text, safe=False, blocked_by="canary", canary_risk_score=0.9)
        if "DEGRADE" in text:
            return _verdict(text, degraded=True, canary_status="failed", canary_risk_score=None)
        return _verdict(text)


def _score(pipeline, rows, **policy_kw):
    """rows: (label, vector, record dict without id). Returns the score document."""
    records, expectations = [], {}
    for n, (label, vector, rec) in enumerate(rows, 1):
        nid = run_eval.neutral_id(n)
        records.append({"id": nid, "source": run_eval.NEUTRAL_SOURCE, **rec})
        expectations[nid] = {"original_id": f"orig-{n}", "original_source": None,
                             "label": label, "vector": vector}
    result = ingest_records(pipeline, records, policy=IngestPolicy(**policy_kw), now=_clock)
    return result, run_eval.score(result, expectations)


def _outcomes(scored):
    return [r["outcome"] for r in scored["records"]]


def test_injected_under_degraded_canary_is_coverage_hold_not_miss():
    result, scored = _score(ScriptedPipeline(), [("injected", "text_start", {"text": "DEGRADE me"})])
    assert result.records[0].hold_reasons[0] == "degraded"
    assert _outcomes(scored) == ["coverage_hold"]
    assert scored["totals"]["miss"] == 0


def test_benign_blocked_is_false_hold_not_coverage_hold():
    _, scored = _score(ScriptedPipeline(), [("benign", "none", {"text": "please BLOCK this"})])
    assert _outcomes(scored) == ["false_hold"]
    assert scored["totals"]["coverage_hold"] == 0


def test_injected_admitted_is_miss_and_benign_admitted_is_admitted_benign():
    _, scored = _score(ScriptedPipeline(), [
        ("injected", "text_end", {"text": "quiet payload"}),
        ("benign", "none", {"text": "ordinary note"}),
    ])
    assert _outcomes(scored) == ["miss", "admitted_benign"]
    rates = scored["rates"]
    assert rates["miss_of_detector_decided_injected"] == {"numerator": 1, "denominator": 1, "value": 1.0}


def test_over_budget_record_is_coverage_hold():
    _, scored = _score(
        ScriptedPipeline(), [("injected", "long_text", {"text": "x" * 50})],
        segment_chars=10, segment_overlap=0, max_segments=2,
    )
    rec = scored["records"][0]
    assert rec["hold_reasons"] == ["over_budget"]
    assert rec["outcome"] == "coverage_hold"
    assert scored["checks_performed"] == 0


def test_blocked_with_incomplete_is_true_hold():
    # metadata is checked first; the block stops the record early, so 'incomplete' co-occurs.
    result, scored = _score(ScriptedPipeline(), [
        ("injected", "metadata", {"text": "benign body", "metadata": {"title": "BLOCK title"}}),
    ])
    reasons = result.records[0].hold_reasons
    assert "blocked" in reasons and "incomplete" in reasons
    assert _outcomes(scored) == ["true_hold"]


def test_classify_outcome_prefers_detection_reasons():
    assert run_eval.classify_outcome("injected", "held", ["flagged", "incomplete"]) == "true_hold"
    assert run_eval.classify_outcome("benign", "held", ["degraded", "incomplete"]) == "coverage_hold"
    for reason in ("malformed", "over_budget", "degraded", "unexercised", "error", "incomplete"):
        assert run_eval.classify_outcome("injected", "held", [reason]) == "coverage_hold"
        assert run_eval.classify_outcome("benign", "held", [reason]) == "coverage_hold"


def test_latency_stats_cover_exercised_segments_only():
    result, scored = _score(ScriptedPipeline(), [
        ("benign", "none", {"text": "a"}),
        ("injected", "text_start", {"text": "DEGRADE"}),
    ])
    lat = scored["latency_seconds"]
    # record 1: metadata + text exercised; record 2: metadata exercised, text degraded
    assert lat["segments"] == 3
    assert lat["min"] == lat["median"] == lat["p95"] == lat["max"] == 0.25


def test_load_corpus_anonymizes_and_strips_expect():
    records, expectations = run_eval.load_corpus(run_eval.DEFAULT_CORPUS)
    originals = [json.loads(line)["id"] for line in run_eval.DEFAULT_CORPUS.read_text("utf-8").splitlines()
                 if line.strip()]
    assert len(records) == len(originals) == len(expectations)
    for n, rec in enumerate(records, 1):
        assert "expect" not in rec
        assert rec["id"] == f"doc-{n:04d}"
        assert rec["source"] == "corpus"
        assert "inj" not in rec["id"] and "benign" not in rec["id"]
        assert "inj" not in rec["source"] and "benign" not in rec["source"]
        assert set(expectations[rec["id"]]) == {"original_id", "original_source", "label", "vector"}
    assert [expectations[r["id"]]["original_id"] for r in records] == originals
    # deterministic
    again, _ = run_eval.load_corpus(run_eval.DEFAULT_CORPUS)
    assert [r["id"] for r in again] == [r["id"] for r in records]


def test_offline_fake_on_corpus_has_no_malformed_holds_and_matches_labels():
    records, expectations = run_eval.load_corpus(run_eval.DEFAULT_CORPUS)
    result = ingest_records(run_eval.OfflineFakePipeline(), records, now=_clock)
    assert all("malformed" not in rec.hold_reasons for rec in result.records)
    scored = run_eval.score(result, expectations)
    assert sum(scored["totals"].values()) == len(records)
    by_orig = {r["original_id"]: r for r in scored["records"]}
    assert by_orig["benign-over-budget-01"]["outcome"] == "coverage_hold"
    assert by_orig["benign-over-budget-01"]["hold_reasons"] == ["over_budget"]
    for row in scored["records"]:
        if row["label"] == "benign":
            assert row["outcome"] in {"false_hold", "admitted_benign", "coverage_hold"}
        else:
            assert row["outcome"] in {"true_hold", "miss", "coverage_hold"}


def test_select_by_ids_and_limit():
    records, expectations = run_eval.load_corpus(run_eval.DEFAULT_CORPUS)
    chosen, exp = run_eval.select(records, expectations, ids=["inj-long-01", "benign-email-01"])
    assert [exp[r["id"]]["original_id"] for r in chosen] == ["benign-email-01", "inj-long-01"]
    chosen, _ = run_eval.select(records, expectations, limit=3)
    assert [r["id"] for r in chosen] == ["doc-0001", "doc-0002", "doc-0003"]


def test_main_offline_fake_json_schema(capsys):
    assert run_eval.main(["--offline-fake", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["schema"] == "little-canary-ingest-eval/v1"
    assert doc["mode"] == "offline-fake"
    total = doc["corpus"]["records_total"]
    assert total == doc["corpus"]["records_run"] == 47
    assert sum(doc["score"]["totals"].values()) == total
    assert sum(b["records"] for b in doc["score"]["by_vector"].values()) == total
    assert doc["score"]["checks_performed"] == doc["run"]["checks_performed"] > 0
    assert doc["ingest_counts"]["by_reason"]["malformed"] == 0


def test_main_unknown_id_and_existing_manifest_exit_2(tmp_path, capsys):
    assert run_eval.main(["--offline-fake", "--ids", "no-such-id"]) == 2
    existing = tmp_path / "m.json"
    existing.write_text("{}", encoding="utf-8")
    assert run_eval.main(["--offline-fake", "--manifest", str(existing)]) == 2
    assert existing.read_text(encoding="utf-8") == "{}"


def test_output_has_no_record_text_and_no_harmlessness_claim(tmp_path, capsys):
    corpus = tmp_path / "corpus.jsonl"
    rows = [
        {"id": "benign-a", "source": "s", "text": f"{SENTINEL} plain body",
         "expect": {"label": "benign", "vector": "none", "note": "n"}},
        {"id": "inj-b", "source": "s", "text": f"{SENTINEL} MARKERX payload",
         "metadata": {"title": SENTINEL}, "expect": {"label": "injected", "vector": "text_start",
                                                     "note": "n", "payload": "MARKERX"}},
        {"id": "inj-c", "source": "s", "text": f"quiet {SENTINEL}",
         "expect": {"label": "injected", "vector": "text_end", "note": "n", "payload": "quiet"}},
    ]
    corpus.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    common = [str(corpus), "--offline-fake", "--fake-marker", "markerx"]
    assert run_eval.main([*common, "--manifest", str(manifest)]) == 0
    table = capsys.readouterr()
    assert run_eval.main([*common, "--json"]) == 0
    js = capsys.readouterr()
    for out in (table.out, table.err, js.out, js.err, manifest.read_text(encoding="utf-8")):
        assert SENTINEL not in out
        assert "MARKERX" not in out and "payload" not in out
    # the runner's own output makes no harmlessness claim (the manifest's redacted
    # verdict dicts carry PipelineVerdict's boolean field name, which is not a claim)
    for out in (table.out, table.err, js.out, js.err):
        assert not re.search(r"\bsafe\b", out, re.IGNORECASE)
    doc = json.loads(js.out)
    assert [r["outcome"] for r in doc["score"]["records"]] == ["admitted_benign", "true_hold", "miss"]
    # the manifest carries only neutral ids
    ids = [r["id"] for r in json.loads(manifest.read_text(encoding="utf-8"))["records"]]
    assert ids == ["doc-0001", "doc-0002", "doc-0003"]
    assert "not a benchmark" in table.out
