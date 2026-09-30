"""`little-canary ingest` CLI: exit codes, file writing rules, output hygiene."""

import hashlib
import io
import json
import types
from unittest.mock import patch

import pytest

from little_canary import verify_export
from little_canary.cli import main
from little_canary.pipeline import PipelineVerdict, SecurityAdvisory

SENTINEL_TEXT = "SENTINEL-TEXT-4c1e-do-not-print"
SENTINEL_META = "SENTINEL-META-9b2d-do-not-print"


def _verdict(text, **kw):
    base = dict(safe=True, input=text, safe_input=text, total_latency=0.0,
                canary_status="exercised", analysis_status="exercised",
                canary_risk_score=0.0)
    base.update(kw)
    return PipelineVerdict(**base)


class FakePipeline:
    """Exercised pass unless the segment says otherwise; mirrors the real 4000-char limit."""

    def __init__(self, interrupt_on=None):
        self.calls = 0
        self.interrupt_on = interrupt_on
        self.structural_filter = types.SimpleNamespace(max_input_length=4000)

    def check(self, text):
        self.calls += 1
        if self.interrupt_on is not None and self.calls == self.interrupt_on:
            raise KeyboardInterrupt
        if "STRUCTBLK" in text:
            return _verdict(text, safe=False, blocked_by="structural_filter",
                            canary_status="skipped_after_block",
                            analysis_status="not_applicable", canary_risk_score=None)
        if "BLOCK" in text:
            return _verdict(text, safe=False, blocked_by="canary", canary_risk_score=0.9)
        if "FLAG" in text:
            return _verdict(text, canary_risk_score=0.4, advisory=SecurityAdvisory(
                flagged=True, severity="medium", signals=["sig_x"], message="m"))
        if "DEGRADE" in text:
            return _verdict(text, degraded=True, canary_status="failed", canary_risk_score=None)
        if "NOANALYSIS" in text:
            return _verdict(text, analysis_status="failed")
        if "BOOM" in text:
            raise RuntimeError("boom")
        return _verdict(text)


def _jsonl(*records):
    return "".join(json.dumps(r) + "\n" for r in records)


def _run(argv, capsys, stdin="", pipeline=None):
    pipeline = pipeline if pipeline is not None else FakePipeline()
    with patch("little_canary.pipeline.SecurityPipeline", return_value=pipeline), \
            patch("sys.stdin", io.StringIO(stdin)):
        code = main(argv)
    out = capsys.readouterr()
    return code, out, pipeline


@pytest.fixture
def paths(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    return types.SimpleNamespace(
        dir=out,
        input=tmp_path / "in.jsonl",
        manifest=out / "manifest.json",
        export=out / "export.json",
    )


def _ingest(paths, capsys, records, *extra, pipeline=None):
    paths.input.write_text(_jsonl(*records), encoding="utf-8")
    argv = ["ingest", str(paths.input), "--manifest", str(paths.manifest), *extra]
    return _run(argv, capsys, pipeline=pipeline)


def _summary_sha(out, label):
    line = next(ln for ln in out.splitlines() if ln.startswith(label + ":"))
    return line.split("sha256=")[1].split()[0]


def test_all_admitted_exits_0_and_writes_manifest_only(paths, capsys):
    code, out, p = _ingest(paths, capsys, ["one", {"id": "b", "text": "two"}])
    assert code == 0
    assert paths.manifest.exists() and not paths.export.exists()
    assert list(paths.dir.iterdir()) == [paths.manifest]
    manifest = json.loads(paths.manifest.read_text())
    assert manifest["counts"]["admitted"] == 2
    assert "export: not requested" in out.out
    assert len(out.out.strip().splitlines()) <= 10


@pytest.mark.parametrize("marker", ["FLAG", "BLOCK", "STRUCTBLK"])
def test_detection_only_holds_exit_1_and_still_write(paths, capsys, marker):
    code, out, _ = _ingest(paths, capsys, ["fine", f"text {marker}"])
    assert code == 1
    manifest = json.loads(paths.manifest.read_text())
    assert manifest["counts"]["held"] == 1


def test_detection_stop_on_long_record_is_still_detection_hold(paths, capsys):
    long_text = "BLOCK " + "x" * 5000  # 2 segments; stop after the first => incomplete too
    code, _, p = _ingest(paths, capsys, [long_text])
    rec = json.loads(paths.manifest.read_text())["records"][0]
    assert rec["hold_reasons"] == ["blocked", "incomplete"]
    assert code == 1 and p.calls == 1


@pytest.mark.parametrize("record", [
    "DEGRADE me",
    "NOANALYSIS",
    "BOOM",
    {"text": "t", "extra": 1},              # malformed (unknown key)
    "x" * 40000,                           # over_budget (segments)
])
def test_operational_holds_exit_2_and_still_write(paths, capsys, record):
    code, _, _ = _ingest(paths, capsys, ["fine", record])
    assert code == 2
    assert json.loads(paths.manifest.read_text())["counts"]["held"] == 1


def test_mixed_block_and_degraded_exits_2(paths, capsys):
    code, out, _ = _ingest(paths, capsys, ["text BLOCK", "DEGRADE me", "fine"], "--export", str(paths.export))
    assert code == 2
    counts = json.loads(paths.manifest.read_text())["counts"]
    assert counts["by_reason"]["blocked"] == 1 and counts["by_reason"]["degraded"] == 1
    assert len(json.loads(paths.export.read_text())["records"]) == 1


def test_empty_input_exits_2_and_writes_nothing(paths, capsys):
    paths.input.write_text("\n\n", encoding="utf-8")
    code, out, p = _run(["ingest", str(paths.input), "--manifest", str(paths.manifest),
                         "--export", str(paths.export)], capsys)
    assert code == 2 and p.calls == 0
    assert list(paths.dir.iterdir()) == []


def test_malformed_json_line_exits_2_and_writes_nothing(paths, capsys):
    paths.input.write_text('"ok"\nnot json\n', encoding="utf-8")
    code, out, p = _run(["ingest", str(paths.input), "--manifest", str(paths.manifest),
                         "--export", str(paths.export)], capsys)
    assert code == 2 and p.calls == 0 and "malformed JSON" in out.err
    assert list(paths.dir.iterdir()) == []


def test_export_contains_only_admitted_and_verifies(paths, capsys):
    records = [
        {"id": "a", "source": "s", "metadata": {"title": "t"}, "text": "keep me"},
        "text BLOCK",
        "DEGRADE",
        "also keep",
    ]
    code, out, _ = _ingest(paths, capsys, records, "--export", str(paths.export))
    assert code == 2
    manifest = json.loads(paths.manifest.read_text())
    export = json.loads(paths.export.read_text())
    assert [r["index"] for r in export["records"]] == [0, 3]
    assert [r["text"] for r in export["records"]] == ["keep me", "also keep"]
    assert verify_export(export, manifest) == []
    assert _summary_sha(out.out, "manifest") == hashlib.sha256(paths.manifest.read_bytes()).hexdigest()
    assert _summary_sha(out.out, "export") == hashlib.sha256(paths.export.read_bytes()).hexdigest()
    assert export["manifest_sha256"] == hashlib.sha256(paths.manifest.read_bytes()).hexdigest()


def test_existing_manifest_refused_without_overwrite_before_any_check(paths, capsys):
    paths.manifest.write_text("previous", encoding="utf-8")
    code, out, p = _ingest(paths, capsys, ["fine"], "--export", str(paths.export))
    assert code == 2 and p.calls == 0 and "--overwrite" in out.err
    assert paths.manifest.read_text() == "previous"
    assert not paths.export.exists()


def test_existing_export_refused_without_overwrite(paths, capsys):
    paths.export.write_text("previous", encoding="utf-8")
    code, _, p = _ingest(paths, capsys, ["fine"], "--export", str(paths.export))
    assert code == 2 and p.calls == 0
    assert not paths.manifest.exists() and paths.export.read_text() == "previous"


def test_overwrite_replaces_existing_files(paths, capsys):
    paths.manifest.write_text("previous", encoding="utf-8")
    paths.export.write_text("previous", encoding="utf-8")
    code, _, _ = _ingest(paths, capsys, ["fine"], "--export", str(paths.export), "--overwrite")
    assert code == 0
    manifest = json.loads(paths.manifest.read_text())
    assert verify_export(json.loads(paths.export.read_text()), manifest) == []


def test_same_manifest_and_export_path_exits_2(paths, capsys):
    code, out, p = _ingest(paths, capsys, ["fine"], "--export", str(paths.manifest))
    assert code == 2 and p.calls == 0 and "different" in out.err
    assert list(paths.dir.iterdir()) == []


def test_output_path_equal_to_input_refused(paths, capsys):
    paths.input.write_text('"fine"\n', encoding="utf-8")
    code, _, p = _run(["ingest", str(paths.input), "--manifest", str(paths.input), "--overwrite"], capsys)
    assert code == 2 and p.calls == 0
    assert paths.input.read_text() == '"fine"\n'


def test_json_prints_parseable_manifest_matching_file(paths, capsys):
    code, out, _ = _ingest(paths, capsys, ["fine", "text FLAG"], "--json")
    assert code == 1
    printed = json.loads(out.out)
    assert printed == json.loads(paths.manifest.read_text())
    assert printed["schema"] == "little-canary-ingest-manifest/v1"
    assert out.out.strip().encode("utf-8") == paths.manifest.read_bytes()


@pytest.mark.parametrize("extra", [[], ["--json"]])
def test_output_never_contains_record_text_or_metadata_values(paths, capsys, extra):
    records = [
        {"id": "a", "metadata": {"title": SENTINEL_META}, "text": SENTINEL_TEXT},
        {"metadata": {"author": SENTINEL_META}, "text": f"{SENTINEL_TEXT} BLOCK"},
        {"metadata": {"k": SENTINEL_META}, "text": f"{SENTINEL_TEXT} DEGRADE"},
        {"text": SENTINEL_TEXT, "bogus": SENTINEL_META},
    ]
    code, out, _ = _ingest(paths, capsys, records, "--export", str(paths.export), *extra)
    assert code == 2
    for stream in (out.out, out.err, paths.manifest.read_text()):
        assert SENTINEL_TEXT not in stream and SENTINEL_META not in stream


def test_stdin_dash_works(paths, capsys):
    code, out, p = _run(["ingest", "-", "--manifest", str(paths.manifest)], capsys,
                        stdin=_jsonl("one", "two"))
    assert code == 0 and p.calls == 2
    assert json.loads(paths.manifest.read_text())["counts"]["admitted"] == 2


def test_default_input_is_stdin(paths, capsys):
    code, _, _ = _run(["ingest", "--manifest", str(paths.manifest)], capsys, stdin='"one"\n')
    assert code == 0 and paths.manifest.exists()


def test_segment_chars_above_max_input_length_exits_2_with_zero_checks(paths, capsys):
    code, out, p = _ingest(paths, capsys, ["fine"], "--segment-chars", "5000")
    assert code == 2 and p.calls == 0 and "max_input_length" in out.err
    assert list(paths.dir.iterdir()) == []


@pytest.mark.parametrize("flag,value", [
    ("--segment-overlap", "3500"),
    ("--max-segments", "-1"),
    ("--max-item-bytes", str(10**30)),
    ("--max-metadata-keys", "-2"),
])
def test_invalid_policy_exits_2_with_zero_checks(paths, capsys, flag, value):
    code, _, p = _ingest(paths, capsys, ["fine"], flag, value)
    assert code == 2 and p.calls == 0
    assert list(paths.dir.iterdir()) == []


def test_run_level_limits_exit_2_with_nothing_written(paths, capsys):
    code, out, p = _ingest(paths, capsys, ["a", "b", "c"], "--max-items", "2")
    assert code == 2 and p.calls == 0 and "limit" in out.err
    assert list(paths.dir.iterdir()) == []


def test_invalid_timeout_env_exits_2(paths, capsys, monkeypatch):
    monkeypatch.setenv("LITTLE_CANARY_TIMEOUT", "abc")
    code, out, p = _ingest(paths, capsys, ["fine"])
    assert code == 2 and p.calls == 0 and "LITTLE_CANARY_TIMEOUT" in out.err
    assert list(paths.dir.iterdir()) == []


def test_missing_input_file_exits_2(paths, capsys):
    code, _, _ = _run(["ingest", str(paths.dir / "nope.jsonl"), "--manifest", str(paths.manifest)], capsys)
    assert code == 2 and not paths.manifest.exists()


def test_keyboard_interrupt_propagates_and_writes_nothing(paths, capsys):
    paths.input.write_text(_jsonl("first", "second", "third"), encoding="utf-8")
    pipeline = FakePipeline(interrupt_on=2)
    with pytest.raises(KeyboardInterrupt):
        _run(["ingest", str(paths.input), "--manifest", str(paths.manifest),
              "--export", str(paths.export)], capsys, pipeline=pipeline)
    assert pipeline.calls == 2
    assert list(paths.dir.iterdir()) == []  # no manifest, no export, no temp files


def test_help_lists_ingest_and_existing_commands(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for command in ("serve", "demo", "screen", "ingest"):
        assert command in out


def test_ingest_help_documents_contract(capsys):
    with pytest.raises(SystemExit):
        main(["ingest", "--help"])
    out = capsys.readouterr().out
    for flag in ("--manifest", "--export", "--overwrite", "--segment-chars", "--json"):
        assert flag in out
    assert "safe" not in out.lower().replace("--", "")


def test_manifest_is_required(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["ingest", "-"])
    assert exc.value.code == 2
