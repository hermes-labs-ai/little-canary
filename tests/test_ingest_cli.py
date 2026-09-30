"""`little-canary ingest` CLI: exit codes, file writing rules, output hygiene."""

import errno
import hashlib
import io
import json
import os
import socket
import tempfile
import types
from unittest.mock import patch

import pytest
import requests

from little_canary import batch, verify_export
from little_canary import canary as canary_module
from little_canary.canary import DEFAULT_CANARY_SYSTEM_PROMPT
from little_canary.cli import main
from little_canary.ingest import MAX_METADATA_KEY_CHARS
from little_canary.pipeline import PipelineVerdict, SecurityAdvisory

SENTINEL_TEXT = "SENTINEL-TEXT-4c1e-do-not-print"
SENTINEL_META = "SENTINEL-META-9b2d-do-not-print"
SENTINEL_ID = "SENTINEL-ID-71aa-do-not-print"
SENTINEL_SOURCE = "SENTINEL-SOURCE-5e03-do-not-print"
SENTINEL_KEY = "SENTINEL-KEY-c8f6-do-not-print"


class UnexpectedRequest(BaseException):
    """Not an ``Exception``: the probe's broad ``except Exception`` cannot swallow it."""


class _Response:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class RequestGuard:
    """Replaces ``requests.post``/``get`` as seen by ``little_canary.canary``.

    Every call is recorded. A call is answered only by a route the test registered
    (``routes[path] = handler(url, json)``) or forwarded for real only to an origin
    the test explicitly allowed; anything else raises ``UnexpectedRequest`` and the
    teardown fails the test, so no test can reach the live Ollama on this VM.
    """

    def __init__(self, real_post, real_get):
        self._real = {"POST": real_post, "GET": real_get}
        self.routes = {}
        self.allowed_origins = set()
        self.calls = []
        self.unexpected = []

    def _handle(self, method, url, **kw):
        self.calls.append((method, url))
        for origin in self.allowed_origins:
            if url.startswith(origin + "/"):
                return self._real[method](url, **kw)
        for path, handler in self.routes.items():
            if url.endswith(path):
                return handler(url, kw.get("json"))
        self.unexpected.append((method, url))
        raise UnexpectedRequest(f"unexpected {method} {url}")

    def post(self, url, **kw):
        return self._handle("POST", url, **kw)

    def get(self, url, **kw):
        return self._handle("GET", url, **kw)

    def paths(self, suffix):
        return [url for _, url in self.calls if url.endswith(suffix)]


@pytest.fixture(autouse=True)
def http(monkeypatch):
    guard = RequestGuard(canary_module.requests.post, canary_module.requests.get)
    monkeypatch.setattr(canary_module.requests, "post", guard.post)
    monkeypatch.setattr(canary_module.requests, "get", guard.get)
    yield guard
    assert guard.unexpected == [], f"unintended HTTP request(s): {guard.unexpected}"


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
    """``stdin`` is a str (text-only stand-in, no ``.buffer``) or a ready stream object."""
    pipeline = pipeline if pipeline is not None else FakePipeline()
    stream = io.StringIO(stdin) if isinstance(stdin, str) else stdin
    with patch("little_canary.pipeline.SecurityPipeline", return_value=pipeline), \
            patch("sys.stdin", stream):
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
    line = next(ln for ln in out.splitlines() if ln.startswith(label + ":") or ln.startswith(label + " "))
    return line.split("sha256=")[1].split()[0]


def _byte_stdin(data):
    """A stdin stand-in that HAS ``.buffer``; its own decoding (latin-1) is deliberately lax."""
    return io.TextIOWrapper(io.BytesIO(data), encoding="latin-1")


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


def test_empty_input_exits_3_and_writes_nothing(paths, capsys):
    paths.input.write_text("\n\n", encoding="utf-8")
    code, out, p = _run(["ingest", str(paths.input), "--manifest", str(paths.manifest),
                         "--export", str(paths.export)], capsys)
    assert code == 3 and p.calls == 0
    assert list(paths.dir.iterdir()) == []


@pytest.mark.parametrize("bad_line", [
    "not json",
    '{"text": "a", "text": "b"}',                                   # duplicate top-level key
    '{"text": "a", "metadata": {"k": "1", "k": "2"}}',              # duplicate nested key
])
def test_malformed_json_line_exits_3_and_writes_nothing(paths, capsys, bad_line):
    paths.input.write_text('"ok"\n' + bad_line + "\n", encoding="utf-8")
    code, out, p = _run(["ingest", str(paths.input), "--manifest", str(paths.manifest),
                         "--export", str(paths.export)], capsys)
    assert code == 3 and p.calls == 0 and "malformed JSON" in out.err
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
    assert code == 3 and p.calls == 0 and "--overwrite" in out.err
    assert paths.manifest.read_text() == "previous"
    assert not paths.export.exists()


def test_existing_export_refused_without_overwrite(paths, capsys):
    paths.export.write_text("previous", encoding="utf-8")
    code, _, p = _ingest(paths, capsys, ["fine"], "--export", str(paths.export))
    assert code == 3 and p.calls == 0
    assert not paths.manifest.exists() and paths.export.read_text() == "previous"


def test_overwrite_replaces_existing_files(paths, capsys):
    paths.manifest.write_text("previous", encoding="utf-8")
    paths.export.write_text("previous", encoding="utf-8")
    code, _, _ = _ingest(paths, capsys, ["fine"], "--export", str(paths.export), "--overwrite")
    assert code == 0
    manifest = json.loads(paths.manifest.read_text())
    assert verify_export(json.loads(paths.export.read_text()), manifest) == []


def test_same_manifest_and_export_path_exits_3(paths, capsys):
    code, out, p = _ingest(paths, capsys, ["fine"], "--export", str(paths.manifest))
    assert code == 3 and p.calls == 0 and "different" in out.err
    assert list(paths.dir.iterdir()) == []


def test_output_path_equal_to_input_refused(paths, capsys):
    paths.input.write_text('"fine"\n', encoding="utf-8")
    code, _, p = _run(["ingest", str(paths.input), "--manifest", str(paths.input), "--overwrite"], capsys)
    assert code == 3 and p.calls == 0
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
    # Labels/key names of HELD records must not appear anywhere either (digests only).
    held_labels = {"id": SENTINEL_ID, "source": SENTINEL_SOURCE}
    records = [
        {"id": "a", "metadata": {"title": SENTINEL_META}, "text": SENTINEL_TEXT},
        {**held_labels, "metadata": {"author": SENTINEL_META, SENTINEL_KEY: "v"}, "text": f"{SENTINEL_TEXT} BLOCK"},
        {**held_labels, "metadata": {"k": SENTINEL_META, SENTINEL_KEY: "v"}, "text": f"{SENTINEL_TEXT} DEGRADE"},
        {**held_labels, "text": SENTINEL_TEXT, "bogus": SENTINEL_META},              # malformed
        {**held_labels, "metadata": {SENTINEL_KEY: "v"}, "text": "x" * 40000},        # over_budget
    ]
    code, out, _ = _ingest(paths, capsys, records, "--export", str(paths.export), *extra)
    assert code == 2
    sentinels = (SENTINEL_TEXT, SENTINEL_META, SENTINEL_ID, SENTINEL_SOURCE, SENTINEL_KEY)
    for stream in (out.out, out.err, paths.manifest.read_text()):
        for sentinel in sentinels:
            assert sentinel not in stream
    manifest = json.loads(paths.manifest.read_text())
    held = [r for r in manifest["records"] if r["admission"] != "admitted"]
    assert [r["index"] for r in held] == [1, 2, 3, 4]
    id_digest = hashlib.sha256(SENTINEL_ID.encode("utf-8")).hexdigest()
    source_digest = hashlib.sha256(SENTINEL_SOURCE.encode("utf-8")).hexdigest()
    for rec in held:
        assert rec["id"] is None and rec["source"] is None and rec["metadata_keys"] is None
        assert rec["id_sha256"] == id_digest and rec["source_sha256"] == source_digest
    assert manifest["records"][0]["id"] == "a" and manifest["records"][0]["metadata_keys"] == ["title"]


def test_stdin_dash_works(paths, capsys):
    code, out, p = _run(["ingest", "-", "--manifest", str(paths.manifest)], capsys,
                        stdin=_jsonl("one", "two"))
    assert code == 0 and p.calls == 2
    assert json.loads(paths.manifest.read_text())["counts"]["admitted"] == 2


def test_default_input_is_stdin(paths, capsys):
    code, _, _ = _run(["ingest", "--manifest", str(paths.manifest)], capsys, stdin='"one"\n')
    assert code == 0 and paths.manifest.exists()


def test_segment_chars_above_max_input_length_exits_3_with_zero_checks(paths, capsys):
    code, out, p = _ingest(paths, capsys, ["fine"], "--segment-chars", "5000")
    assert code == 3 and p.calls == 0 and "max_input_length" in out.err
    assert list(paths.dir.iterdir()) == []


@pytest.mark.parametrize("flag,value", [
    ("--segment-overlap", "3500"),
    ("--max-segments", "-1"),
    ("--max-item-bytes", str(10**30)),
    ("--max-metadata-keys", "-2"),
])
def test_invalid_policy_exits_3_with_zero_checks(paths, capsys, flag, value):
    code, _, p = _ingest(paths, capsys, ["fine"], flag, value)
    assert code == 3 and p.calls == 0
    assert list(paths.dir.iterdir()) == []


def test_run_level_limits_exit_3_with_nothing_written(paths, capsys):
    code, out, p = _ingest(paths, capsys, ["a", "b", "c"], "--max-items", "2")
    assert code == 3 and p.calls == 0 and "limit" in out.err
    assert list(paths.dir.iterdir()) == []


def test_invalid_timeout_env_exits_3(paths, capsys, monkeypatch):
    monkeypatch.setenv("LITTLE_CANARY_TIMEOUT", "abc")
    code, out, p = _ingest(paths, capsys, ["fine"])
    assert code == 3 and p.calls == 0 and "LITTLE_CANARY_TIMEOUT" in out.err
    assert list(paths.dir.iterdir()) == []


def test_missing_input_file_exits_3(paths, capsys):
    code, _, _ = _run(["ingest", str(paths.dir / "nope.jsonl"), "--manifest", str(paths.manifest)], capsys)
    assert code == 3 and not paths.manifest.exists()


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


# -- output paths: unusable targets are refused before any check (exit 3) -----------


@pytest.mark.parametrize("which", ["--manifest", "--export"])
@pytest.mark.parametrize("overwrite", [[], ["--overwrite"]])
def test_output_path_that_is_a_directory_exits_3_nothing_written(paths, capsys, which, overwrite):
    target = paths.dir / "adir"
    target.mkdir()
    manifest = target if which == "--manifest" else paths.manifest
    export = target if which == "--export" else paths.export
    paths.input.write_text(_jsonl("fine"), encoding="utf-8")
    code, out, p = _run(["ingest", str(paths.input), "--manifest", str(manifest),
                         "--export", str(export), *overwrite], capsys)
    assert code == 3 and p.calls == 0 and "is a directory" in out.err
    assert list(paths.dir.iterdir()) == [target] and list(target.iterdir()) == []


def test_export_directory_missing_exits_3_before_any_check(paths, capsys):
    export = paths.dir / "no-such-dir" / "export.json"
    code, out, p = _ingest(paths, capsys, ["fine"], "--export", str(export))
    assert code == 3 and p.calls == 0 and "--export directory is not writable" in out.err
    assert list(paths.dir.iterdir()) == []


def test_output_directory_not_writable_exits_3_before_any_check(paths, capsys, monkeypatch):
    real_access = os.access

    def deny_out_dir(path, mode, *a, **kw):
        if os.path.abspath(path) == str(paths.dir) and mode & os.W_OK:
            return False
        return real_access(path, mode, *a, **kw)

    monkeypatch.setattr(os, "access", deny_out_dir)  # deterministic even when run as root
    code, out, p = _ingest(paths, capsys, ["fine"])
    assert code == 3 and p.calls == 0 and "--manifest directory is not writable" in out.err
    assert list(paths.dir.iterdir()) == []


# -- --overwrite removes the previous pair before the run -----------------------------


def test_overwrite_failed_rerun_leaves_no_stale_pair(paths, capsys):
    argv_tail = ["--export", str(paths.export), "--overwrite"]
    code, _, _ = _ingest(paths, capsys, ["fine"], *argv_tail)
    assert code == 0 and paths.manifest.exists() and paths.export.exists()
    paths.input.write_text('"ok"\nnot json\n', encoding="utf-8")
    code, out, p = _run(["ingest", str(paths.input), "--manifest", str(paths.manifest), *argv_tail], capsys)
    assert code == 3 and p.calls == 0 and "malformed JSON" in out.err
    assert list(paths.dir.iterdir()) == []  # old manifest AND old export are gone


def test_overwrite_successful_rerun_replaces_both(paths, capsys):
    argv_tail = ["--export", str(paths.export), "--overwrite"]
    _ingest(paths, capsys, ["first"], *argv_tail)
    first_manifest, first_export = paths.manifest.read_bytes(), paths.export.read_bytes()
    code, _, _ = _ingest(paths, capsys, ["second", "third"], *argv_tail)
    assert code == 0
    manifest = json.loads(paths.manifest.read_text())
    export = json.loads(paths.export.read_text())
    assert paths.manifest.read_bytes() != first_manifest and paths.export.read_bytes() != first_export
    assert [r["text"] for r in export["records"]] == ["second", "third"]
    assert verify_export(export, manifest) == []
    assert sorted(p.name for p in paths.dir.iterdir()) == ["export.json", "manifest.json"]


# -- two-phase publication ------------------------------------------------------------


@pytest.mark.parametrize("func,overwrite", [("link", []), ("replace", ["--overwrite"])])
def test_interrupt_during_manifest_publish_leaves_nothing(paths, capsys, monkeypatch, func, overwrite):
    if overwrite:  # a previous pair exists and is consented away
        paths.manifest.write_text("previous", encoding="utf-8")
        paths.export.write_text("previous", encoding="utf-8")
    real = getattr(os, func)
    published = []

    def interrupting(src, dst, *a, **kw):
        if os.fspath(dst) == str(paths.manifest):
            published.extend(sorted(p.name for p in paths.dir.iterdir()))
            raise KeyboardInterrupt
        return real(src, dst, *a, **kw)

    monkeypatch.setattr(os, func, interrupting)
    paths.input.write_text(_jsonl("fine"), encoding="utf-8")
    with pytest.raises(KeyboardInterrupt):
        _run(["ingest", str(paths.input), "--manifest", str(paths.manifest),
              "--export", str(paths.export), *overwrite], capsys)
    # At interrupt time the export was already published and the manifest temp existed.
    assert "export.json" in published
    assert any(n.startswith(".manifest.json.") and n.endswith(".tmp") for n in published)
    assert list(paths.dir.iterdir()) == []  # no manifest, no export, no *.tmp


def test_export_temp_write_failure_after_manifest_temp_leaves_nothing(paths, capsys, monkeypatch):
    real_mkstemp = tempfile.mkstemp
    seen = []

    def failing_mkstemp(*a, **kw):
        if kw.get("prefix", "").startswith(".export.json."):
            seen.extend(sorted(p.name for p in paths.dir.iterdir()))
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_mkstemp(*a, **kw)

    monkeypatch.setattr(tempfile, "mkstemp", failing_mkstemp)
    code, out, p = _ingest(paths, capsys, ["fine"], "--export", str(paths.export))
    assert code == 3 and p.calls == 1 and "nothing written" in out.err
    assert len(seen) == 1 and seen[0].startswith(".manifest.json.") and seen[0].endswith(".tmp")
    assert list(paths.dir.iterdir()) == []
    assert out.out == ""


# -- run evidence: input digest and export request ------------------------------------


@pytest.mark.parametrize("export", [False, True])
def test_manifest_records_input_sha256_and_export_requested_for_file(paths, capsys, export):
    data = '"café"\r\n{"id": "b", "text": "☃ two"}\n\n'.encode()
    paths.input.write_bytes(data)
    argv = ["ingest", str(paths.input), "--manifest", str(paths.manifest)]
    if export:
        argv += ["--export", str(paths.export)]
    code, out, p = _run(argv, capsys)
    assert code == 0 and p.calls == 3  # two text segments + the id-bearing metadata segment
    run = json.loads(paths.manifest.read_text())["run"]
    expected = hashlib.sha256(paths.input.read_bytes()).hexdigest()
    assert run["input_sha256"] == expected
    assert run["export_requested"] is export
    assert f"input sha256={expected}" in out.out.splitlines()
    assert _summary_sha(out.out, "input") == expected


@pytest.mark.parametrize("buffered", [False, True])
def test_manifest_records_input_sha256_for_stdin(paths, capsys, buffered):
    data = '"café"\r\n"two"\n'.encode()
    # buffered: bytes via .buffer; else a text-only stand-in used as-is (\r\n kept by newline="").
    stdin = _byte_stdin(data) if buffered else io.StringIO(data.decode(), newline="")
    code, out, p = _run(["ingest", "-", "--manifest", str(paths.manifest), "--json"], capsys, stdin=stdin)
    assert code == 0 and p.calls == 2
    run = json.loads(out.out)["run"]
    assert run["input_sha256"] == hashlib.sha256(data).hexdigest()
    assert run["export_requested"] is False


def test_stdin_is_decoded_as_strict_utf8_regardless_of_stream_encoding(paths, capsys):
    # The stand-in would decode these bytes happily as latin-1; the CLI must not.
    code, out, p = _run(["ingest", "-", "--manifest", str(paths.manifest), "--export", str(paths.export)],
                        capsys, stdin=_byte_stdin(b'"ok"\n"\xff\xfe bad"\n'))
    assert code == 3 and p.calls == 0 and "utf-8" in out.err.lower()
    assert list(paths.dir.iterdir()) == []


def test_stdin_valid_utf8_via_buffer_is_admitted(paths, capsys):
    data = _jsonl("café", "two").encode("utf-8")
    code, _, p = _run(["ingest", "--manifest", str(paths.manifest)], capsys, stdin=_byte_stdin(data))
    assert code == 0 and p.calls == 2
    assert json.loads(paths.manifest.read_text())["counts"]["admitted"] == 2


def test_file_input_invalid_utf8_exits_3_nothing_written(paths, capsys):
    paths.input.write_bytes(b'"ok"\n"\xff bad"\n')
    code, _, p = _run(["ingest", str(paths.input), "--manifest", str(paths.manifest)], capsys)
    assert code == 3 and p.calls == 0
    assert list(paths.dir.iterdir()) == []


# -- help text pins the round-3 contract ----------------------------------------------


def test_ingest_help_pins_overwrite_timing_and_held_label_digests(capsys):
    with pytest.raises(SystemExit):
        main(["ingest", "--help"])
    out = " ".join(capsys.readouterr().out.split())  # undo argparse line wrapping
    assert "the previous pair is removed before the run starts" in out
    assert "label digests and a key count otherwise" in out


# -- --overwrite: previous pair removed only after local config validation ------------


@pytest.mark.parametrize("extra,env", [
    (["--segment-chars", "0"], None),
    (["--segment-overlap", "3500"], None),
    ([], "abc"),                                     # invalid LITTLE_CANARY_TIMEOUT
])
def test_overwrite_with_invalid_config_keeps_previous_pair(paths, capsys, monkeypatch, extra, env):
    if env is not None:
        monkeypatch.setenv("LITTLE_CANARY_TIMEOUT", env)
    paths.manifest.write_text("previous manifest", encoding="utf-8")
    paths.export.write_text("previous export", encoding="utf-8")
    code, out, p = _ingest(paths, capsys, ["fine"], "--export", str(paths.export), "--overwrite", *extra)
    assert code == 3 and p.calls == 0 and out.err.startswith(("error:", "LITTLE_CANARY_TIMEOUT"))
    assert paths.manifest.read_text() == "previous manifest"
    assert paths.export.read_text() == "previous export"
    assert sorted(x.name for x in paths.dir.iterdir()) == ["export.json", "manifest.json"]


# -- reader line cap is a run-level limit ---------------------------------------------


def _line_cap(max_item_bytes, keys=32, value_chars=1024):
    slack = keys * (12 * (MAX_METADATA_KEY_CHARS + value_chars) + 8) + 16
    return batch.max_line_chars(max_item_bytes) + slack


def test_line_longer_than_reader_cap_exits_3_nothing_written(paths, capsys):
    cap = _line_cap(16)
    long_line = json.dumps("x" * cap) + "\n"  # a JSON string line of cap + 3 chars
    assert len(long_line) > cap
    paths.input.write_text('"fine"\n' + long_line, encoding="utf-8")
    code, out, p = _run(["ingest", str(paths.input), "--manifest", str(paths.manifest),
                         "--export", str(paths.export), "--max-item-bytes", "16"], capsys)
    assert code == 3 and p.calls == 0
    assert "exceeds" in out.err and f"line 2: exceeds {cap} characters" in out.err
    assert list(paths.dir.iterdir()) == []


def test_line_at_reader_cap_is_read_and_held_per_record(paths, capsys):
    cap = _line_cap(16)
    at_cap = json.dumps("x" * (cap - 3)) + "\n"  # exactly cap chars including the newline
    assert len(at_cap) == cap
    paths.input.write_text('"fine"\n' + at_cap, encoding="utf-8")
    code, out, _ = _run(["ingest", str(paths.input), "--manifest", str(paths.manifest),
                         "--max-item-bytes", "16"], capsys)
    assert code == 2 and "exceeds" not in out.err  # record-level hold, not a run refusal
    manifest = json.loads(paths.manifest.read_text())
    assert manifest["counts"]["admitted"] == 1 and manifest["counts"]["held"] == 1


# -- real SecurityPipeline: canary context sized and verified before any check --------


_PROXY_VARS = ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy")
_KNOWN_MODEL = "qwen2.5:1.5b"
_EXPECTED_NUM_CTX = 4 * 3500 + 4 * len(DEFAULT_CANARY_SYSTEM_PROMPT) + 256 + 64


def _show_route(trained):
    """``/api/show`` stand-in: the known model reports ``trained``; any other model is 404."""
    def handler(url, body):
        if body.get("model") != _KNOWN_MODEL:
            return _Response(404, {"error": "model not found"})
        return _Response(200, {"model_info": {"general.architecture": "qwen2",
                                              "qwen2.context_length": trained}})
    return handler


def _chat_timeout(url, body):
    raise requests.Timeout("simulated canary timeout")


def _real_ingest(paths, *extra, url="http://127.0.0.1:9"):
    paths.input.write_text(_jsonl("hello there"), encoding="utf-8")
    with patch("sys.stdin", io.StringIO("")):
        return main(["ingest", str(paths.input), "--manifest", str(paths.manifest),
                     "--export", str(paths.export), "--ollama-url", url, "--timeout", "1", *extra])


def test_real_pipeline_unreachable_backend_refuses_exit_3(paths, capsys, monkeypatch, http):
    for var in _PROXY_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1")
    monkeypatch.setenv("no_proxy", "localhost,127.0.0.1")
    # Bound but not listening: connects are refused and no other process can take the port.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
        http.allowed_origins.add(origin)  # the only real request allowed: to the dead port
        code = _real_ingest(paths, url=origin)
    err = capsys.readouterr().err
    assert code == 3 and "verify" in err and "context length" in err
    assert http.paths("/api/show") == [origin + "/api/show"]
    assert http.paths("/api/chat") == []
    assert list(paths.dir.iterdir()) == []


def test_real_pipeline_sizes_canary_context_and_holds_degraded(paths, capsys, http):
    http.routes["/api/show"] = _show_route(32768)
    http.routes["/api/chat"] = _chat_timeout
    code = _real_ingest(paths)
    out = capsys.readouterr()
    assert len(http.paths("/api/show")) == 1 and len(http.paths("/api/chat")) == 1
    manifest = json.loads(paths.manifest.read_text())
    assert manifest["pipeline"]["canary_num_ctx"] == _EXPECTED_NUM_CTX
    assert manifest["pipeline"]["canary_context_length"] == 32768
    rec = manifest["records"][0]
    assert rec["admission"] == "held" and "degraded" in rec["hold_reasons"]
    assert code == 2 and "exit 2" in out.out
    export = json.loads(paths.export.read_text())
    assert export["records"] == []
    assert verify_export(export, manifest) == []


def test_real_pipeline_trained_context_too_small_refuses_exit_3(paths, capsys, http):
    http.routes["/api/show"] = _show_route(4096)
    http.routes["/api/chat"] = _chat_timeout
    code = _real_ingest(paths)
    err = capsys.readouterr().err
    assert code == 3 and "trained context length (4096)" in err and str(_EXPECTED_NUM_CTX) in err
    assert http.paths("/api/chat") == []
    assert list(paths.dir.iterdir()) == []


@pytest.mark.parametrize("payload", [None, {"details": {}}])
def test_real_pipeline_show_without_model_info_refuses_exit_3(paths, capsys, http, payload):
    http.routes["/api/show"] = lambda url, body: _Response(200 if payload else 404, payload)
    http.routes["/api/chat"] = _chat_timeout
    code = _real_ingest(paths)
    assert code == 3 and "context length" in capsys.readouterr().err
    assert http.paths("/api/chat") == []
    assert list(paths.dir.iterdir()) == []


def test_real_pipeline_unknown_canary_model_refuses_exit_3(paths, capsys, http):
    shown = []
    show = _show_route(32768)
    http.routes["/api/show"] = lambda url, body: shown.append(body["model"]) or show(url, body)
    http.routes["/api/chat"] = _chat_timeout
    code = _real_ingest(paths, "--canary-model", "no-such-model:latest")
    assert code == 3 and "context length" in capsys.readouterr().err
    assert shown == ["no-such-model:latest"]
    assert http.paths("/api/chat") == []
    assert list(paths.dir.iterdir()) == []


def test_offline_guard_rejects_unrouted_requests(paths, capsys, http):
    # Default ollama url (the live VM Ollama) with no routes: the guard must intercept.
    with pytest.raises(UnexpectedRequest):
        _real_ingest(paths, url="http://127.0.0.1:11434")
    assert http.calls == [("POST", "http://127.0.0.1:11434/api/show")]
    http.unexpected.clear()  # this test expects the interception; teardown stays clean
    assert list(paths.dir.iterdir()) == []
