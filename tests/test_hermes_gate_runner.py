"""Regression tests for the vendored Hermes Gate repository runner.

``.hermes/hermes_gate_runner.py`` is based on the Hermes Gate 0.1.2 runner
with a missing-staged-file preflight. It requires Python 3.11 or newer (``tomllib``), which
is a tooling minimum separate from the library's Python 3.9+ support, so this
module skips on older interpreters.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tracemalloc
from pathlib import Path

import pytest

if sys.version_info < (3, 11):
    pytest.skip("Hermes Gate runner requires Python 3.11 or newer", allow_module_level=True)

import tomllib

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / ".hermes" / "hermes_gate_runner.py"
PROFILE = ROOT / ".hermes" / "gate.toml"
RUNNER_RELATIVE = ".hermes/hermes_gate_runner.py"
STREAM_CAP = 32768


def _load_runner():
    spec = importlib.util.spec_from_file_location("hermes_gate_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _profile() -> dict:
    return tomllib.loads(PROFILE.read_text(encoding="utf-8"))


def _fast_command(name: str) -> dict:
    (command,) = [spec for spec in _profile()["fast"] if spec["name"] == name]
    return command


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def _fixture_repo(root: Path, commands: list[dict], baseline: dict[str, str]) -> Path:
    """Commit a repository carrying the real runner, the given fast commands, and baseline files."""
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Fixture")
    _git(root, "config", "user.email", "fixture@example.com")
    hermes = root / ".hermes"
    hermes.mkdir()
    (hermes / "hermes_gate_runner.py").write_bytes(RUNNER.read_bytes())
    lines = ["version = 1", "", "[gate]", 'exclusions = [".git/**"]']
    for spec in commands:
        # The profile resolves ``python3`` from PATH; pin the test interpreter instead.
        argv = [sys.executable if part == "python3" else part for part in spec["argv"]]
        lines += [
            "",
            "[[fast]]",
            f'name = "{spec["name"]}"',
            f"argv = {json.dumps(argv)}",
            f"timeout_seconds = {spec['timeout_seconds']}",
            f"globs = {json.dumps(spec['globs'])}",
        ]
    (hermes / "gate.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    for name, content in baseline.items():
        (root / name).write_text(content, encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "baseline")
    return root


def _run_fast(root: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, str(root / RUNNER_RELATIVE), "fast"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    return json.loads(proc.stdout)


def test_profile_uses_runner_diff_check_and_keeps_runner_in_scope() -> None:
    runner = _load_runner()
    profile = _profile()
    assert runner.RUNNER_VERSION == "0.1.2"
    assert _fast_command("diff-check")["argv"] == ["python3", RUNNER_RELATIVE, "diff-check", "{files}"]
    assert not any(runner._match(RUNNER_RELATIVE, pattern) for pattern in profile["gate"]["exclusions"])
    (full_ruff,) = [spec for spec in profile["full"] if spec["name"] == "ruff"]
    assert RUNNER_RELATIVE in full_ruff["argv"]


@pytest.mark.parametrize("state", ["unstaged", "staged", "untracked", "staged_then_cleaned"])
@pytest.mark.parametrize("bad", [False, True])
def test_profile_whitespace_check_covers_git_states(tmp_path: Path, state: str, bad: bool) -> None:
    root = _fixture_repo(tmp_path, [_fast_command("diff-check")], {"notes with spaces.txt": "baseline\n"})
    path = root / ("new notes.txt" if state == "untracked" else "notes with spaces.txt")
    path.write_text("changed" + (" " if bad else "") + "\n", encoding="utf-8")
    if state in {"staged", "staged_then_cleaned"}:
        _git(root, "add", "--", path.name)
    if state == "staged_then_cleaned":
        path.write_text("clean working copy\n", encoding="utf-8")

    result = _run_fast(root)

    assert result["status"] == ("FAIL" if bad else "PASS"), result
    if bad:
        assert "trailing whitespace" in result["checks"][-1]["stdout"]


def test_fast_is_not_applicable_for_deletion_only_change(tmp_path: Path) -> None:
    root = _fixture_repo(
        tmp_path,
        [_fast_command("python-parse"), _fast_command("diff-check")],
        {"deleted.py": "value = 1\n"},
    )
    (root / "deleted.py").unlink()

    result = _load_runner().run("fast", root=root)

    assert result["status"] == "NOT_APPLICABLE"
    assert result["reason"] == "no changed files"


def test_fast_drops_deleted_paths_from_file_checks(tmp_path: Path) -> None:
    root = _fixture_repo(
        tmp_path,
        [_fast_command("python-parse"), _fast_command("diff-check")],
        {"deleted.py": "value = 1\n", "kept.py": "value = 1\n"},
    )
    (root / "deleted.py").unlink()
    (root / "kept.py").write_text("value = 2\n", encoding="utf-8")

    result = _run_fast(root)

    assert result["status"] == "PASS", result
    (parse,) = [check for check in result["checks"] if check["name"] == "python-parse"]
    assert "kept.py" in parse["argv"]
    assert "deleted.py" not in parse["argv"]


def test_execute_bounds_captured_output_per_stream(tmp_path: Path) -> None:
    runner = _load_runner()
    script = "import sys; sys.stdout.write('x' * 8_000_000); sys.stderr.write('y' * 8_000_000)"
    tracemalloc.start()
    try:
        result = runner._execute([sys.executable, "-c", script], tmp_path, 10, "bounded-output")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert result["status"] == "PASS"
    assert result["output_truncated"] is True
    assert len(result["stdout"]) == len(result["stderr"]) == STREAM_CAP
    assert peak < 4_000_000, f"capture retained memory proportional to emitted output: {peak} bytes"


def test_runner_reports_tooling_minimum_without_traceback(tmp_path: Path) -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import runpy, sys; sys.version_info = (3, 10, 0); runpy.run_path(sys.argv[1])",
            str(RUNNER),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )

    assert proc.returncode != 0
    assert "Python 3.11 or newer" in proc.stderr
    assert "Traceback" not in proc.stderr


@pytest.mark.parametrize("content", ["invalid syntax  \n", "invalid syntax\n", "value = 1\n"])
def test_fast_holds_missing_staged_addition(tmp_path: Path, content: str) -> None:
    root = _fixture_repo(tmp_path, [_fast_command("python-parse"), _fast_command("diff-check")], {})
    path = root / "staged.py"
    path.write_text(content, encoding="utf-8")
    _git(root, "add", path.name)
    path.unlink()

    result = _run_fast(root)

    assert result["status"] == "FAIL", result
    assert "restore them or stage their deletion" in result["reason"]
    check = result["checks"][0]
    assert check["name"] == "staged-diff-check"
    assert check["status"] == ("FAIL" if content.endswith("  \n") else "PASS")
    if content.endswith("  \n"):
        assert "trailing whitespace" in check["stdout"]


def test_fast_holds_missing_staged_modification(tmp_path: Path) -> None:
    root = _fixture_repo(tmp_path, [_fast_command("python-parse")], {"changed.py": "value = 1\n"})
    path = root / "changed.py"
    path.write_text("invalid syntax\n", encoding="utf-8")
    _git(root, "add", path.name)
    path.unlink()
    assert _run_fast(root)["status"] == "FAIL"

    # Staging the deletion removes the pending indexed content, so it is safe to skip.
    _git(root, "add", path.name)
    assert _run_fast(root)["status"] == "NOT_APPLICABLE"
