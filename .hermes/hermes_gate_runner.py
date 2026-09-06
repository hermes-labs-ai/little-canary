"""Self-contained deterministic repository runner; copied byte-for-byte by init."""

from __future__ import annotations

import fnmatch
import json
import os
import signal
import subprocess
import sys
import time
import tomllib
from pathlib import Path

RUNNER_VERSION = "0.1.0"
OUTPUT_CAP = 65536


def _root() -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise RuntimeError("not a Git repository")
    return Path(result.stdout.strip()).resolve()


def _changed(root: Path) -> list[str]:
    values: set[str] = set()
    for args in (
        ("diff", "--name-only", "-z"),
        ("diff", "--cached", "--name-only", "-z"),
        ("ls-files", "--others", "--exclude-standard", "-z"),
    ):
        proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False)
        values.update(x.decode("utf-8", "surrogateescape") for x in proc.stdout.split(b"\0") if x)
    return sorted(values)


def _match(path: str, pattern: str) -> bool:
    return fnmatch.fnmatch(path, pattern) or (
        pattern.startswith("**/") and fnmatch.fnmatch(path, pattern[3:])
    )


def run(
    mode: str, *, root: Path | None = None, files: list[str] | None = None
) -> dict[str, object]:
    started = time.monotonic()
    root = (root or _root()).resolve()
    config_path = root / ".hermes" / "gate.toml"
    if not config_path.is_file():
        return _result(mode, "NOT_CONFIGURED", started, [], "run hermes-gate init")
    try:
        config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return _result(mode, "ERROR", started, [], f"invalid profile: {exc}")
    paths = list(files) if files is not None else _changed(root)
    exclusions = config.get("gate", {}).get("exclusions", [])
    paths = [path for path in paths if not any(_match(path, pattern) for pattern in exclusions)]
    if mode == "fast" and not paths:
        return _result(mode, "NOT_APPLICABLE", started, [], "no changed files")
    commands = list(config.get(mode, []))
    if not commands:
        return _result(mode, "NOT_CONFIGURED", started, [], f"no [[{mode}]] commands")
    budget = (
        float(config.get("gate", {}).get("fast_budget_seconds", 8.0)) if mode == "fast" else None
    )
    checks: list[dict[str, object]] = []
    for spec in commands:
        globs = spec.get("globs", ["**/*"])
        selected = [path for path in paths if any(_match(path, pattern) for pattern in globs)]
        if mode == "fast" and not selected:
            continue
        argv: list[str] = []
        for part in spec.get("argv", []):
            argv.extend(selected if part == "{files}" else [part])
        if not argv or any(not isinstance(part, str) for part in argv):
            return _result(mode, "ERROR", started, checks, "argv must be a non-empty string array")
        elapsed = time.monotonic() - started
        timeout = float(spec.get("timeout_seconds", 8.0))
        if budget is not None:
            timeout = min(timeout, max(0.01, budget - elapsed))
        check = _execute(argv, root, timeout, str(spec.get("name", argv[0])))
        checks.append(check)
        if check["status"] != "PASS":
            return _result(mode, "FAIL", started, checks, str(check.get("reason", "check failed")))
        if budget is not None and time.monotonic() - started >= budget:
            return _result(mode, "FAIL", started, checks, "fast budget exhausted")
    if not checks:
        return _result(mode, "NOT_APPLICABLE", started, [], "no commands matched changed files")
    return _result(mode, "PASS", started, checks, "")


def _execute(argv: list[str], root: Path, timeout: float, name: str) -> dict[str, object]:
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            argv,
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except FileNotFoundError:
        return {"name": name, "argv": argv, "status": "FAIL", "reason": "executable unavailable"}
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.communicate(timeout=0.25)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if proc.poll() is None:
            proc.communicate()
        return {"name": name, "argv": argv, "status": "FAIL", "reason": "timeout"}
    stdout_text = stdout[: OUTPUT_CAP // 2].decode("utf-8", "replace")
    stderr_text = stderr[: OUTPUT_CAP // 2].decode("utf-8", "replace")
    return {
        "name": name,
        "argv": argv,
        "status": "PASS" if proc.returncode == 0 else "FAIL",
        "returncode": proc.returncode,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
        "stdout": stdout_text,
        "stderr": stderr_text,
        "output_truncated": len(stdout) + len(stderr) > OUTPUT_CAP,
    }


def _result(
    mode: str, status: str, started: float, checks: list[dict[str, object]], reason: str
) -> dict[str, object]:
    return {
        "schema": "hermes-gate/runner-v1",
        "runner_version": RUNNER_VERSION,
        "command": mode,
        "status": status,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
        "checks": checks,
        "reason": reason,
    }


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args or args[0] not in {"fast", "full"}:
        print(json.dumps({"status": "ERROR", "reason": "usage: runner.py fast|full"}))
        return 2
    result = run(args[0])
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in {"PASS", "NOT_APPLICABLE"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
