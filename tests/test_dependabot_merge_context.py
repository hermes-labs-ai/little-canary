"""Adversarial offline coverage for the privileged workflow_run input boundary."""

import json
import subprocess
from copy import deepcopy
from types import SimpleNamespace

import pytest

from scripts import dependabot_merge_context as context

REPO = "owner/repo"
HEAD = "a" * 40


def fixture():
    repository = {"id": 1, "full_name": REPO, "default_branch": "main"}
    pr = {"number": 42, "state": "open", "draft": False, "user": {"login": "dependabot[bot]"},
          "base": {"repo": {"id": 1}, "ref": "main"},
          "head": {"repo": {"id": 1}, "ref": "dependabot/actions/group", "sha": HEAD},
          "title": "Untrusted title", "body": "$(touch /tmp/should-never-run)"}
    association = {key: deepcopy(pr[key]) for key in ("number", "base", "head")}
    run = {"id": 99, "run_attempt": 1, "status": "completed", "conclusion": "success",
           "path": context.SOURCE_WORKFLOW, "event": "pull_request_review",
           "repository": {"id": 1}, "head_repository": {"id": 1}, "head_sha": HEAD,
           "head_branch": pr["head"]["ref"], "pull_requests": [association]}
    event = {"action": "completed", "repository": {"id": 1}, "workflow_run": {"id": 99, "run_attempt": 1}}
    data = {"repository": repository, "run": run, "pr": pr, "event": event}
    return data


def query_for(data):
    endpoints = {f"repos/{REPO}": "repository", f"repos/{REPO}/actions/runs/99": "run",
                 f"repos/{REPO}/pulls/42": "pr"}

    def query(endpoint):
        return deepcopy(data[endpoints[endpoint]])

    return query


@pytest.mark.parametrize("event_name", sorted(context.SOURCE_EVENTS))
def test_source_event_resolves_only_current_same_repo_dependabot_head(event_name):
    data = fixture()
    data["run"]["event"] = event_name
    assert context.validated_pull_request(REPO, data["event"], query_for(data)) == data["pr"]


@pytest.mark.parametrize("part,path,value", [
    ("event", ("action",), "requested"),
    ("event", ("repository", "id"), 2),
    ("event", ("workflow_run", "id"), "99\nhead=forged"),
    ("event", ("workflow_run", "id"), True),
    ("event", ("workflow_run", "run_attempt"), 2),
    ("run", ("id",), 100),
    ("run", ("status",), "in_progress"),
    ("run", ("conclusion",), "failure"),
    ("run", ("conclusion",), None),
    ("run", ("event",), "workflow_dispatch"),
    ("run", ("event",), "push"),
    ("run", ("path",), ".github/workflows/attacker.yml"),
    ("run", ("repository", "id"), 2),
    ("run", ("head_repository", "id"), 2),
    ("run", ("pull_requests",), []),
    ("run", ("head_sha",), "b" * 40),
    ("run", ("head_branch",), "attacker"),
    ("pr", ("number",), 43),
    ("pr", ("state",), "closed"),
    ("pr", ("draft",), True),
    ("pr", ("user", "login"), "human-reviewer"),
    ("pr", ("base", "repo", "id"), 2),
    ("pr", ("head", "repo", "id"), 2),
    ("pr", ("base", "ref"), "attacker-base"),
    ("pr", ("head", "sha"), "b" * 40),
    ("pr", ("head", "ref"), "attacker"),
    ("repository", ("full_name",), "attacker/repo"),
])
def test_untrusted_or_stale_context_is_rejected(part, path, value):
    data = fixture()
    target = data[part]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        context.validated_pull_request(REPO, data["event"], query_for(data))


@pytest.mark.parametrize("path,value", [
    (("number",), "42\nhead=forged"),
    (("number",), True),
    (("base", "repo", "id"), 2),
    (("base", "ref"), "attacker-base"),
    (("head", "repo", "id"), 2),
    (("head", "sha"), "b" * 40),
    (("head", "ref"), "attacker"),
])
def test_source_run_pr_association_must_match_live_pr(path, value):
    data = fixture()
    target = data["run"]["pull_requests"][0]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError):
        context.validated_pull_request(REPO, data["event"], query_for(data))


def test_multiple_pr_associations_are_not_guessed():
    data = fixture()
    data["run"]["pull_requests"] *= 2
    with pytest.raises(ValueError, match="exactly one"):
        context.validated_pull_request(REPO, data["event"], query_for(data))


def test_api_and_source_outputs_cannot_inject_github_output(monkeypatch, tmp_path):
    data = fixture()
    data["event"]["workflow_run"].update(head_sha="forged", outputs={"pr": 123, "head": "forged"})
    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps(data["event"]))
    output = tmp_path / "output"
    for key, value in {"GITHUB_EVENT_NAME": "workflow_run", "GITHUB_REPOSITORY": REPO,
                       "GITHUB_EVENT_PATH": str(event_file), "RUNNER_TEMP": str(tmp_path),
                       "GITHUB_OUTPUT": str(output)}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(context, "gh_json", query_for(data))
    context.main()
    assert output.read_text() == f"pr=42\nhead={HEAD}\n"
    payload = json.loads((tmp_path / "little-canary-metadata-event.json").read_text())
    assert payload == {"pull_request": data["pr"]}


@pytest.mark.parametrize("event_name", sorted(context.SOURCE_EVENTS))
def test_helper_refuses_pr_merge_context_even_with_valid_source_run(monkeypatch, event_name):
    monkeypatch.setenv("GITHUB_EVENT_NAME", event_name)
    with pytest.raises(SystemExit, match="default-branch workflow_run"):
        context.main()


def test_context_query_is_read_only_and_bounded(monkeypatch):
    def run(argv, **kwargs):
        assert argv == ["gh", "api", "--method", "GET", "repos/owner/repo"]
        assert kwargs["timeout"] == 30
        return SimpleNamespace(returncode=0, stdout='{"id": 1}')

    monkeypatch.setattr(context.subprocess, "run", run)
    assert context.gh_json("repos/owner/repo") == {"id": 1}


@pytest.mark.parametrize("failure", ["api", "timeout", "json"])
def test_context_query_failure_cannot_select_a_pr(monkeypatch, failure):
    def run(*args, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired("gh", 30)
        return SimpleNamespace(returncode=1 if failure == "api" else 0, stdout="invalid", stderr="unavailable")

    monkeypatch.setattr(context.subprocess, "run", run)
    with pytest.raises((ValueError, subprocess.TimeoutExpired)):
        context.gh_json("repos/owner/repo")


def test_metadata_child_gets_verified_payload_and_keeps_commit_verification(monkeypatch, tmp_path):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_EVENT_PATH", "runner-overwrites-this-with-workflow-run.json")
    monkeypatch.setenv("GH_TOKEN", "offline-dummy-token")
    monkeypatch.setenv("INPUT_ALERT-LOOKUP", "inherited-value-must-not-enable-api-lookups")
    monkeypatch.setenv("INPUT_COMPAT-LOOKUP", "inherited-value-must-not-enable-api-lookups")
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "metadata-output"))

    def run(argv, **kwargs):
        assert argv == ["node", str(tmp_path / "little-canary-fetch-metadata.cjs")]
        env = kwargs["env"]
        assert env["GITHUB_EVENT_PATH"] == str(tmp_path / "little-canary-metadata-event.json")
        assert env["INPUT_GITHUB-TOKEN"] == "offline-dummy-token"
        assert env["INPUT_SKIP-COMMIT-VERIFICATION"] == env["INPUT_SKIP-VERIFICATION"] == "false"
        assert env["INPUT_ALERT-LOOKUP"] == env["INPUT_COMPAT-LOOKUP"] == ""
        assert env["GITHUB_OUTPUT"] == str(tmp_path / "metadata-output")
        assert kwargs["check"] is True and kwargs["timeout"] == 120

    monkeypatch.setattr(context.subprocess, "run", run)
    context.run_metadata()
