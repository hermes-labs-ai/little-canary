"""Offline proof that successful bot checks cannot hide late review findings."""

import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from scripts import check_pr_readiness as guard

HEAD = "ab0e8583e0afcc0417227d25c67aa151bf1597df"


def review(author, submitted, state="COMMENTED", head=HEAD):
    return {"id": author, "author": {"login": author}, "submittedAt": submitted,
            "state": state, "commit": {"oid": head}, "body": ""}


def ready_state():
    return {"head": HEAD, "reviewDecision": None, "reviews": [
        review("sourcery-ai", "2026-10-20T19:00:46Z"),
        review("copilot-pull-request-reviewer", "2026-10-20T19:01:20Z"),
    ], "reviewRequests": [], "reviewThreads": [],
        "required_contexts": ["test"],
        "comments": [],
        "checks": [{"__typename": "CheckRun", "name": "test", "isRequired": True,
                    "databaseId": 1, "startedAt": "2026-10-20T19:00:00Z",
                    "checkSuite": {"app": {"id": "trusted-app"}},
                    "status": "COMPLETED", "conclusion": "SUCCESS"}], "comment_activity": []}


def test_pr155_successful_check_before_and_after_late_reviews_stays_held():
    # Sourcery submitted three findings at 19:00:46. Merge was at 19:00:49,
    # the same second its check became green. Copilot followed at 19:01:20.
    at_merge = ready_state()
    at_merge["reviews"] = at_merge["reviews"][:1]
    at_merge["reviewThreads"] = [
        {"id": f"sourcery-{index}", "isResolved": False, "isOutdated": False} for index in range(3)
    ]
    reasons = guard.holds(at_merge)
    assert any("unresolved" in reason for reason in reasons)
    assert any("copilot" in reason for reason in reasons)
    after_merge = ready_state()
    after_merge["reviewThreads"] = at_merge["reviewThreads"] + [
        {"id": f"copilot-{index}", "isResolved": False, "isOutdated": False} for index in range(2)
    ]
    assert any("unresolved" in reason for reason in guard.holds(after_merge))


@pytest.mark.parametrize("case", ["stale", "missing", "pending", "requested", "changes", "outdated", "checks"])
def test_readiness_fails_closed(case):
    state = ready_state()
    if case == "stale":
        state["reviews"][0]["commit"]["oid"] = "older-head"
    elif case == "missing":
        state["reviews"] = []
    elif case == "pending":
        state["reviews"].append(review("reviewer", None, "PENDING"))
    elif case == "requested":
        state["reviewRequests"] = [{"requestedReviewer": {"__typename": "User"}}]
    elif case == "changes":
        state["reviews"].extend([review("reviewer", "now", "CHANGES_REQUESTED"),
                                  review("reviewer", "later", "COMMENTED")])
    elif case == "outdated":
        state["reviewThreads"] = [{"id": "old", "isResolved": False, "isOutdated": True}]
    else:
        state["checks"][0]["status"] = "IN_PROGRESS"
    assert guard.holds(state)


def test_zero_threads_and_actual_head_reviews_can_pass():
    assert guard.holds(ready_state()) == []


class Clock:
    def __init__(self):
        self.time = 0

    def now(self):
        return self.time

    def sleep(self, seconds):
        self.time += seconds


def test_new_review_activity_restarts_final_quiet_window():
    clock = Clock()

    def fetch():
        state = ready_state()
        if clock.time >= 45:
            state["comment_activity"] = [{"id": 1, "updated_at": "new edit"}]
        return state

    guard.wait_until_ready(fetch, 60, 150, now=clock.now, sleep=clock.sleep)
    assert clock.time == 105


def test_reviews_arriving_after_green_checks_cannot_finish_early():
    clock = Clock()

    def fetch():
        state = ready_state()
        if clock.time < 45:
            state["reviews"] = []
        return state

    guard.wait_until_ready(fetch, 60, 150, now=clock.now, sleep=clock.sleep)
    assert clock.time == 105


def test_timeout_never_waives_missing_review():
    clock = Clock()
    state = ready_state()
    state["reviews"] = []
    with pytest.raises(ValueError, match="missing head-specific review"):
        guard.wait_until_ready(lambda: state, 60, 60, now=clock.now, sleep=clock.sleep)


def test_snapshot_reads_every_thread_page_and_rejects_head_race(monkeypatch):
    seen = []

    def gh(*args, **kwargs):
        seen.append(args)
        if args[:2] == ("api", "graphql"):
            query = args[3]
            if "object(expression:" in query:
                return {"data": {"repository": {"object": {"oid": HEAD, "statusCheckRollup": {
                    "contexts": {"nodes": ready_state()["checks"],
                                 "pageInfo": {"hasNextPage": False, "endCursor": None}}
                }}}}}
            connection = next(name for name in guard.CONNECTIONS if name + "(first:" in query)
            second_page = "cursor=next" in args
            nodes = [{"id": "late-thread", "isResolved": False}] if second_page else []
            return {"data": {"repository": {"pullRequest": {
                "headRefOid": HEAD, "reviewDecision": None,
                "baseRef": {"branchProtectionRule": {"requiredStatusCheckContexts": ["test"]}}, connection: {"nodes": nodes,
                    "pageInfo": {"hasNextPage": connection == "reviewThreads" and not second_page,
                                 "endCursor": "next"}}}}}}
        if args[:2] == ("api", "--paginate"):
            return [[], [{"id": 1, "created_at": "then", "updated_at": "now", "body": "edit"}]]
        if args[:2] == ("pr", "checks"):
            return [{"name": "test", "bucket": "pass"}]
        return {"headRefOid": HEAD, "reviewDecision": None}

    monkeypatch.setattr(guard, "gh_json", gh)
    state = guard.snapshot("owner/repo", 155, HEAD)
    assert state["reviewThreads"][0]["id"] == "late-thread"
    assert state["comment_activity"][0]["updated_at"] == "now"
    assert any("cursor=next" in args for args in seen)

    def changed(*args, **kwargs):
        result = gh(*args, **kwargs)
        if args[:2] == ("pr", "view"):
            result["headRefOid"] = "changed"
        return result

    monkeypatch.setattr(guard, "gh_json", changed)
    with pytest.raises(ValueError, match="head changed"):
        guard.snapshot("owner/repo", 155, HEAD)


def controller_workflow():
    return yaml.safe_load((Path(__file__).parents[1] / ".github/workflows/dependabot-auto-merge.yml").read_text())


def assert_controller_workflow(workflow):
    assert workflow["permissions"]["checks"] == "read"
    assert workflow["permissions"]["statuses"] == "read"
    assert workflow["concurrency"] == {
        "group": "dependabot-merge-${{ github.event.pull_request.number }}", "cancel-in-progress": True
    }
    triggers = workflow.get("on", workflow.get(True))
    assert triggers["pull_request_review"]["types"] == ["submitted", "edited", "dismissed"]
    assert triggers["pull_request_review_comment"]["types"] == ["created", "edited", "deleted"]
    job = workflow["jobs"]["auto-merge"]
    assert job["if"] == "github.event.pull_request.user.login == 'dependabot[bot]'"
    guarded = False
    checkouts = 0
    for step in job["steps"]:
        if step.get("uses", "").partition("@")[0] == "actions/checkout":
            assert step["with"]["ref"] == "${{ github.event.pull_request.base.sha }}"
            assert step["with"]["persist-credentials"] is False
            checkouts += 1
        command = step.get("run", "")
        if "little-canary-review-guard.py" in command:
            assert 'git show "$BASE_SHA:scripts/check_pr_readiness.py"' in command
            assert 'python3 -I "$RUNNER_TEMP/little-canary-review-guard.py"' in command
            assert '--head "$HEAD_SHA" --merge' in command
            assert step["env"]["BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
            assert step["env"]["HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
            guarded = True
            break
    assert guarded and checkouts


def test_dependabot_controller_runs_trusted_guard_with_check_read_permissions():
    assert_controller_workflow(controller_workflow())


def test_second_head_checkout_is_a_failing_controller_control():
    workflow = controller_workflow()
    steps = workflow["jobs"]["auto-merge"]["steps"]
    head_checkout = deepcopy(steps[0])
    head_checkout["with"]["ref"] = "${{ github.event.pull_request.head.sha }}"
    steps.insert(1, head_checkout)
    with pytest.raises(AssertionError):
        assert_controller_workflow(workflow)


@pytest.mark.parametrize("permission", ["checks", "statuses"])
def test_missing_check_read_permission_is_a_failing_control(permission):
    workflow = controller_workflow()
    del workflow["permissions"][permission]
    with pytest.raises((AssertionError, KeyError)):
        assert_controller_workflow(workflow)


@pytest.mark.parametrize("state", ["DISMISSED", "APPROVED"])
def test_dismissed_or_approved_change_requests_do_not_hold(state):
    snapshot = ready_state()
    snapshot["reviews"].append(review("reviewer", "now", state))
    assert guard.holds(snapshot) == []


def test_missing_required_context_is_not_hidden_by_other_green_checks():
    state = ready_state()
    state["required_contexts"].append("missing test")
    assert "required checks are missing" in guard.holds(state)


def test_checks_are_queried_by_commit_and_incomplete_pagination_fails_closed(monkeypatch):
    calls = []

    def gh(*args, **kwargs):
        calls.append(args)
        assert "head=" + HEAD in args
        return {"data": {"repository": {"object": {"oid": HEAD, "statusCheckRollup": {
            "contexts": {"nodes": [], "pageInfo": {"hasNextPage": True, "endCursor": None}}
        }}}}}

    monkeypatch.setattr(guard, "gh_json", gh)
    with pytest.raises(ValueError, match="Incomplete check pagination"):
        guard.commit_checks("owner/repo", 155, HEAD)
    assert "object(expression:$head)" in calls[0][3]


def test_check_rerun_restarts_quiet_window():
    clock = Clock()

    def fetch():
        state = ready_state()
        if clock.time >= 45:
            state["checks"][0]["id"] = "rerun-on-same-head"
        return state

    guard.wait_until_ready(fetch, 60, 150, now=clock.now, sleep=clock.sleep)
    assert clock.time == 105


def test_same_name_check_from_unrequired_app_cannot_replace_required_check():
    state = ready_state()
    state["checks"][0]["isRequired"] = False
    assert "required checks are missing" in guard.holds(state)


@pytest.mark.parametrize("connection", list(guard.CONNECTIONS))
@pytest.mark.parametrize("failure", ["api", "cursor"])
def test_incomplete_review_data_fails_closed(monkeypatch, connection, failure):
    def gh(*args, **kwargs):
        query = args[3]
        selected = next(name for name in guard.CONNECTIONS if name + "(first:" in query)
        if selected == connection and failure == "api":
            return {"errors": [{"message": "unavailable"}], "data": None}
        return {"data": {"repository": {"pullRequest": {
            "headRefOid": HEAD, "reviewDecision": None,
            "baseRef": {"branchProtectionRule": {"requiredStatusCheckContexts": ["test"]}},
            selected: {"nodes": [], "pageInfo": {
                "hasNextPage": selected == connection, "endCursor": None}}
        }}}}

    monkeypatch.setattr(guard, "gh_json", gh)
    with pytest.raises(ValueError, match="GraphQL returned errors|Incomplete review pagination"):
        guard.snapshot("owner/repo", 155, HEAD)


def test_unavailable_review_commit_is_a_clean_missing_review_hold():
    state = ready_state()
    state["reviews"][0]["commit"] = None
    assert any("missing head-specific" in reason for reason in guard.holds(state))


@pytest.mark.parametrize("conclusion", ["SKIPPED", "NEUTRAL"])
def test_required_coverage_check_must_exercise_success(conclusion):
    state = ready_state()
    state["checks"][0]["conclusion"] = conclusion
    assert any("required check not passing" in reason for reason in guard.holds(state))


@pytest.mark.parametrize("seconds", [60, 119])
def test_cli_cannot_shorten_documented_quiet_window(monkeypatch, seconds):
    monkeypatch.setattr("sys.argv", ["guard", "--repo", "owner/repo", "--pr", "156",
                                     "--head", HEAD, "--quiet-seconds", str(seconds)])
    with pytest.raises(SystemExit) as error:
        guard.main()
    assert error.value.code == 2


def test_missing_classic_policy_is_explicit_hold(monkeypatch):
    def gh(*args, **kwargs):
        return {"data": {"repository": {"pullRequest": {
            "headRefOid": HEAD, "reviewDecision": None, "baseRef": {"branchProtectionRule": None}
        }}}}

    monkeypatch.setattr(guard, "gh_json", gh)
    with pytest.raises(ValueError, match="No classic required-context policy"):
        guard.snapshot("owner/repo", 156, HEAD)



def disposition(state, review_body, *, association="COLLABORATOR", head=HEAD):
    return {"authorAssociation": association, "body": guard.DISPOSITION_MARKER + "\n" + json.dumps({
        "head": head, "reviews": [{"id": review_body["id"], "digest": guard.fingerprint(review_body),
            "disposition": "addressed", "evidence": "Verified correction and adversarial regression test."}]
    })}


def test_body_only_findings_require_explicit_controller_disposition():
    state = ready_state()
    finding = state["reviews"][0]
    finding["body"] = "Material bug: bypasses dependency security. No inline thread was created."
    assert any("undisposed review body" in reason for reason in guard.holds(state))
    state["comments"].append(disposition(state, finding))
    assert guard.holds(state) == []


@pytest.mark.parametrize("mutation", ["head", "body", "outsider", "evidence", "digest", "malformed"])
def test_stale_forged_or_incomplete_disposition_cannot_clear_body_findings(mutation):
    state = ready_state()
    finding = state["reviews"][0]
    finding["body"] = "Finding without an inline thread"
    ack = disposition(state, finding)
    if mutation == "head":
        ack = disposition(state, finding, head="stale-head")
    elif mutation == "body":
        finding["body"] += " edited after disposition"
    elif mutation == "outsider":
        ack["authorAssociation"] = "CONTRIBUTOR"
    elif mutation == "malformed":
        ack["body"] = guard.DISPOSITION_MARKER + "\nnot JSON"
    else:
        record = json.loads(ack["body"].split("\n", 1)[1])
        record["reviews"][0][mutation] = ""
        ack["body"] = guard.DISPOSITION_MARKER + "\n" + json.dumps(record)
    state["comments"] = [ack]
    assert any("undisposed review body" in reason for reason in guard.holds(state))


@pytest.mark.parametrize("reverse", [False, True])
def test_newest_opinionated_review_wins_independent_of_api_order(reverse):
    state = ready_state()
    opinions = [review("reviewer", "2026-10-20T18:00:00Z", "APPROVED"),
                review("reviewer", "2026-10-20T19:00:00Z", "CHANGES_REQUESTED"),
                review("reviewer", "2026-10-20T19:01:00Z", "COMMENTED")]
    state["reviews"].extend(reversed(opinions) if reverse else opinions)
    assert "changes requested: reviewer" in guard.holds(state)


def test_successful_rerun_replaces_failed_run_for_same_required_identity():
    state = ready_state()
    older = deepcopy(state["checks"][0])
    older["conclusion"] = "FAILURE"
    state["checks"][0]["databaseId"] = 2
    state["checks"].append(older)
    assert guard.holds(state) == []


def test_queued_new_rerun_cannot_reuse_prior_success():
    state = ready_state()
    newer = deepcopy(state["checks"][0])
    newer.update(databaseId=2, startedAt=None, status="QUEUED", conclusion=None)
    state["checks"].append(newer)
    assert any("required check not passing" in reason for reason in guard.holds(state))


def test_late_ready_fetch_cannot_pass_after_timeout():
    clock = Clock()

    def fetch():
        if clock.time >= 60:
            clock.time = 151
        return ready_state()

    with pytest.raises(ValueError, match="timeout elapsed"):
        guard.wait_until_ready(fetch, 60, 150, now=clock.now, sleep=clock.sleep)


def test_slow_final_confirmation_cannot_bypass_timeout():
    clock = Clock()
    confirmations = 0

    def fetch():
        nonlocal confirmations
        if clock.time == 60:
            confirmations += 1
            if confirmations == 2:
                clock.time = 151
        return ready_state()

    with pytest.raises(ValueError, match="timeout elapsed during final confirmation"):
        guard.wait_until_ready(fetch, 60, 150, now=clock.now, sleep=clock.sleep)


def test_github_subprocess_uses_remaining_deadline_and_bounds_unscoped_calls(monkeypatch):
    timeouts = []
    monkeypatch.setattr(guard.time, "monotonic", lambda: 100)

    def run(*args, **kwargs):
        timeouts.append(kwargs["timeout"])
        return subprocess.CompletedProcess(args, 0, stdout="{}")

    monkeypatch.setattr(guard.subprocess, "run", run)
    guard.gh_json("api", "test", deadline=105)
    assert 0 < timeouts[0] <= 5
    guard.gh_json("api", "test")
    assert timeouts[1] == 30
    with pytest.raises(ValueError, match="timeout elapsed"):
        guard.remaining(100, now=lambda: 101)


@pytest.mark.parametrize("activity", ["reviews", "reviewThreads", "comments", "comment_activity"])
def test_snapshot_rechecks_all_review_activity_before_returning(monkeypatch, activity):
    calls = 0

    def fetch(*args, **kwargs):
        nonlocal calls
        calls += 1
        state = ready_state()
        if calls == 2:
            state[activity].append({"id": "new activity"})
        return state

    monkeypatch.setattr(guard, "_snapshot", fetch)
    with pytest.raises(ValueError, match="activity changed during readiness query"):
        guard.snapshot("owner/repo", 156, HEAD)


def test_late_thread_immediately_before_merge_prevents_merge(monkeypatch):
    initial = ready_state()
    changed = ready_state()
    changed["reviewThreads"] = [{"id": "late", "isResolved": False}]
    monkeypatch.setattr(guard, "snapshot", lambda *args, **kwargs: changed)
    monkeypatch.setattr(guard, "gh_run", lambda *args, **kwargs: pytest.fail("merge was attempted"))
    with pytest.raises(ValueError, match="Readiness changed before merge"):
        guard.merge_ready_pr("owner/repo", 156, HEAD, initial, deadline=float("inf"))


def test_controller_merge_rechecks_then_matches_exact_head(monkeypatch):
    state = ready_state()
    calls = []
    monkeypatch.setattr(guard, "snapshot", lambda *args, **kwargs: calls.append("recheck") or state)
    monkeypatch.setattr(guard, "gh_run", lambda *args, **kwargs: calls.append(args))
    guard.merge_ready_pr("owner/repo", 156, HEAD, state, deadline=float("inf"))
    assert calls[0] == "recheck"
    assert calls[1] == ("pr", "merge", "156", "--repo", "owner/repo", "--squash", "--match-head-commit", HEAD)



def test_cli_subprocess_timeout_fails_closed_before_merge(monkeypatch):
    monkeypatch.setattr("sys.argv", ["guard", "--repo", "owner/repo", "--pr", "156", "--head", HEAD, "--merge"])

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(["gh", "api"], 30)

    monkeypatch.setattr(guard, "snapshot", timeout)
    monkeypatch.setattr(guard, "merge_ready_pr", lambda *args, **kwargs: pytest.fail("merge attempted after timeout"))
    assert guard.main() == 1



def test_browser_crlf_disposition_is_accepted():
    state = ready_state()
    state["reviews"][0]["body"] = "Finding without inline thread"
    ack = disposition(state, state["reviews"][0])
    ack["body"] = ack["body"].replace("\n", "\r\n")
    state["comments"] = [ack]
    assert guard.holds(state) == []
