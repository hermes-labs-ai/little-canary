"""Offline proof that successful bot checks cannot hide late review findings."""

import pytest

from scripts import check_pr_readiness as guard

HEAD = "ab0e8583e0afcc0417227d25c67aa151bf1597df"


def review(author, submitted, state="COMMENTED", head=HEAD):
    return {"id": author, "author": {"login": author}, "submittedAt": submitted,
            "state": state, "commit": {"oid": head}}


def ready_state():
    return {"head": HEAD, "reviewDecision": None, "reviews": [
        review("sourcery-ai", "2026-10-20T19:00:46Z"),
        review("copilot-pull-request-reviewer", "2026-10-20T19:01:20Z"),
    ], "reviewRequests": [], "reviewThreads": [],
        "required_contexts": ["test"],
        "checks": [{"__typename": "CheckRun", "name": "test", "isRequired": True,
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


def test_dependabot_controller_runs_guard_from_base_before_head_matched_merge():
    from pathlib import Path

    import yaml

    workflow = yaml.safe_load((Path(__file__).parents[1] / ".github/workflows/dependabot-auto-merge.yml").read_text())
    steps = workflow["jobs"]["auto-merge"]["steps"]
    assert steps[0]["with"]["ref"] == "${{ github.event.pull_request.base.sha }}"
    command = steps[-1]["run"]
    assert command.index("gh pr checks") < command.index("scripts/check_pr_readiness.py") < command.index("gh pr merge")
    assert '--match-head-commit "$HEAD_SHA"' in command


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

    def gh(*args):
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
