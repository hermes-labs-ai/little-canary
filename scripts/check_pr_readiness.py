"""Merge/release guard for the independent controller; read-only unless --merge.

Missing reviews fail closed. Every nonempty review body needs an explicit
controller disposition. API visibility does not include other users' private drafts.
"""

import argparse
import hashlib
import json
import subprocess
import sys
import time

EXPECTED_REVIEWERS = {"sourcery-ai", "copilot-pull-request-reviewer"}
DISPOSITION_MARKER = "<!-- little-canary-review-disposition/v1 -->"
TRUSTED_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}
QUERY = """
query($owner:String!, $name:String!, $number:Int!, $cursor:String) {
  repository(owner:$owner,name:$name) {
    pullRequest(number:$number) {
      headRefOid
      reviewDecision
      baseRef { branchProtectionRule { requiredStatusCheckContexts } }
      CONNECTION(first:100, after:$cursor) {
        nodes { FIELDS }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""
CONNECTIONS = {
    "reviews": "id state submittedAt updatedAt author { login } commit { oid } body",
    "reviewThreads": "id isResolved isOutdated",
    "reviewRequests": "requestedReviewer { __typename }",
    "comments": "id author { login } authorAssociation body createdAt updatedAt",
}
CHECKS_QUERY = """
query($owner:String!, $name:String!, $number:Int!, $head:String!, $cursor:String) {
  repository(owner:$owner,name:$name) {
    object(expression:$head) {
      ... on Commit {
        oid
        statusCheckRollup {
          contexts(first:100, after:$cursor) {
            nodes {
              __typename
              ... on CheckRun {
                id databaseId name status conclusion startedAt completedAt
                checkSuite { app { id } }
                isRequired(pullRequestNumber:$number)
              }
              ... on StatusContext {
                id context state createdAt isRequired(pullRequestNumber:$number)
              }
            }
            pageInfo { hasNextPage endCursor }
          }
        }
      }
    }
  }
}
"""


def remaining(deadline, *, now=None):
    clock = now or time.monotonic
    seconds = 30 if deadline is None else min(30, deadline - clock())
    if seconds <= 0:
        raise ValueError("Readiness timeout elapsed")
    return seconds


def gh_run(*args, deadline=None):
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=True,
                          timeout=remaining(deadline))


def gh_json(*args, deadline=None):
    return json.loads(gh_run(*args, deadline=deadline).stdout)


def commit_checks(repo, number, head, *, deadline=None):
    owner, name = repo.split("/", 1)
    checks = []
    cursor = None
    seen = set()
    while True:
        args = ["api", "graphql", "-f", "query=" + CHECKS_QUERY, "-f", "owner=" + owner,
                "-f", "name=" + name, "-F", f"number={number}", "-f", "head=" + head]
        if cursor:
            args += ["-f", "cursor=" + cursor]
        response = gh_json(*args, deadline=deadline)
        if response.get("errors"):
            raise ValueError("GitHub check query returned errors")
        commit = response["data"]["repository"]["object"]
        if commit["oid"] != head:
            raise ValueError("Check results do not belong to expected head")
        page = commit["statusCheckRollup"]["contexts"]
        checks.extend(page["nodes"])
        info = page["pageInfo"]
        if not info["hasNextPage"]:
            return with_full_check_ids(repo, head, checks, deadline=deadline)
        cursor = info["endCursor"]
        if not cursor or cursor in seen:
            raise ValueError("Incomplete check pagination")
        seen.add(cursor)


def with_full_check_ids(repo, head, checks, *, deadline=None):
    # This GitHub GraphQL schema lacks CheckRun.fullDatabaseId, and its legacy
    # Int databaseId may be null. REST check-run.id is the full numeric ID.
    # Bind by node_id, never by a same-name check or by list position.
    missing = [check for check in checks if check["__typename"] == "CheckRun" and check["isRequired"]
               and check.get("fullDatabaseId") is None and check.get("databaseId") is None]
    if not missing:
        return checks
    needed = {check["id"] for check in missing}
    pages = gh_json("api", "--paginate", "--slurp",
                    f"repos/{repo}/commits/{head}/check-runs?filter=all&per_page=100", deadline=deadline)
    full_ids = {}
    for page in pages:
        for run in page["check_runs"]:
            node = run["node_id"]
            if node not in needed:
                continue
            if run["head_sha"] != head:
                raise ValueError("Full check ID does not belong to expected head")
            if node in full_ids and full_ids[node] != run["id"]:
                raise ValueError("Conflicting full check ordering IDs")
            full_ids[node] = run["id"]
    for check in missing:
        if check["id"] in full_ids:
            check["fullDatabaseId"] = full_ids[check["id"]]
    return checks


def check_run_order(check):
    value = check.get("fullDatabaseId")
    if value is None:
        value = check.get("databaseId")
    if (isinstance(value, bool) or not isinstance(value, (int, str))
            or (isinstance(value, str) and not (value.isascii() and value.isdecimal()))):
        raise ValueError("Required check ordering ID is unavailable: " + check["name"])
    order = int(value)
    if order <= 0:
        raise ValueError("Required check ordering ID is invalid: " + check["name"])
    return order


def _snapshot(repo, number, head, *, deadline=None):
    owner, name = repo.split("/", 1)
    result = {"head": head}
    for connection, fields in CONNECTIONS.items():
        nodes = []
        cursor = None
        seen = set()
        while True:
            args = ["api", "graphql", "-f", "query=" + QUERY.replace(
                "CONNECTION", connection
            ).replace("FIELDS", fields), "-f", "owner=" + owner, "-f", "name=" + name,
                "-F", f"number={number}"]
            if cursor:
                args += ["-f", "cursor=" + cursor]
            response = gh_json(*args, deadline=deadline)
            if response.get("errors"):
                raise ValueError("GitHub GraphQL returned errors")
            pr = response["data"]["repository"]["pullRequest"]
            if pr["headRefOid"] != head:
                raise ValueError("PR head changed; obtain a new independent review")
            result["reviewDecision"] = pr["reviewDecision"]
            rule = pr["baseRef"]["branchProtectionRule"]
            if rule is None:
                raise ValueError("No classic required-context policy; refusing to infer completeness from reported checks")
            result["required_contexts"] = rule["requiredStatusCheckContexts"]
            page = pr[connection]
            nodes.extend(page["nodes"])
            if not page["pageInfo"]["hasNextPage"]:
                break
            cursor = page["pageInfo"]["endCursor"]
            if not cursor or cursor in seen:
                raise ValueError("Incomplete review pagination")
            seen.add(cursor)
        result[connection] = nodes
    pages = gh_json("api", "--paginate", "--slurp", f"repos/{repo}/pulls/{number}/comments?per_page=100",
                    deadline=deadline)
    result["comment_activity"] = [
        {key: comment[key] for key in ("id", "created_at", "updated_at", "body")}
        for page in pages for comment in page
    ]
    result["checks"] = commit_checks(repo, number, head, deadline=deadline)
    current = gh_json("pr", "view", str(number), "--repo", repo, "--json", "headRefOid,reviewDecision",
                      deadline=deadline)
    if current["headRefOid"] != head:
        raise ValueError("PR head changed during readiness query")
    result["reviewDecision"] = current["reviewDecision"]
    return result


def fingerprint(state):
    return hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()


def snapshot(repo, number, head, *, deadline=None):
    # These are repeated observations, not an atomic GitHub transaction. Include
    # all review/body/thread/comment/check activity, rather than only the head.
    first = _snapshot(repo, number, head, deadline=deadline)
    confirmed = _snapshot(repo, number, head, deadline=deadline)
    if fingerprint(first) != fingerprint(confirmed):
        raise ValueError("Review or check activity changed during readiness query; restart the quiet window")
    return confirmed


def latest_required_checks(state):
    latest = {}
    for check in state["checks"]:
        # isRequired includes GitHub's app binding; a same-name untrusted app
        # cannot stand in for a missing configured check.
        if not check["isRequired"]:
            continue
        name = check.get("name", check.get("context"))
        app = (check.get("checkSuite") or {}).get("app") or {}
        identity = (check["__typename"], name, app.get("id"))
        order = check_run_order(check) if check["__typename"] == "CheckRun" else check.get("createdAt") or ""
        if identity in latest and order == latest[identity][0] and check != latest[identity][1]:
            raise ValueError("Ambiguous required check ordering: " + name)
        if identity not in latest or order > latest[identity][0]:
            latest[identity] = (order, check)
    return [check for _, check in latest.values()]


def dispositions(state):
    accepted = set()
    for comment in state["comments"]:
        if comment["authorAssociation"] not in TRUSTED_ASSOCIATIONS:
            continue
        body = comment["body"].replace("\r\n", "\n")
        if not body.startswith(DISPOSITION_MARKER + "\n"):
            continue
        try:
            record = json.loads(body.split("\n", 1)[1])
            if record["head"] != state["head"]:
                continue
            for item in record["reviews"]:
                if item["disposition"] in {"addressed", "no-action"} and item["evidence"].strip():
                    accepted.add((item["id"], item["digest"]))
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
    return accepted


def holds(state):
    reasons = []
    required = set(state["required_contexts"])
    try:
        checks = latest_required_checks(state)
    except ValueError as error:
        reasons.append(str(error))
        checks = []
    found = {check.get("name", check.get("context")) for check in checks}
    for check in checks:
        name = check.get("name", check.get("context"))
        passed = (check.get("status") == "COMPLETED" and check.get("conclusion") == "SUCCESS"
                  if check["__typename"] == "CheckRun" else check["state"] == "SUCCESS")
        if not passed:
            reasons.append("required check not passing: " + name)
    if not required or not required <= found:
        reasons.append("required checks are missing")
    if state["reviewDecision"] == "CHANGES_REQUESTED":
        reasons.append("GitHub review decision is changes requested")
    if state["reviewRequests"]:
        reasons.append("review requests remain pending")
    unresolved = [thread["id"] for thread in state["reviewThreads"] if not thread["isResolved"]]
    if unresolved:
        reasons.append("unresolved review threads: " + ", ".join(unresolved))
    latest = {}
    submitted = set()
    disposed = dispositions(state)
    for review in state["reviews"]:
        author = (review.get("author") or {}).get("login", "").removesuffix("[bot]")
        if review["state"] == "PENDING":
            reasons.append("visible pending review: " + author)
            continue
        # A general comment never retracts an opinionated change request.
        # Dismissed reviews have no standing. Do not depend on API traversal order.
        if review["state"] in {"APPROVED", "CHANGES_REQUESTED"}:
            order = review["submittedAt"] or ""
            if not order:
                reasons.append("review submission time is unavailable: " + review["id"])
            elif (author not in latest or order > latest[author][0]
                  or (order == latest[author][0] and review["state"] == "CHANGES_REQUESTED")):
                latest[author] = (order, review["state"])
        if review.get("body", "").strip() and (review["id"], fingerprint(review)) not in disposed:
            reasons.append(f"undisposed review body: {review['id']} digest={fingerprint(review)}")
        if (review["state"] in {"COMMENTED", "APPROVED"}
                and (review.get("commit") or {}).get("oid") == state["head"]):
            submitted.add(author)
    for author, (_, status) in latest.items():
        if status == "CHANGES_REQUESTED":
            reasons.append("changes requested: " + author)
    missing = EXPECTED_REVIEWERS - submitted
    if missing:
        reasons.append("missing head-specific review submissions: " + ", ".join(sorted(missing)))
    return reasons


def wait_until_ready(fetch, quiet_seconds, timeout_seconds, *, now=time.monotonic, sleep=time.sleep):
    deadline = now() + timeout_seconds
    previous = None
    quiet_since = now()
    while True:
        state = fetch()
        observed = now()
        # Check the deadline before considering a late result ready.
        if observed >= deadline:
            raise ValueError("Readiness timeout elapsed: " + "; ".join(holds(state)))
        current = fingerprint(state)
        if current != previous:
            quiet_since = observed
            previous = current
        if not holds(state) and observed - quiet_since >= quiet_seconds:
            # A fresh complete read must still agree at the end of the window.
            confirmed = fetch()
            if now() >= deadline:
                raise ValueError("Readiness timeout elapsed during final confirmation")
            if fingerprint(confirmed) == current and not holds(confirmed):
                return confirmed
            quiet_since = now()
            previous = fingerprint(confirmed)
        sleep(min(15, deadline - now()))


def merge_ready_pr(repo, number, head, state, *, deadline):
    # Kept inside the controller process so there is no separate CLI handoff
    # between the final complete review recheck and the head-matched merge.
    confirmed = snapshot(repo, number, head, deadline=deadline)
    remaining(deadline)
    if fingerprint(confirmed) != fingerprint(state) or holds(confirmed):
        raise ValueError("Readiness changed before merge; restart controller verification")
    gh_run("pr", "merge", str(number), "--repo", repo, "--squash", "--match-head-commit", head,
           deadline=deadline)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--quiet-seconds", type=int, default=120)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--merge", action="store_true", help="Independent controller only: recheck and merge exact head")
    args = parser.parse_args()
    if args.quiet_seconds < 120 or args.timeout_seconds <= args.quiet_seconds:
        parser.error("quiet window must be at least 120 seconds and less than the timeout")
    deadline = time.monotonic() + args.timeout_seconds
    try:
        state = wait_until_ready(
            lambda: snapshot(args.repo, args.pr, args.head, deadline=deadline),
            args.quiet_seconds, args.timeout_seconds
        )
        if args.merge:
            merge_ready_pr(args.repo, args.pr, args.head, state, deadline=deadline)
    except (ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr.rstrip(), file=sys.stderr)
        return 1
    print(json.dumps({"head": args.head, "merged": args.merge,
                      "unresolved_threads": sum(not thread["isResolved"] for thread in state["reviewThreads"]),
                      "quiet_seconds": args.quiet_seconds,
                      "reviews": [{"id": review["id"], "digest": fingerprint(review),
                                   "state": review["state"], "submittedAt": review["submittedAt"],
                                   "author": review["author"]} for review in state["reviews"]],
                      "required_checks": latest_required_checks(state)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
