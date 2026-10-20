"""Read-only merge/release guard; run by the independent merge controller.

Requires gh authentication. Missing reviews fail closed. A successful bot check
never substitutes for an actual submitted review or a resolved thread.
"""

import argparse
import hashlib
import json
import subprocess
import sys
import time

EXPECTED_REVIEWERS = {"sourcery-ai", "copilot-pull-request-reviewer"}
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
                id name status conclusion startedAt completedAt
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


def commit_checks(repo, number, head):
    owner, name = repo.split("/", 1)
    checks = []
    cursor = None
    seen = set()
    while True:
        args = ["api", "graphql", "-f", "query=" + CHECKS_QUERY, "-f", "owner=" + owner,
                "-f", "name=" + name, "-F", f"number={number}", "-f", "head=" + head]
        if cursor:
            args += ["-f", "cursor=" + cursor]
        response = gh_json(*args)
        if response.get("errors"):
            raise ValueError("GitHub check query returned errors")
        commit = response["data"]["repository"]["object"]
        if commit["oid"] != head:
            raise ValueError("Check results do not belong to expected head")
        page = commit["statusCheckRollup"]["contexts"]
        checks.extend(page["nodes"])
        info = page["pageInfo"]
        if not info["hasNextPage"]:
            return checks
        cursor = info["endCursor"]
        if not cursor or cursor in seen:
            raise ValueError("Incomplete check pagination")
        seen.add(cursor)


def gh_json(*args, acceptable_codes=(0,)):
    result = subprocess.run(["gh", *args], capture_output=True, text=True, check=False)
    if result.returncode not in acceptable_codes:
        raise ValueError(f"GitHub query failed ({result.returncode}): {result.stderr.strip()}")
    return json.loads(result.stdout)


def snapshot(repo, number, head):
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
            response = gh_json(*args)
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
    # Include edits/replies on every inline comment, including old threads.
    pages = gh_json("api", "--paginate", "--slurp", f"repos/{repo}/pulls/{number}/comments?per_page=100")
    result["comment_activity"] = [
        {key: comment[key] for key in ("id", "created_at", "updated_at", "body")}
        for page in pages for comment in page
    ]
    result["checks"] = commit_checks(repo, number, head)
    # Bind the checks request and paginated review reads to the same head.
    current = gh_json("pr", "view", str(number), "--repo", repo, "--json", "headRefOid,reviewDecision")
    if current["headRefOid"] != head:
        raise ValueError("PR head changed during readiness query")
    result["reviewDecision"] = current["reviewDecision"]
    return result


def holds(state):
    reasons = []
    required = set(state["required_contexts"])
    found = set()
    for check in state["checks"]:
        name = check.get("name", check.get("context"))
        # GitHub evaluates required context AND app identity. A same-name
        # success from another app must not satisfy a missing trusted check.
        if check["isRequired"]:
            found.add(name)
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
    for review in state["reviews"]:
        author = (review.get("author") or {}).get("login", "").removesuffix("[bot]")
        if review["state"] == "PENDING":
            reasons.append("pending review: " + author)
            continue
        # COMMENTED never retracts an opinionated change request. A dismissed
        # review has no standing; GitHub reports its state as DISMISSED in place.
        if review["state"] in {"APPROVED", "CHANGES_REQUESTED"}:
            latest[author] = review["state"]
        if (review["state"] in {"COMMENTED", "APPROVED"}
                and (review.get("commit") or {}).get("oid") == state["head"]):
            submitted.add(author)
    for author, status in latest.items():
        if status == "CHANGES_REQUESTED":
            reasons.append("changes requested: " + author)
    missing = EXPECTED_REVIEWERS - submitted
    if missing:
        reasons.append("missing head-specific review submissions: " + ", ".join(sorted(missing)))
    return reasons


def fingerprint(state):
    return hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()


def wait_until_ready(fetch, quiet_seconds, timeout_seconds, *, now=time.monotonic, sleep=time.sleep):
    deadline = now() + timeout_seconds
    previous = None
    quiet_since = now()
    last_reasons = []
    while True:
        state = fetch()
        observed = now()
        current = fingerprint(state)
        if current != previous:
            quiet_since = observed
            previous = current
        last_reasons = holds(state)
        if not last_reasons and observed - quiet_since >= quiet_seconds:
            return state
        if observed >= deadline:
            detail = "; ".join(last_reasons) or "final quiet window has not elapsed"
            raise ValueError("Readiness held: " + detail)
        sleep(min(15, deadline - observed))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--quiet-seconds", type=int, default=120)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    args = parser.parse_args()
    if args.quiet_seconds < 120 or args.timeout_seconds < args.quiet_seconds:
        parser.error("quiet window must be at least 120 seconds and fit within the timeout")
    try:
        state = wait_until_ready(
            lambda: snapshot(args.repo, args.pr, args.head), args.quiet_seconds, args.timeout_seconds
        )
    except (ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps({"head": args.head, "unresolved_threads": sum(not thread["isResolved"] for thread in state["reviewThreads"]),
                      "quiet_seconds": args.quiet_seconds,
                      "reviews": [{key: review.get(key) for key in ("id", "state", "submittedAt", "author")}
                                  for review in state["reviews"]], "required_checks": [check for check in state["checks"] if check["isRequired"]]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
