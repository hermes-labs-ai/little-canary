#!/usr/bin/env python3
"""Validate workflow_run metadata without trusting PR code, artifacts or outputs."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

SOURCE_WORKFLOW = ".github/workflows/dependabot-auto-merge.yml"
SOURCE_EVENTS = {"pull_request", "pull_request_review", "pull_request_review_comment"}


def gh_json(endpoint):
    result = subprocess.run(["gh", "api", "--method", "GET", endpoint], capture_output=True,
                            text=True, check=False, timeout=30)
    if result.returncode:
        raise ValueError("GitHub context query failed: " + result.stderr.strip())
    return json.loads(result.stdout)


def validated_pull_request(repo, event, query=None):
    if event["action"] != "completed":
        raise ValueError("Source run is not completed")
    query = query or gh_json
    repository = query(f"repos/{repo}")
    repo_id = repository["id"]
    if repository["full_name"] != repo or event["repository"]["id"] != repo_id:
        raise ValueError("Source repository mismatch")
    source = event["workflow_run"]
    run_id = source["id"]
    if type(run_id) is not int or run_id <= 0:
        raise ValueError("Invalid source run ID")
    run = query(f"repos/{repo}/actions/runs/{run_id}")
    if (run["id"] != run_id or run["run_attempt"] != source["run_attempt"]
            or run["status"] != "completed" or run["conclusion"] != "success"
            or run["path"] != SOURCE_WORKFLOW or run["event"] not in SOURCE_EVENTS
            or run["repository"]["id"] != repo_id or run["head_repository"]["id"] != repo_id):
        raise ValueError("Untrusted source workflow run")
    # An empty/ambiguous association holds; never infer a PR from an artifact,
    # branch name, title or untrusted workflow output.
    associations = run["pull_requests"]
    if len(associations) != 1:
        raise ValueError("Source run must identify exactly one PR")
    associated = associations[0]
    number = associated["number"]
    if type(number) is not int or number <= 0:
        raise ValueError("Invalid associated PR number")
    pr = query(f"repos/{repo}/pulls/{number}")
    if (pr["number"] != number or pr["state"] != "open" or pr["draft"]
            or pr["user"]["login"] != "dependabot[bot]"
            or pr["base"]["repo"]["id"] != repo_id
            or pr["head"]["repo"]["id"] != repo_id
            or pr["base"]["ref"] != repository["default_branch"]
            or associated["base"]["repo"]["id"] != repo_id
            or associated["base"]["ref"] != pr["base"]["ref"]
            or associated["head"]["repo"]["id"] != repo_id
            or associated["head"]["sha"] != run["head_sha"]
            or pr["head"]["sha"] != run["head_sha"]
            or associated["head"]["ref"] != run["head_branch"]
            or pr["head"]["ref"] != run["head_branch"]
            or not re.fullmatch(r"[0-9a-f]{40}", pr["head"]["sha"])):
        raise ValueError("Live PR does not match the source Dependabot run")
    return pr


def run_metadata():
    directory = Path(os.environ["RUNNER_TEMP"])
    env = os.environ.copy()
    env["GITHUB_EVENT_PATH"] = str(directory / "little-canary-metadata-event.json")
    env["INPUT_GITHUB-TOKEN"] = env["GH_TOKEN"]
    env["INPUT_SKIP-COMMIT-VERIFICATION"] = "false"
    env["INPUT_SKIP-VERIFICATION"] = "false"
    # Supply every input consumed by this pinned bundle. Optional lookups use
    # core.getInput (strings), not getBooleanInput: "false" would enable them.
    env["INPUT_ALERT-LOOKUP"] = ""
    env["INPUT_COMPAT-LOOKUP"] = ""
    subprocess.run(["node", str(directory / "little-canary-fetch-metadata.cjs")],
                   env=env, check=True, timeout=120)


def main(argv=()):
    try:
        if os.environ["GITHUB_EVENT_NAME"] != "workflow_run":
            raise ValueError("Controller requires default-branch workflow_run context")
        if argv == ("--metadata",):
            run_metadata()
            return
        if argv:
            raise ValueError("Unknown controller arguments")
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        pr = validated_pull_request(os.environ["GITHUB_REPOSITORY"], event)
        # fetch-metadata reads this API-verified PR as data, with a read token.
        path = Path(os.environ["RUNNER_TEMP"]) / "little-canary-metadata-event.json"
        path.write_text(json.dumps({"pull_request": pr}))
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
            output.write(f"pr={pr['number']}\nhead={pr['head']['sha']}\n")
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit("Dependabot context held: " + str(error)) from error


if __name__ == "__main__":
    main(tuple(sys.argv[1:]))
