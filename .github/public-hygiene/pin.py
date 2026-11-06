#!/usr/bin/env python3
"""Check that a caller pins the shared check to a commit on this repository's default
branch.

    python3 pin.py

Run by the `pin` job of `.github/workflows/public-hygiene.yml`, and by the weekly sweep.
A caller's `uses: ...@<sha>` resolves any commit GitHub can see under this repository's
name, including one pushed to a pull request branch or to a fork (an impostor commit).
`check` passes only when the pinned commit is the default branch's head or one of its
ancestors.

`check_comment` passes only when the comment after the pin is exactly `# <tag>`, where the
tag is a `v*` tag of this repository (the tags a ruleset keeps from moving) that points at
the pinned commit. A branch name (`# main`) drifts as soon as the branch moves, and a
description is never checked against the sha, so both are refused. zizmor's online
`ref-version-mismatch` audit checks the same pairing, and only for a one-word comment.

What each caller catches:
- The `pin` job runs the pinned commit's own code, so it catches an honest mistake (a
  pin left on a pull request branch). It cannot catch an impostor commit: that commit's
  own `pin` job can simply pass, or not exist.
- The sweep runs from this repository's main, reads every public repository's caller
  file and checks its pin with this function, so an impostor pin is reported there.
- A reviewer still checks a caller's pin by hand before merging it.

Environment: WORKFLOW_REPOSITORY and WORKFLOW_SHA (from the `job` context, which names
the called workflow's own repository and commit), GH_TOKEN, GITHUB_API_URL.
"""

from __future__ import annotations

import base64
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from event import Api, ApiError, RestApi  # noqa: E402


def check(api: Api, repo: str, sha: str) -> tuple[bool, str]:
    if not re.fullmatch(r"[\w.\-]+/[\w.\-]+", repo) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        return False, "WORKFLOW_REPOSITORY and a full WORKFLOW_SHA are required."
    branch = (api.get(f"/repos/{repo}") or {}).get("default_branch")
    if not isinstance(branch, str) or not re.fullmatch(r"[\w./\-]+", branch):
        return False, "The default branch could not be read."
    try:
        status = (api.get(f"/repos/{repo}/compare/{branch}...{sha}") or {}).get("status")
    except ApiError as e:
        if e.status == 404:
            return False, f"The pinned commit {sha[:12]} is not known to {repo}."
        raise
    if status in ("identical", "behind"):
        return True, f"The pinned commit {sha[:12]} is on {repo} {branch}."
    return False, (
        f"The pinned commit {sha[:12]} is not on {repo} {branch} (compare status: {status}). "
        "Re-pin the caller to a commit of that branch before merging it."
    )


# ASCII digits only: a fullwidth digit is not a tag name, and would not survive the URL.
TAG_COMMENT = re.compile(r"#[ \t]*(v[0-9]{1,6}(?:\.[0-9]{1,6}){0,2})[ \t]*")
# A caller's `uses:` line for the shared workflow: the pinned commit and its comment.
USES_PIN = re.compile(r"^[^#\n]*/\.github/workflows/public-hygiene\.yml@([0-9a-f]{40})[ \t]*(#[^\n]*)?$", re.M)


def check_comment(api: Api, repo: str, sha: str, comment: str | None) -> tuple[bool, str]:
    """Whether `comment` is `# <tag>` for a `v*` tag of `repo` that points at `sha`."""
    if not comment or not comment.strip():
        return False, f"The pin {sha[:12]} has no comment; write `# <tag>`, a v* tag on that commit."
    m = TAG_COMMENT.fullmatch(comment.strip())
    if not m:
        return False, (
            f"The comment after the pin {sha[:12]} must be exactly `# <tag>` (a v* tag on that commit), "
            "not a branch name or a description."
        )
    tag = m.group(1)
    try:
        ref = api.get(f"/repos/{repo}/git/ref/tags/{tag}")
    except ApiError as e:
        if e.status == 404:
            return False, f"The comment names {tag}, which is not a tag of {repo}."
        raise
    obj = (ref or {}).get("object") if isinstance(ref, dict) else None
    if not isinstance(obj, dict):
        return False, f"The comment names {tag}, which is not a tag of {repo}."
    target = obj.get("sha")
    if obj.get("type") == "tag":  # an annotated tag: its commit is one step further
        target = ((api.get(f"/repos/{repo}/git/tags/{target}") or {}).get("object") or {}).get("sha")
    if target != sha:
        return False, f"The comment names {tag}, which points at {str(target)[:12]}, not at the pinned commit {sha[:12]}."
    return True, f"The comment names {tag}, the pinned commit {sha[:12]}."


def check_caller(api: Api, repo: str, text: str) -> list[str]:
    """Every problem with the pins in a caller workflow's text: each must be a commit on
    `repo`'s default branch, named by its tag in the comment. Empty means all is well."""
    pins = USES_PIN.findall(text)
    if not pins:
        return ["The caller pins no commit of the shared workflow."]
    problems: list[str] = []
    for sha, comment in pins:
        for ok, message in (check(api, repo, sha), check_comment(api, repo, sha, comment)):
            if not ok:
                problems.append(message)
    return problems


def caller_text(api: Api, caller_repo: str, workflow_ref: str, caller_sha: str) -> str:
    """The calling workflow's file, as committed at `caller_sha` (read, never run)."""
    path = workflow_ref.split("@", 1)[0]
    prefix = caller_repo + "/"
    if not path.startswith(prefix) or not re.fullmatch(r"[0-9a-f]{40}", caller_sha):
        raise ApiError("the calling workflow could not be named")
    content = api.get(f"/repos/{caller_repo}/contents/{path[len(prefix):]}?ref={caller_sha}") or {}
    return base64.b64decode(str(content.get("content") or "")).decode("utf-8", "replace")


def main() -> int:
    env = os.environ
    repo, sha = env.get("WORKFLOW_REPOSITORY", ""), env.get("WORKFLOW_SHA", "")
    try:
        api = RestApi(env.get("GITHUB_API_URL", "https://api.github.com"), env.get("GH_TOKEN", ""))
        ok, message = check(api, repo, sha)
        problems = [] if ok else [message]
        if env.get("CALLER_REPOSITORY"):
            text = caller_text(api, env["CALLER_REPOSITORY"], env.get("CALLER_WORKFLOW_REF", ""), env.get("CALLER_SHA", ""))
            problems += [p for p in check_caller(api, repo, text) if p not in problems]
    except ApiError as e:
        print(f"::error::{e}")
        return 2
    for p in problems:
        print(f"::error::{p}")
    if not problems:
        print(message + " The comment names its tag.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
