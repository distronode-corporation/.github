#!/usr/bin/env python3
"""Check that a caller pins the shared check to a commit on this repository's default
branch.

    python3 pin.py

Run by the `pin` job of `.github/workflows/public-hygiene.yml`. A caller's
`uses: ...@<sha>` resolves any commit GitHub can see under this repository's name,
including one pushed to a pull request branch or to a fork (an impostor commit). This
job fails unless the pinned commit is the default branch's head or one of its ancestors,
so a pin to anything that was not reviewed and merged stays red.

Environment: WORKFLOW_REPOSITORY and WORKFLOW_SHA (from the `job` context, which names
the called workflow's own repository and commit), GH_TOKEN, GITHUB_API_URL.
"""

from __future__ import annotations

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


def main() -> int:
    env = os.environ
    try:
        api = RestApi(env.get("GITHUB_API_URL", "https://api.github.com"), env.get("GH_TOKEN", ""))
        ok, message = check(api, env.get("WORKFLOW_REPOSITORY", ""), env.get("WORKFLOW_SHA", ""))
    except ApiError as e:
        print(f"::error::{e}")
        return 2
    print(message if ok else f"::error::{message}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
