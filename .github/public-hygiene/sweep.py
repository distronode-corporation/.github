#!/usr/bin/env python3
"""Weekly sweep: every public repository's recent issue, pull request, review, comment
and release text, checked against rules.py, reported to a confidential GitLab issue.

    python3 sweep.py

Run by `.github/workflows/public-hygiene-sweep.yml`, which stays off until the
organization sets it up (see that file). The per-thread check catches text as it is
written; this catches what it cannot see: release notes, text written while a
repository had no caller workflow, and runs that failed.

Environment:

    GH_TOKEN                  the job's GITHUB_TOKEN; public data only is read
    GITHUB_REPOSITORY_OWNER   the organization
    SWEEP_DAYS                how far back to look (default 8, so weekly runs overlap)
    GITLAB_TOKEN              secret: a project access token, `api` scope, Reporter
    GITLAB_PROJECT            secret: the numeric id of the private project
    GITLAB_ISSUE              secret: the iid of a CONFIDENTIAL issue in it
    GITLAB_API                optional, default https://gitlab.com/api/v4

The report names each item's public URL and the rule ids, never the matched text. It
goes only to the GitLab issue, and only after the API confirms the issue is
confidential; otherwise the sweep refuses to post. The workflow log is public, so it
shows counts only, never an item's URL.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rules  # noqa: E402
from event import Api, ApiError, RestApi  # noqa: E402


@dataclass(frozen=True)
class Hit:
    repo: str
    kind: str
    url: str
    ids: tuple[str, ...]


def _after(stamp: str | None, since: dt.datetime) -> bool:
    if not stamp:
        return False
    return dt.datetime.fromisoformat(stamp.replace("Z", "+00:00")) >= since


def _user(item: dict[str, Any]) -> tuple[str | None, str | None]:
    u = item.get("user") or {}
    return u.get("login"), u.get("type")


def collect(api: Api, org: str, since: dt.datetime) -> tuple[list[Hit], int, list[str]]:
    """Findings in public text changed since `since`, how many texts were read, and what
    could not be read ("repo: what"). One unreadable endpoint (issues turned off, a rate
    limit, a network error) skips that part only; the sweep goes on with the rest."""
    stamp = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    hits: list[Hit] = []
    scanned = 0
    unreadable: list[str] = []

    def check(repo: str, kind: str, item: dict[str, Any], texts: tuple[str | None, ...]) -> None:
        nonlocal scanned
        # Release notes are checked whoever published them: a release workflow publishes
        # as the Actions bot, with notes a person wrote. The per-thread check's own
        # comment is the Actions bot's and is skipped with the rest.
        if kind != "release" and rules.is_skipped_author(*_user(item)):
            return
        scanned += 1
        ids = rules.rule_ids(*texts)
        if ids:
            hits.append(Hit(repo, kind, str(item.get("html_url") or ""), tuple(ids)))

    for repo in api.get_all(f"/orgs/{org}/repos?type=public"):
        if repo.get("private") or repo.get("archived"):
            continue
        name = repo["full_name"]

        def read(what: str, path: str) -> list[Any]:
            try:
                return api.get_all(path)
            except ApiError:
                unreadable.append(f"{name}: {what}")
                return []

        try:
            threads = api.get_all(f"/repos/{name}/issues?state=all&since={stamp}")
        except ApiError as e:
            # Issues turned off answers 410 here, and is not a failure. Anything else
            # is: the issues go unread and are listed as such. Either way pull requests
            # still have their own listing (no `since`, so filter on updated_at).
            if e.status != 410:
                unreadable.append(f"{name}: issues")
            pulls = read("pull requests", f"/repos/{name}/pulls?state=all&sort=updated&direction=desc")
            threads = [dict(p, pull_request={}) for p in pulls if _after(p.get("updated_at"), since)]
        for item in threads:
            kind = "pull request" if "pull_request" in item else "issue"
            check(name, kind, item, (item.get("title"), item.get("body")))
            if kind == "pull request":
                for review in read(f"reviews of #{int(item['number'])}", f"/repos/{name}/pulls/{int(item['number'])}/reviews"):
                    if _after(review.get("submitted_at"), since):
                        check(name, "review", review, (review.get("body"),))
        for c in read("comments", f"/repos/{name}/issues/comments?since={stamp}"):
            check(name, "comment", c, (c.get("body"),))
        for c in read("review comments", f"/repos/{name}/pulls/comments?since={stamp}"):
            check(name, "review comment", c, (c.get("body"),))
        for release in read("releases", f"/repos/{name}/releases"):
            if _after(release.get("published_at") or release.get("created_at"), since):
                check(name, "release", release, (release.get("name"), release.get("body")))
    return hits, scanned, unreadable


def render_note(hits: list[Hit], scanned: int, since: dt.datetime, unreadable: list[str] | None = None) -> str:
    lines = [
        f"### Public hygiene sweep, text since {since:%Y-%m-%d}",
        "",
        f"{scanned} public texts read; {len(hits)} with findings. Rule ids only; open each "
        "item to see the text, edit it, then delete the earlier revisions.",
        "",
        "| Repository | Item | Rules |",
        "|---|---|---|",
    ]
    for h in hits:
        url = h.url if re.fullmatch(r"https://github\.com/\S+", h.url) else "(no link)"
        lines.append(f"| {h.repo} | {h.kind}: {url} | {', '.join(f'`{i}`' for i in h.ids)} |")
    if unreadable:
        lines += ["", "Not read this week (checked again next week):", ""]
        lines += [f"- {u}" for u in unreadable]
    return "\n".join(lines)


def post_report(gitlab: Api, project: str, issue: str, body: str) -> None:
    if not (project.isdigit() and issue.isdigit()):
        raise ApiError("GITLAB_PROJECT and GITLAB_ISSUE must be numeric ids")
    target = gitlab.get(f"/projects/{project}/issues/{issue}")
    if not (isinstance(target, dict) and target.get("confidential") is True):
        raise ApiError("the GitLab issue is not confidential; refusing to post")
    gitlab.post(f"/projects/{project}/issues/{issue}/notes", {"body": body})


def run(env: dict[str, str], github: Api | None = None, gitlab: Api | None = None, now: dt.datetime | None = None) -> int:
    org = env.get("GITHUB_REPOSITORY_OWNER", "")
    token = env.get("GITLAB_TOKEN", "")
    project, issue = env.get("GITLAB_PROJECT", ""), env.get("GITLAB_ISSUE", "")
    if not re.fullmatch(r"[\w.\-]+", org):
        print("::error::GITHUB_REPOSITORY_OWNER is required.")
        return 2
    if not (token and project and issue):
        print("::error::The sweep is not set up: GITLAB_TOKEN, GITLAB_PROJECT and GITLAB_ISSUE are required. Nothing was read.")
        return 2
    days = int(env.get("SWEEP_DAYS") or 8)
    since = (now or dt.datetime.now(dt.timezone.utc)) - dt.timedelta(days=days)
    github = github or RestApi(env.get("GITHUB_API_URL", "https://api.github.com"), env.get("GH_TOKEN", ""))
    gitlab = gitlab or RestApi(env.get("GITLAB_API", "https://gitlab.com/api/v4"), token, gitlab=True)

    hits, scanned, unreadable = collect(github, org, since)
    repos = len({h.repo for h in hits})
    print(f"Read {scanned} public texts changed in the last {days} days; {len(hits)} with findings in {repos} repositories.")
    if unreadable:
        print(f"::warning::{len(unreadable)} part(s) could not be read; the report lists them.")
    if hits or unreadable:
        post_report(gitlab, project, issue, render_note(hits, scanned, since, unreadable))
        print("Report posted to the confidential GitLab issue.")
    # A partial read still posts what it found, and then fails the run so it is seen.
    return 1 if unreadable else 0


def main() -> int:
    try:
        return run(dict(os.environ))
    except ApiError as e:
        print(f"::error::{e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
