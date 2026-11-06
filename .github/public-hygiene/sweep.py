#!/usr/bin/env python3
"""Weekly sweep: every public repository's recent issue, pull request, review, comment,
discussion and release text, and the earlier revisions of recent issues and pull
requests, checked against rules.py and reported to a confidential GitLab issue.

    python3 sweep.py

Run by `.github/workflows/public-hygiene-sweep.yml`, which stays off until the
organization sets it up (see that file). The per-thread check catches text as it is
written; this catches what it cannot see: earlier revisions still present, text written
while a repository had no caller workflow, and runs that failed.

Environment:

    GH_TOKEN                  the job's GITHUB_TOKEN; public data only is read
    GITHUB_REPOSITORY         this repository (its activity keeps the schedule alive)
    GITHUB_REPOSITORY_OWNER   the organization
    SWEEP_DAYS                how far back to look (default 8, so weekly runs overlap)
    GITLAB_TOKEN              secret: a project access token, `api` scope, Reporter
    GITLAB_PROJECT            secret: the numeric id of the project holding the issue
    GITLAB_ISSUE              secret: the iid of a CONFIDENTIAL issue in it
    GITLAB_API                optional, default https://gitlab.com/api/v4
    PUBLIC_HYGIENE_DENYLIST_KEY  secret: the denylist key (see rules.py); without it the
                              `internal-name` rule does not run and the report says so

The report names each item's public URL and the rule ids, never the matched text. It
goes only to the GitLab issue, and only after the API confirms the issue is
confidential; otherwise the sweep refuses to post. The workflow log is public, so it
shows counts only, never an item's URL. Reviews and releases are read in full each week
(their timestamps do not change on an edit), so a finding is reported until it is fixed.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rules  # noqa: E402
from event import Api, ApiError, RestApi, _assoc, _hidden, _user  # noqa: E402

# GitHub turns a public repository's schedules off after 60 days without activity.
INACTIVE_WARNING_DAYS = 45
MAX_EDITS = 30

EDITS_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    issueOrPullRequest(number: $number) {
      ... on Issue { body userContentEdits(first: 30) { totalCount nodes { diff } } }
      ... on PullRequest { body userContentEdits(first: 30) { totalCount nodes { diff } } }
    }
  }
}
"""

DISCUSSIONS_QUERY = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    discussions(first: 50, orderBy: {field: UPDATED_AT, direction: DESC}) {
      nodes {
        title body url updatedAt authorAssociation author { login __typename }
        comments(first: 50) {
          nodes {
            body url isMinimized authorAssociation author { login __typename }
            replies(first: 50) { nodes { body url isMinimized authorAssociation author { login __typename } } }
          }
        }
      }
    }
  }
}
"""


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


def collect(api: Api, org: str, since: dt.datetime) -> tuple[list[Hit], int, list[str]]:
    """Findings in public text, how many texts were read, and what could not be read
    ("repo: what"). One unreadable part (issues turned off, a rate limit, a network
    error) skips that part only; the sweep goes on with the rest."""
    stamp = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    hits: list[Hit] = []
    scanned = 0
    unreadable: list[str] = []

    def check(repo: str, kind: str, item: dict[str, Any], texts: tuple[str | None, ...], skip_bots: bool = True) -> None:
        nonlocal scanned
        login, account_type = _user(item)
        if skip_bots and rules.is_skipped_author(login, account_type):
            return
        if _hidden(item):
            return
        scanned += 1
        ids = rules.rule_ids(*texts, outside=rules.is_outside_author(_assoc(item), account_type))
        if ids:
            hits.append(Hit(repo, kind, str(item.get("html_url") or item.get("url") or ""), tuple(ids)))

    for repo in api.get_all(f"/orgs/{org}/repos?type=public"):
        if repo.get("private") or repo.get("archived"):
            continue
        name = repo["full_name"]
        owner, short = name.split("/", 1)

        def read(what: str, path: str) -> list[Any]:
            try:
                return api.get_all(path)
            except ApiError:
                unreadable.append(f"{name}: {what}")
                return []

        try:
            threads = api.get_all(f"/repos/{name}/issues?state=all&since={stamp}")
        except ApiError as e:
            # Issues turned off answers 410 here, and is not a failure. Anything else is:
            # the issues go unread and are listed as such. Either way pull requests still
            # have their own listing (no `since`, so filter on updated_at).
            if e.status != 410:
                unreadable.append(f"{name}: issues")
            pulls = read("pull requests", f"/repos/{name}/pulls?state=all&sort=updated&direction=desc")
            threads = [dict(p, pull_request={}) for p in pulls if _after(p.get("updated_at"), since)]
        for item in threads:
            kind = "pull request" if "pull_request" in item else "issue"
            number = int(item["number"])
            check(name, kind, item, (item.get("title"), item.get("body")))
            if kind == "pull request":
                for review in read(f"reviews of #{number}", f"/repos/{name}/pulls/{number}/reviews"):
                    check(name, "review", review, (review.get("body"),))
            # Earlier revisions of the description: GitHub keeps every one public.
            try:
                data = api.graphql(EDITS_QUERY, {"owner": owner, "name": short, "number": number})
                node = (data.get("repository") or {}).get("issueOrPullRequest") or {}
                edits = (node.get("userContentEdits") or {}).get("nodes") or []
                current = node.get("body") or ""
                flagged = sum(1 for e in edits[:MAX_EDITS] if e.get("diff") and e["diff"] != current and rules.rule_ids(e["diff"]))
                if flagged:
                    ids = tuple(sorted({i for e in edits[:MAX_EDITS] if e.get("diff") and e["diff"] != current for i in rules.rule_ids(e["diff"])}))
                    hits.append(Hit(name, f"{flagged} earlier revision(s) of a {kind}", str(item.get("html_url") or ""), ids))
            except ApiError:
                unreadable.append(f"{name}: revisions of #{number}")
        for c in read("comments", f"/repos/{name}/issues/comments?since={stamp}"):
            check(name, "comment", c, (c.get("body"),))
        for c in read("review comments", f"/repos/{name}/pulls/comments?since={stamp}"):
            check(name, "review comment", c, (c.get("body"),))
        for release in read("releases", f"/repos/{name}/releases"):
            # Checked whoever published them: a release workflow publishes as a bot, with
            # notes a person wrote.
            check(name, "release", release, (release.get("name"), release.get("body")), skip_bots=False)
        if repo.get("has_discussions"):
            try:
                data = api.graphql(DISCUSSIONS_QUERY, {"owner": owner, "name": short})
                for d in ((data.get("repository") or {}).get("discussions") or {}).get("nodes") or []:
                    if not _after(d.get("updatedAt"), since):
                        continue
                    check(name, "discussion", d, (d.get("title"), d.get("body")))
                    for c in (d.get("comments") or {}).get("nodes") or []:
                        check(name, "discussion comment", c, (c.get("body"),))
                        for r in (c.get("replies") or {}).get("nodes") or []:
                            check(name, "discussion comment", r, (r.get("body"),))
            except ApiError:
                unreadable.append(f"{name}: discussions")
    return hits, scanned, unreadable


def idle_days(api: Api, repo: str, now: dt.datetime) -> int | None:
    """Days since the last commit on this repository's default branch, or None."""
    try:
        commits = api.get(f"/repos/{repo}/commits?per_page=1")
        stamp = commits[0]["commit"]["committer"]["date"]
    except (ApiError, LookupError, TypeError):
        return None
    return (now - dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))).days


def render_note(hits: list[Hit], scanned: int, since: dt.datetime, unreadable: list[str] | None = None, idle: int | None = None) -> str:
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
    if not rules.internal_names_enabled():
        lines += ["", "The internal-name rule did not run this week: the sweep had no denylist key."]
    if idle is not None and idle >= INACTIVE_WARNING_DAYS:
        lines += ["", f"The sweep's repository has had no commit for {idle} days. GitHub turns its schedule off at 60; "
                  "push a commit or re-enable the workflow from the Actions tab."]
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
    days_text = env.get("SWEEP_DAYS") or "8"
    if not days_text.isdigit() or not 1 <= int(days_text) <= 366:
        print("::error::SWEEP_DAYS must be a whole number of days from 1 to 366.")
        return 2
    days = int(days_text)
    now = now or dt.datetime.now(dt.timezone.utc)
    since = now - dt.timedelta(days=days)
    github = github or RestApi(env.get("GITHUB_API_URL", "https://api.github.com"), env.get("GH_TOKEN", ""))
    gitlab = gitlab or RestApi(env.get("GITLAB_API", "https://gitlab.com/api/v4"), token, gitlab=True)

    hits, scanned, unreadable = collect(github, org, since)
    idle = idle_days(github, env.get("GITHUB_REPOSITORY", ""), now) if env.get("GITHUB_REPOSITORY") else None
    repos = len({h.repo for h in hits})
    print(f"Read {scanned} public texts changed in the last {days} days; {len(hits)} with findings in {repos} repositories.")
    if unreadable:
        print(f"::warning::{len(unreadable)} part(s) could not be read; the report lists them.")
    stale = idle is not None and idle >= INACTIVE_WARNING_DAYS
    if stale:
        print(f"::warning::No commit for {idle} days; GitHub turns the schedule off at 60.")
    if hits or unreadable or stale:
        post_report(gitlab, project, issue, render_note(hits, scanned, since, unreadable, idle))
        print("Report posted to the confidential GitLab issue.")
    # A partial read still posts what it found, and then fails the run so it is seen.
    return 1 if unreadable else 0


def main() -> int:
    try:
        return run(dict(os.environ))
    except ApiError as e:
        print(f"::error::{e}")
        return 2
    except Exception as e:  # noqa: BLE001 - the type and place only, never a message that could quote text
        frame = traceback.extract_tb(e.__traceback__)[-1]
        print(f"::error::Unexpected {type(e).__name__} at {Path(frame.filename).name}:{frame.lineno}; no text is shown.")
        return 2


if __name__ == "__main__":
    sys.exit(main())
