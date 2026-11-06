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

import base64
import datetime as dt
import os
import re
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pin  # noqa: E402
import rules  # noqa: E402
from event import Api, ApiError, AuthorGate, RestApi, _assoc, _hidden, _user  # noqa: E402

# GitHub turns a public repository's schedules off after 60 days without activity.
INACTIVE_WARNING_DAYS = 45
MAX_EDITS = 30

EDITS_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    issueOrPullRequest(number: $number) {
      ... on Issue { body editor { login __typename } userContentEdits(first: 30) { totalCount nodes { diff } } }
      ... on PullRequest { body editor { login __typename } userContentEdits(first: 30) { totalCount nodes { diff } } }
    }
  }
}
"""

DISCUSSIONS_QUERY = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    discussions(first: 50, orderBy: {field: UPDATED_AT, direction: DESC}) {
      pageInfo { hasNextPage }
      nodes {
        number title body url updatedAt authorAssociation author { login __typename } editor { login __typename }
        comments(first: 50) {
          pageInfo { hasNextPage }
          nodes {
            body url isMinimized authorAssociation author { login __typename } editor { login __typename }
            replies(first: 50) {
              totalCount
              nodes { body url isMinimized authorAssociation author { login __typename } editor { login __typename } }
            }
          }
        }
      }
    }
  }
}
"""

EDITORS_QUERY = """
query($ids: [ID!]!) { nodes(ids: $ids) { ... on Comment { id editor { login __typename } } } }
"""

COMMENT_KINDS = ("comment", "review", "review comment", "discussion comment")


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


def _edited_by_person(item: dict[str, Any]) -> bool:
    login, kind = _user({"user": item.get("editor") or {}})
    return bool(login) and not rules.is_skipped_author(login, kind)


def caller_pin(api: Api, org: str, repo: str) -> str | None:
    """None when the repository's caller pins a commit on the shared repository's main and
    names it by its tag, else what is wrong. Runs from main's code, so an impostor pin
    cannot vouch for itself."""
    path = "public-text.yml" if repo == f"{org}/.github" else "public-hygiene.yml"
    try:
        content = api.get(f"/repos/{repo}/contents/.github/workflows/{path}") or {}
    except ApiError as e:
        if e.status == 404:
            return "no caller workflow"
        raise
    try:
        text = base64.b64decode(str(content.get("content") or "")).decode("utf-8", "replace")
    except (ValueError, TypeError):
        return "the caller workflow could not be read"
    problems = pin.check_caller(api, f"{org}/.github", text)
    return "; ".join(problems) if problems else None


def collect(api: Api, org: str, since: dt.datetime) -> tuple[list[Hit], int, list[str]]:
    """Findings in public text, how many texts were read, and what could not be read or
    checked in full ("repo: what"). One unreadable part (issues turned off, a rate limit,
    a network error, a page cap) skips that part only; the sweep goes on with the rest."""
    stamp = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    hits: list[Hit] = []
    scanned = 0
    unreadable: list[str] = []
    gates: dict[str, AuthorGate] = {}

    def check(repo: str, kind: str, item: dict[str, Any], texts: tuple[str | None, ...], *, force: bool = False) -> None:
        nonlocal scanned
        login, account_type = _user(item)
        if _hidden(item):
            return
        if not force and kind != "release" and rules.is_skipped_author(login, account_type, comment=kind in COMMENT_KINDS) and not _edited_by_person(item):
            return
        scanned += 1
        url = str(item.get("html_url") or item.get("url") or "")
        if any(rules.was_truncated(t) for t in texts):
            unreadable.append(f"{repo}: a {kind} too long to check in full ({url})")
        ids = rules.rule_ids(*texts, outside=gates.setdefault(repo, AuthorGate(api, repo)).outside(login, _assoc(item), account_type))
        if ids:
            hits.append(Hit(repo, kind, url, tuple(ids)))

    for repo in api.get_all(f"/orgs/{org}/repos?type=public"):
        if repo.get("private") or repo.get("archived"):
            continue
        name = repo["full_name"]
        owner, short = name.split("/", 1)
        # Items by a skipped bot, held until we know whether a person last edited them.
        pending: list[tuple[str, dict[str, Any], tuple[str | None, ...]]] = []

        def read(what: str, path: str) -> list[Any]:
            try:
                return api.get_all(path)
            except ApiError:
                unreadable.append(f"{name}: {what}")
                return []

        def check_or_hold(kind: str, item: dict[str, Any], texts: tuple[str | None, ...]) -> None:
            login, account_type = _user(item)
            if rules.is_skipped_author(login, account_type, comment=kind in COMMENT_KINDS) and item.get("node_id"):
                pending.append((kind, item, texts))
            else:
                check(name, kind, item, texts)

        try:
            problem = caller_pin(api, org, name)
        except ApiError:
            problem = "the caller pin could not be checked"
        if problem:
            unreadable.append(f"{name}: caller pin ({problem})")

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
            if kind == "pull request":
                for review in read(f"reviews of #{number}", f"/repos/{name}/pulls/{number}/reviews"):
                    check_or_hold("review", review, (review.get("body"),))
            # The description, and its earlier revisions: GitHub keeps every one public.
            # They are held to the same author rules as the description itself.
            login, account_type = _user(item)
            outside = gates.setdefault(name, AuthorGate(api, name)).outside(login, _assoc(item), account_type)
            try:
                data = api.graphql(EDITS_QUERY, {"owner": owner, "name": short, "number": number})
            except ApiError:
                unreadable.append(f"{name}: revisions of #{number}")
                check(name, kind, item, (item.get("title"), item.get("body")))
                continue
            node = (data.get("repository") or {}).get("issueOrPullRequest") or {}
            by_person = _edited_by_person(node)
            if rules.is_skipped_author(login, account_type, comment=False) and not by_person:
                continue
            check(name, kind, item, (item.get("title"), item.get("body")), force=True)
            history = node.get("userContentEdits") or {}
            edits = history.get("nodes") or []
            if int(history.get("totalCount") or 0) > len(edits[:MAX_EDITS]):
                unreadable.append(f"{name}: revisions of #{number} (more than {MAX_EDITS})")
            current = node.get("body") or ""
            earlier = [e["diff"] for e in edits[:MAX_EDITS] if e.get("diff") and e["diff"] != current]
            found = [rules.rule_ids(d, outside=outside) for d in earlier]
            flagged = sum(1 for ids in found if ids)
            if flagged:
                ids = tuple(sorted({i for f in found for i in f}))
                hits.append(Hit(name, f"{flagged} earlier revision(s) of a {kind}", str(item.get("html_url") or ""), ids))
        for c in read("comments", f"/repos/{name}/issues/comments?since={stamp}"):
            check_or_hold("comment", c, (c.get("body"),))
        for c in read("review comments", f"/repos/{name}/pulls/comments?since={stamp}"):
            check_or_hold("review comment", c, (c.get("body"),))
        for release in read("releases", f"/repos/{name}/releases"):
            # Checked whoever published them: a release workflow publishes as a bot, with
            # notes a person wrote.
            check(name, "release", release, (release.get("name"), release.get("body")))
        if repo.get("has_discussions"):
            try:
                data = api.graphql(DISCUSSIONS_QUERY, {"owner": owner, "name": short})
                conn = (data.get("repository") or {}).get("discussions") or {}
                nodes = conn.get("nodes") or []
                if (conn.get("pageInfo") or {}).get("hasNextPage") and nodes and _after(nodes[-1].get("updatedAt"), since):
                    unreadable.append(f"{name}: discussions (more recent ones than one page)")
                for d in nodes:
                    if not _after(d.get("updatedAt"), since):
                        continue
                    check(name, "discussion", d, (d.get("title"), d.get("body")))
                    comments = d.get("comments") or {}
                    if (comments.get("pageInfo") or {}).get("hasNextPage"):
                        unreadable.append(f"{name}: comments of discussion #{d.get('number')} (more than one page)")
                    for c in comments.get("nodes") or []:
                        check(name, "discussion comment", c, (c.get("body"),))
                        replies = c.get("replies") or {}
                        reply_nodes = replies.get("nodes") or []
                        if int(replies.get("totalCount") or 0) > len(reply_nodes):
                            unreadable.append(f"{name}: replies in discussion #{d.get('number')} (more than one page)")
                        for r in reply_nodes:
                            check(name, "discussion comment", r, (r.get("body"),))
            except ApiError:
                unreadable.append(f"{name}: discussions")
        # A skipped bot's comment or review is checked when a person last edited it.
        ids = [str(item["node_id"]) for _, item, _ in pending]
        edited: set[str] = set()
        try:
            for i in range(0, len(ids), 100):
                data = api.graphql(EDITORS_QUERY, {"ids": ids[i : i + 100]})
                edited |= {str(n.get("id")) for n in data.get("nodes") or [] if isinstance(n, dict) and _edited_by_person(n)}
        except ApiError:
            unreadable.append(f"{name}: editors of bot comments")
        for kind, item, texts in pending:
            if str(item["node_id"]) in edited:
                check(name, kind, item, texts, force=True)
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
