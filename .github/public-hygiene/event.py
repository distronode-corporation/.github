#!/usr/bin/env python3
"""Check one issue, pull request, discussion or release against rules.py, from inside a
workflow run.

    python3 event.py

Called by `.github/workflows/public-hygiene.yml`. It reads the event from the file at
GITHUB_EVENT_PATH (never from the command line or the environment, so the text is in no
`run:` line and in no step's logged env), then reads the whole thread with the job's
GITHUB_TOKEN (passed as GH_TOKEN):

- an issue or pull request: the title, the description, every conversation comment and,
  for a pull request, every review, review comment and commit message (the REST API);
- a discussion: the title, the body, every comment and reply (the GraphQL API);
- a release: its name and notes (the payload).

The event's own item is taken from the payload as well, since the API can lag a write by
a moment; a deleted item is not.

The result goes to three places, none of which ever holds the matched text:

- The log and the step summary: which kind of text had a finding, and the rule ids.
- One comment on the thread (not on a release), kept up to date and found by the marker
  below and by its author, the Actions bot: the rule ids, their descriptions, a link to
  each item, and how to fix it. When a later run finds nothing, the comment says so.
- The exit status: 1 when anything in the thread has a finding. 2 when the thread could
  not be read in full (an API error, more than MAX_PAGES pages, the time budget): a run
  that could not check everything has failed, never passed, so a later run that hit a
  rate limit cannot turn a red check green.

Writing the comment needs `issues: write` (issues and pull requests) or
`discussions: write`. A fork's pull request runs with a read-only token, so there the
comment is skipped with a warning and the failed check is the signal.

Authors: text by Dependabot and Renovate and by the code review bots (Seer, Copilot) is
skipped (rules.SKIPPED_BOTS), unless a person edited it in this event. An author outside the organization (no write access, not a bot)
is checked for credentials only (rules.scan, `outside=True`). Everyone else, every other
bot included, is checked against every rule. A minimized (hidden) comment is skipped.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import sys
import time
import traceback
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rules  # noqa: E402

MARKER = "<!-- public-hygiene-check -->"
COMMENT_AUTHOR = "github-actions[bot]"
MAX_PAGES = 30
MAX_COMMIT_PAGES = 3  # the API lists at most 250 commits of a pull request
TIME_BUDGET = 240.0  # seconds; the job's timeout is 5 minutes
PR_EVENTS = {"pull_request", "pull_request_target", "pull_request_review", "pull_request_review_comment"}
ISSUE_EVENTS = {"issues", "issue_comment"}
DISCUSSION_EVENTS = {"discussion", "discussion_comment"}
RELEASE_EVENTS = {"release"}
URL_SHAPE = re.compile(r"https://github\.com/[\w.\-]+/[\w.\-]+/(?:issues|pull|discussions|releases/tag|commit)/[\w.\-%]+(?:#[\w\-]+)?")


class Api(Protocol):
    def get(self, path: str) -> Any: ...
    def get_all(self, path: str, max_pages: int = MAX_PAGES) -> list[Any]: ...
    def post(self, path: str, body: dict[str, Any]) -> Any: ...
    def patch(self, path: str, body: dict[str, Any]) -> Any: ...
    def graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]: ...


class ApiError(Exception):
    """An API failure, described by method, path and status only. `status` is the HTTP
    status when there was one, else None."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class _Deadline:
    """The run's wall-clock budget, below the job's timeout."""

    end: float | None = None

    @classmethod
    def start(cls, seconds: float) -> None:
        cls.end = time.monotonic() + seconds

    @classmethod
    def check(cls) -> None:
        if cls.end is not None and time.monotonic() > cls.end:
            raise ApiError("the run's time budget is spent")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """None of these endpoints redirects. Following one would carry the token to another
    host (or to plain http), and would replay a POST as a bodiless GET."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise ApiError(f"{req.get_method()} answered {code}: redirects are refused", code)


OPENER = urllib.request.build_opener(_NoRedirect)


class RestApi:
    """GitHub's REST and GraphQL APIs (or GitLab's REST API) over urllib. Errors carry
    the method, path and status, never a response body."""

    def __init__(self, base: str, token: str, *, gitlab: bool = False) -> None:
        if not base.startswith("https://"):
            raise ApiError("the API URL must be https")
        self.base = base.rstrip("/")
        self.token = token
        self.gitlab = gitlab

    def _request(self, method: str, url: str, body: dict[str, Any] | None = None) -> tuple[Any, str]:
        _Deadline.check()
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("User-Agent", "public-hygiene-check")
        # Unredirected: never copied onto another request, whatever answers.
        if self.gitlab:
            req.add_unredirected_header("PRIVATE-TOKEN", self.token)
        else:
            req.add_header("Accept", "application/vnd.github+json")
            req.add_header("X-GitHub-Api-Version", "2022-11-28")
            if self.token:
                req.add_unredirected_header("Authorization", f"Bearer {self.token}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        path = url[len(self.base) :].split("?")[0]
        try:
            with OPENER.open(req, timeout=30) as resp:
                raw = resp.read()
                link = resp.headers.get("Link", "")
        except ApiError:
            raise
        except urllib.error.HTTPError as e:
            raise ApiError(f"{method} {path}: HTTP {e.code}", e.code) from None
        except (OSError, http.client.HTTPException) as e:
            # URLError, timeouts, resets mid-read and malformed responses alike.
            raise ApiError(f"{method} {path}: {type(e).__name__}") from None
        try:
            return (json.loads(raw) if raw else None), link
        except ValueError:
            raise ApiError(f"{method} {path}: the response is not JSON") from None

    def get(self, path: str) -> Any:
        return self._request("GET", self.base + path)[0]

    def get_all(self, path: str, max_pages: int = MAX_PAGES) -> list[Any]:
        url = self.base + path + ("&" if "?" in path else "?") + "per_page=100"
        out: list[Any] = []
        for _ in range(max_pages):
            page, link = self._request("GET", url)
            out.extend(page or [])
            m = re.search(r'<([^>]+)>;\s*rel="next"', link)
            if not m or not m.group(1).startswith(self.base + "/"):
                return out
            url = m.group(1)
        raise ApiError(f"GET {path.split('?')[0]}: more than {max_pages} pages")

    def post(self, path: str, body: dict[str, Any]) -> Any:
        return self._request("POST", self.base + path, body)[0]

    def patch(self, path: str, body: dict[str, Any]) -> Any:
        return self._request("PATCH", self.base + path, body)[0]

    def graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        result = self._request("POST", self.base + "/graphql", {"query": query, "variables": variables})[0]
        if not isinstance(result, dict) or result.get("errors") or not isinstance(result.get("data"), dict):
            raise ApiError("POST /graphql: the query failed")
        return result["data"]


@dataclass
class Source:
    kind: str  # "title", "description", "comment", "review", "review comment", "commit message", "release"
    key: str
    url: str
    login: str | None
    account_type: str | None
    texts: tuple[str | None, ...]
    association: str | None = None
    # Scan even when the author is a skipped bot: a person edited it in this event.
    edited_by_person: bool = False
    truncated: bool = field(default=False, compare=False)


@dataclass(frozen=True)
class Target:
    kind: str  # "issue", "pr", "discussion", "release"
    number: int


def _user(item: dict[str, Any]) -> tuple[str | None, str | None]:
    user = item.get("user") or item.get("author") or {}
    login, kind = user.get("login"), user.get("type") or user.get("__typename")
    if "type" not in user and kind == "Bot" and login and not login.endswith("[bot]"):
        login += "[bot]"  # GraphQL names an app bot without the suffix REST uses
    return login, kind


def _assoc(item: dict[str, Any]) -> str | None:
    return item.get("author_association") or item.get("authorAssociation")


def _is_own_comment(item: dict[str, Any]) -> bool:
    login, account_type = _user(item)
    return login == COMMENT_AUTHOR and account_type == "Bot" and MARKER in (item.get("body") or "")


def _hidden(item: dict[str, Any]) -> bool:
    return bool(item.get("minimized") or item.get("isMinimized"))


def _source(kind: str, item: dict[str, Any], texts: tuple[str | None, ...], key: str | None = None, url: str | None = None) -> Source:
    login, account_type = _user(item)
    return Source(
        kind,
        key or f"{kind}:{item.get('id')}",
        str(url if url is not None else item.get("html_url") or item.get("url") or ""),
        login,
        account_type,
        texts,
        _assoc(item),
    )


def _head(kind: str, item: dict[str, Any]) -> list[Source]:
    """The title and the body of an issue, pull request or discussion, as two items, so
    the comment says which one to fix."""
    return [
        _source("title", item, (item.get("title"),), key="title"),
        _source("description", item, (item.get("body"),), key="description"),
    ]


def thread_target(event_name: str, payload: dict[str, Any]) -> Target | None:
    """The thread the event belongs to, or None."""
    if event_name in PR_EVENTS and isinstance(payload.get("pull_request"), dict):
        return Target("pr", int(payload["pull_request"]["number"]))
    if event_name in ISSUE_EVENTS and isinstance(payload.get("issue"), dict):
        issue = payload["issue"]
        return Target("pr" if "pull_request" in issue else "issue", int(issue["number"]))
    if event_name in DISCUSSION_EVENTS and isinstance(payload.get("discussion"), dict):
        return Target("discussion", int(payload["discussion"]["number"]))
    if event_name in RELEASE_EVENTS and isinstance(payload.get("release"), dict):
        return Target("release", int(payload["release"].get("id") or 0))
    return None


def payload_sources(event_name: str, payload: dict[str, Any]) -> list[Source]:
    """The item the event is about, as the payload has it. A deleted item is gone."""
    if payload.get("action") == "deleted":
        return []
    sender_login, sender_type = _user({"user": payload.get("sender") or {}})
    by_person = payload.get("action") == "edited" and not rules.is_skipped_author(sender_login, sender_type)
    out: list[Source] = []
    if event_name in ("pull_request", "pull_request_target"):
        out += _head("pr", payload["pull_request"])
    elif event_name == "issues":
        out += _head("issue", payload["issue"])
    elif event_name == "discussion":
        out += _head("discussion", payload["discussion"])
    elif event_name in ("issue_comment", "discussion_comment") and isinstance(payload.get("comment"), dict):
        comment = payload["comment"]
        if not _is_own_comment(comment) and not _hidden(comment):
            out.append(_source("comment", comment, (comment.get("body"),), key=f"comment:{comment.get('node_id') or comment.get('id')}"))
    elif event_name == "pull_request_review" and isinstance(payload.get("review"), dict):
        out.append(_source("review", payload["review"], (payload["review"].get("body"),)))
    elif event_name == "pull_request_review_comment" and isinstance(payload.get("comment"), dict):
        out.append(_source("review comment", payload["comment"], (payload["comment"].get("body"),)))
    elif event_name == "release" and isinstance(payload.get("release"), dict):
        release = payload["release"]
        out.append(_source("release", release, (release.get("name"), release.get("body")), key="release"))
    for s in out:
        s.edited_by_person = by_person
    return out


def issue_thread(api: Api, repo: str, number: int, is_pr: bool) -> tuple[list[Source], list[dict[str, Any]]]:
    """Every text in an issue or pull request thread, and the raw conversation comments
    (to find our own)."""
    issue = api.get(f"/repos/{repo}/issues/{number}")
    sources = _head("pr" if is_pr else "issue", issue)
    comments = api.get_all(f"/repos/{repo}/issues/{number}/comments")
    sources += [
        _source("comment", c, (c.get("body"),), key=f"comment:{c.get('node_id') or c.get('id')}")
        for c in comments
        if not _is_own_comment(c) and not _hidden(c)
    ]
    if is_pr:
        sources += [_source("review", r, (r.get("body"),)) for r in api.get_all(f"/repos/{repo}/pulls/{number}/reviews")]
        sources += [_source("review comment", c, (c.get("body"),)) for c in api.get_all(f"/repos/{repo}/pulls/{number}/comments")]
        # Commit messages and the addresses they carry. The API lists at most 250.
        pr_association = _assoc(issue)
        for c in api.get_all(f"/repos/{repo}/pulls/{number}/commits", MAX_COMMIT_PAGES):
            commit = c.get("commit") or {}
            texts = (commit.get("message"), (commit.get("author") or {}).get("email"), (commit.get("committer") or {}).get("email"))
            src = _source("commit message", {"user": c.get("author") or {}, "id": c.get("sha")}, texts, url=c.get("html_url"))
            src.association = pr_association
            sources.append(src)
    return sources, comments


DISCUSSION_QUERY = """
query($owner: String!, $name: String!, $number: Int!, $after: String) {
  repository(owner: $owner, name: $name) {
    discussion(number: $number) {
      id title body url authorAssociation author { login __typename }
      comments(first: 50, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id body url isMinimized authorAssociation author { login __typename }
          replies(first: 50) {
            totalCount
            nodes { id body url isMinimized authorAssociation author { login __typename } }
          }
        }
      }
    }
  }
}
"""


def discussion_thread(api: Api, repo: str, number: int) -> tuple[list[Source], list[dict[str, Any]], str]:
    """Every text in a discussion, its top-level comments (to find our own) and its node id."""
    owner, name = repo.split("/", 1)
    sources: list[Source] = []
    top: list[dict[str, Any]] = []
    after: str | None = None
    node_id = ""
    for _ in range(MAX_PAGES):
        data = api.graphql(DISCUSSION_QUERY, {"owner": owner, "name": name, "number": number, "after": after})
        discussion = ((data.get("repository") or {}).get("discussion")) or None
        if not isinstance(discussion, dict):
            raise ApiError("POST /graphql: no such discussion")
        if not sources:
            node_id = str(discussion.get("id") or "")
            sources += _head("discussion", discussion)
        conn = discussion.get("comments") or {}
        for c in conn.get("nodes") or []:
            top.append(c)
            if not _is_own_comment(c) and not _hidden(c):
                sources.append(_source("comment", c, (c.get("body"),), key=f"comment:{c.get('id')}"))
            replies = c.get("replies") or {}
            nodes = replies.get("nodes") or []
            if int(replies.get("totalCount") or 0) > len(nodes):
                raise ApiError("POST /graphql: more replies than one page")
            for r in nodes:
                if not _hidden(r):
                    sources.append(_source("comment", r, (r.get("body"),), key=f"comment:{r.get('id')}"))
        page = conn.get("pageInfo") or {}
        if not page.get("hasNextPage"):
            return sources, top, node_id
        after = page.get("endCursor")
    raise ApiError(f"POST /graphql: more than {MAX_PAGES} pages of comments")


NOUN = {
    "issue": "issue",
    "pr": "pull request",
    "discussion": "discussion",
    "release": "release",
}


def _link(source: Source, target: Target) -> str:
    if source.kind in ("title", "description"):
        label = f"The {NOUN[target.kind]} {source.kind}"
    elif source.kind == "release":
        label = "The release notes"
    else:
        label = f"A {source.kind}"
    if URL_SHAPE.fullmatch(source.url):
        return f"[{label}]({source.url})"
    return label


def _fix_notes(results: list[tuple[Source, list[str]]]) -> list[str]:
    kinds = {s.kind for s, _ in results}
    ids = {i for _, rids in results for i in rids}
    notes = [
        "To fix: edit the text to remove that detail (operator steps belong in the private tracker; here, "
        "say they are tracked privately). Then delete the earlier revisions from the item's \"edited\" menu, "
        "because GitHub keeps every revision public. Deleting the item works too. This check runs again on "
        "the edit and updates this comment."
    ]
    if "token" in ids:
        notes.append("**A credential:** revoke or rotate it first. Editing the text does not take it back; "
                     "assume it was copied the moment it was posted.")
    if "title" in kinds:
        notes.append("**A title:** the earlier title also stays in the timeline (\"changed the title\"), and "
                     "only GitHub Support can remove that entry.")
    if "commit message" in kinds:
        notes.append("**A commit message:** rewrite the commit (amend or rebase) and force-push the branch "
                     "before merging. After the merge it stays in the history.")
    return notes


def render_comment(results: list[tuple[Source, list[str]]], target: Target) -> str:
    lines = [
        MARKER,
        "### Public hygiene check",
        "",
        "This repository is public. Text here matches rules for operator or infrastructure detail "
        "that is kept out of public text. The matched text is not repeated here or in the run log.",
        "",
        "| Where | Rule | What the rule covers |",
        "|---|---|---|",
    ]
    for source, ids in results:
        for rule_id in ids:
            lines.append(f"| {_link(source, target)} | `{rule_id}` | {rules.RULES_BY_ID[rule_id].description} |")
    lines.append("")
    for note in _fix_notes(results):
        lines += [note, ""]
    return "\n".join(lines).rstrip()


def render_resolved() -> str:
    return "\n".join(
        [
            MARKER,
            "### Public hygiene check",
            "",
            "Nothing here matches the public hygiene rules any more. If an edit removed the text, "
            "delete the earlier revisions from the item's \"edited\" menu too, because GitHub keeps "
            "every revision public.",
        ]
    )


def write_summary(path: str | None, results: list[tuple[Source, list[str]]], scanned: int, problems: list[str]) -> None:
    if not path:
        return
    lines = ["### Public hygiene check", "", f"Texts checked: {scanned}.", ""]
    lines += [f"- {p}" for p in problems]
    if problems:
        lines.append("")
    if results:
        lines += ["| Where | Rule |", "|---|---|"]
        lines += [f"| {s.kind} | `{rule_id}` |" for s, ids in results for rule_id in ids]
    else:
        lines.append("No findings.")
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def upsert_issue_comment(api: Api, repo: str, number: int, comments: list[dict[str, Any]], body: str | None) -> str:
    """Create, update or leave the one marker comment. `body` None means "resolved if one
    exists". Returns what happened, for the log."""
    own = [c for c in comments if _is_own_comment(c)]
    existing = own[0] if own else None
    if body is None:
        if existing is None:
            return "no comment needed"
        body = render_resolved()
    if existing is not None:
        if (existing.get("body") or "") == body:
            return "comment already current"
        api.patch(f"/repos/{repo}/issues/comments/{int(existing['id'])}", {"body": body})
        return "comment updated"
    api.post(f"/repos/{repo}/issues/{number}/comments", {"body": body})
    return "comment posted"


ADD_COMMENT = "mutation($id: ID!, $body: String!) { addDiscussionComment(input: {discussionId: $id, body: $body}) { comment { id } } }"
UPDATE_COMMENT = "mutation($id: ID!, $body: String!) { updateDiscussionComment(input: {commentId: $id, body: $body}) { comment { id } } }"


def upsert_discussion_comment(api: Api, discussion_id: str, comments: list[dict[str, Any]], body: str | None) -> str:
    own = [c for c in comments if _is_own_comment(c)]
    existing = own[0] if own else None
    if body is None:
        if existing is None:
            return "no comment needed"
        body = render_resolved()
    if existing is not None:
        if (existing.get("body") or "") == body:
            return "comment already current"
        api.graphql(UPDATE_COMMENT, {"id": str(existing["id"]), "body": body})
        return "comment updated"
    api.graphql(ADD_COMMENT, {"id": discussion_id, "body": body})
    return "comment posted"


def run(env: dict[str, str], api: Api | None = None) -> int:
    _Deadline.start(float(env.get("PUBLIC_HYGIENE_TIME_BUDGET") or TIME_BUDGET))
    event_name = env.get("GITHUB_EVENT_NAME", "")
    event_path = env.get("GITHUB_EVENT_PATH", "")
    repo = env.get("GITHUB_REPOSITORY", "")
    if not event_path or not re.fullmatch(r"[\w.\-]+/[\w.\-]+", repo):
        print("::error::GITHUB_EVENT_PATH and GITHUB_REPOSITORY are required.")
        return 2
    try:
        payload = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"::error::Could not read the event payload ({type(e).__name__}).")
        return 2
    target = thread_target(event_name, payload)
    if target is None:
        print(f"Nothing to check for a {event_name or 'missing'} event.")
        return 0
    if api is None:
        api = RestApi(env.get("GITHUB_API_URL", "https://api.github.com"), env.get("GH_TOKEN", ""))

    by_key: dict[str, Source] = {}
    comments: list[dict[str, Any]] = []
    discussion_id = ""
    problems: list[str] = []
    thread_read = True
    if target.kind != "release":
        try:
            if target.kind == "discussion":
                listed, comments, discussion_id = discussion_thread(api, repo, target.number)
            else:
                listed, comments = issue_thread(api, repo, target.number, target.kind == "pr")
            by_key.update((s.key, s) for s in listed)
        except ApiError as e:
            thread_read = False
            problems.append(f"The thread could not be read in full ({e}); only the event's own item was checked.")
    for s in payload_sources(event_name, payload):
        by_key[s.key] = s

    results: list[tuple[Source, list[str]]] = []
    scanned = 0
    for source in by_key.values():
        try:
            _Deadline.check()
        except ApiError as e:
            problems.append(f"Stopped early: {e}.")
            thread_read = False
            break
        if rules.is_skipped_author(source.login, source.account_type) and not source.edited_by_person:
            continue
        scanned += 1
        if any(rules.was_truncated(t) for t in source.texts):
            problems.append(f"A {source.kind} is longer than {rules.MAX_SCAN_CHARS} characters; only the start was checked.")
        outside = rules.is_outside_author(source.association, source.account_type)
        ids = rules.rule_ids(*source.texts, outside=outside)
        if ids:
            results.append((source, ids))

    if not rules.internal_names_enabled():
        # Neutral on purpose: forks and Dependabot runs get no secrets.
        problems.append("The internal-name rule did not run (no denylist key in this run); every other rule did.")
    print(f"Checked {scanned} text(s) in {NOUN[target.kind]} {target.number if target.kind != 'release' else ''}".rstrip() + ".")
    for p in problems:
        print(f"::warning::{p}")
    for source, ids in results:
        print(f"Finding in a {source.kind}: {', '.join(ids)}")
    write_summary(env.get("GITHUB_STEP_SUMMARY"), results, scanned, problems)

    if thread_read and target.kind != "release":
        try:
            body = render_comment(results, target) if results else None
            if target.kind == "discussion":
                outcome = upsert_discussion_comment(api, discussion_id, comments, body)
            else:
                outcome = upsert_issue_comment(api, repo, target.number, comments, body)
            print(outcome.capitalize() + ".")
        except ApiError as e:
            print(f"::warning::Could not write the hygiene comment ({e}). A fork's pull request has a read-only token.")
    elif results and target.kind != "release":
        print("::warning::The thread could not be read, so the comment was not written.")

    if results:
        ids = sorted({rule_id for _, rids in results for rule_id in rids})
        print(f"::error::Public hygiene findings: {', '.join(ids)}. The matched text is not shown; see the rules in the check's comment or summary.")
        return 1
    if not thread_read:
        print("::error::The thread could not be checked in full, so this run fails rather than passes.")
        return 2
    return 0


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
