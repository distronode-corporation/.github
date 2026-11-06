#!/usr/bin/env python3
"""Check one issue or pull request thread against rules.py, from inside a workflow run.

    python3 event.py

Called by `.github/workflows/public-hygiene.yml`. It reads the event from the file at
GITHUB_EVENT_PATH (never from the command line or the environment, so the text is in no
`run:` line and in no step's logged env), then reads the whole thread through the REST
API with the job's GITHUB_TOKEN (passed as GH_TOKEN): the title and description, every
conversation comment and, for a pull request, every review and review comment. The
event's own item is taken from the payload as well, since the API can lag a write by a
moment.

The result goes to three places, none of which ever holds the matched text:

- The log and the step summary: which kind of text had a finding, and the rule ids.
- One comment on the thread, kept up to date (found by the marker below and by its
  author, the Actions bot): the rule ids and their descriptions, a link to each item,
  and how to fix it. When a later run finds nothing, the comment says so.
- The exit status: 1 when anything in the thread has a finding, so a pull request's
  check fails. 2 on a usage or read error.

Writing the comment needs `issues: write` (issues) or `pull-requests: write` (pull
requests). A fork's pull request runs with a read-only token, so there the comment is
skipped with a warning and the failed check is the signal.

Text by Dependabot, Renovate and the Actions bot is skipped (rules.SKIPPED_BOTS): it is
generated from public upstream content.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import sys
import traceback
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rules  # noqa: E402

MARKER = "<!-- public-hygiene-check -->"
COMMENT_AUTHOR = "github-actions[bot]"
MAX_PAGES = 30
PR_EVENTS = {"pull_request", "pull_request_target", "pull_request_review", "pull_request_review_comment"}
ISSUE_EVENTS = {"issues", "issue_comment"}


class Api(Protocol):
    def get(self, path: str) -> Any: ...
    def get_all(self, path: str) -> list[Any]: ...
    def post(self, path: str, body: dict[str, Any]) -> Any: ...
    def patch(self, path: str, body: dict[str, Any]) -> Any: ...


class ApiError(Exception):
    """An API failure, described by method, path and status only. `status` is the HTTP
    status when there was one, else None."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class RestApi:
    """A REST API over urllib (GitHub by default). Errors carry the method, path and
    status, never a response body."""

    def __init__(self, base: str, token: str, *, gitlab: bool = False) -> None:
        if not base.startswith("https://"):
            raise ApiError("the API URL must be https")
        self.base = base.rstrip("/")
        self.token = token
        self.gitlab = gitlab

    def _request(self, method: str, url: str, body: dict[str, Any] | None = None) -> tuple[Any, str]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("User-Agent", "public-hygiene-check")
        if self.gitlab:
            req.add_header("PRIVATE-TOKEN", self.token)
        else:
            req.add_header("Accept", "application/vnd.github+json")
            req.add_header("X-GitHub-Api-Version", "2022-11-28")
            if self.token:
                req.add_header("Authorization", f"Bearer {self.token}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        path = url[len(self.base) :].split("?")[0]
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (https only)
                raw = resp.read()
                link = resp.headers.get("Link", "")
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

    def get_all(self, path: str) -> list[Any]:
        url = self.base + path + ("&" if "?" in path else "?") + "per_page=100"
        out: list[Any] = []
        for _ in range(MAX_PAGES):
            page, link = self._request("GET", url)
            out.extend(page or [])
            m = re.search(r'<([^>]+)>;\s*rel="next"', link)
            if not m or not m.group(1).startswith(self.base + "/"):
                return out
            url = m.group(1)
        raise ApiError(f"GET {path}: more than {MAX_PAGES} pages")

    def post(self, path: str, body: dict[str, Any]) -> Any:
        return self._request("POST", self.base + path, body)[0]

    def patch(self, path: str, body: dict[str, Any]) -> Any:
        return self._request("PATCH", self.base + path, body)[0]


@dataclass
class Source:
    kind: str  # "description", "comment", "review", "review comment"
    key: str
    url: str
    login: str | None
    account_type: str | None
    texts: tuple[str | None, ...]


def _user(item: dict[str, Any]) -> tuple[str | None, str | None]:
    user = item.get("user") or {}
    return user.get("login"), user.get("type")


def _is_own_comment(item: dict[str, Any]) -> bool:
    login, account_type = _user(item)
    return login == COMMENT_AUTHOR and account_type == "Bot" and MARKER in (item.get("body") or "")


def _source(kind: str, item: dict[str, Any], texts: tuple[str | None, ...]) -> Source:
    login, account_type = _user(item)
    return Source(kind, f"{kind}:{item.get('id')}", str(item.get("html_url") or ""), login, account_type, texts)


def thread_target(event_name: str, payload: dict[str, Any]) -> tuple[int, bool] | None:
    """(number, is_pull_request) of the thread the event belongs to, or None."""
    if event_name in PR_EVENTS and isinstance(payload.get("pull_request"), dict):
        return int(payload["pull_request"]["number"]), True
    if event_name in ISSUE_EVENTS and isinstance(payload.get("issue"), dict):
        issue = payload["issue"]
        return int(issue["number"]), "pull_request" in issue
    return None


def payload_sources(event_name: str, payload: dict[str, Any]) -> list[Source]:
    """The item the event is about, as the payload has it."""
    out: list[Source] = []
    head = payload.get("pull_request") if event_name in PR_EVENTS else payload.get("issue")
    if event_name in ("pull_request", "pull_request_target", "issues") and isinstance(head, dict):
        out.append(_source("description", head, (head.get("title"), head.get("body"))))
    if event_name == "issue_comment" and isinstance(payload.get("comment"), dict) and not _is_own_comment(payload["comment"]):
        out.append(_source("comment", payload["comment"], (payload["comment"].get("body"),)))
    if event_name == "pull_request_review" and isinstance(payload.get("review"), dict):
        out.append(_source("review", payload["review"], (payload["review"].get("body"),)))
    if event_name == "pull_request_review_comment" and isinstance(payload.get("comment"), dict):
        out.append(_source("review comment", payload["comment"], (payload["comment"].get("body"),)))
    return out


def thread_sources(api: Api, repo: str, number: int, is_pr: bool) -> tuple[list[Source], list[dict[str, Any]]]:
    """Every text in the thread, and the raw conversation comments (to find our own)."""
    issue = api.get(f"/repos/{repo}/issues/{number}")
    sources = [_source("description", issue, (issue.get("title"), issue.get("body")))]
    comments = api.get_all(f"/repos/{repo}/issues/{number}/comments")
    sources += [_source("comment", c, (c.get("body"),)) for c in comments if not _is_own_comment(c)]
    if is_pr:
        sources += [_source("review", r, (r.get("body"),)) for r in api.get_all(f"/repos/{repo}/pulls/{number}/reviews")]
        sources += [_source("review comment", c, (c.get("body"),)) for c in api.get_all(f"/repos/{repo}/pulls/{number}/comments")]
    return sources, comments


def _link(source: Source, is_pr: bool) -> str:
    noun = {"description": "pull request description" if is_pr else "issue description"}.get(source.kind, source.kind)
    label = f"The {noun}" if source.kind == "description" else f"A {noun}"
    if re.fullmatch(r"https://github\.com/[\w.\-]+/[\w.\-]+/(?:issues|pull)/\d+(?:#[\w\-]+)?", source.url):
        return f"[{label}]({source.url})"
    return label


def render_comment(results: list[tuple[Source, list[str]]], is_pr: bool) -> str:
    lines = [
        MARKER,
        "### Public hygiene check",
        "",
        "This repository is public. Text in this thread matches rules for operator or "
        "infrastructure detail that is kept out of public text. The matched text is not "
        "repeated here or in the run log.",
        "",
        "| Where | Rule | What the rule covers |",
        "|---|---|---|",
    ]
    for source, ids in results:
        for rule_id in ids:
            lines.append(f"| {_link(source, is_pr)} | `{rule_id}` | {rules.RULES_BY_ID[rule_id].description} |")
    lines += [
        "",
        "To fix: edit the text to remove that detail (operator steps belong in the private "
        "tracker; here, say they are tracked privately). Then delete the earlier revision from "
        "the item's \"edited\" menu, because GitHub keeps every revision public. This check "
        "runs again on the edit and updates this comment.",
    ]
    return "\n".join(lines)


def render_resolved() -> str:
    return "\n".join(
        [
            MARKER,
            "### Public hygiene check",
            "",
            "Nothing in this thread matches the public hygiene rules any more. If an edit "
            "removed the text, delete the earlier revision from the item's \"edited\" menu "
            "too, because GitHub keeps every revision public.",
        ]
    )


def write_summary(path: str | None, results: list[tuple[Source, list[str]]], scanned: int) -> None:
    if not path:
        return
    lines = ["### Public hygiene check", "", f"Texts checked: {scanned}.", ""]
    if results:
        lines += ["| Where | Rule |", "|---|---|"]
        lines += [f"| {s.kind} | `{rule_id}` |" for s, ids in results for rule_id in ids]
    else:
        lines.append("No findings.")
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def upsert_comment(api: Api, repo: str, number: int, comments: list[dict[str, Any]], body: str | None) -> str:
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


def run(env: dict[str, str], api: Api | None = None) -> int:
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
    number, is_pr = target
    if api is None:
        api = RestApi(env.get("GITHUB_API_URL", "https://api.github.com"), env.get("GH_TOKEN", ""))

    by_key: dict[str, Source] = {}
    comments: list[dict[str, Any]] = []
    thread_read = True
    try:
        listed, comments = thread_sources(api, repo, number, is_pr)
        by_key.update((s.key, s) for s in listed)
    except ApiError as e:
        thread_read = False
        print(f"::warning::Could not read the whole thread ({e}); checking the event's own item only.")
    for s in payload_sources(event_name, payload):
        if s.kind == "description":
            # The listing keys the description by issue id; the payload's PR object has
            # another id. Replace whichever description is there.
            by_key = {k: v for k, v in by_key.items() if v.kind != "description"}
        by_key[s.key] = s

    results: list[tuple[Source, list[str]]] = []
    scanned = 0
    for source in by_key.values():
        if rules.is_skipped_author(source.login, source.account_type):
            continue
        scanned += 1
        ids = rules.rule_ids(*source.texts)
        if ids:
            results.append((source, ids))

    print(f"Checked {scanned} text(s) in {'pull request' if is_pr else 'issue'} #{number}.")
    for source, ids in results:
        print(f"Finding in a {source.kind}: {', '.join(ids)}")
    write_summary(env.get("GITHUB_STEP_SUMMARY"), results, scanned)

    if thread_read:
        try:
            body = render_comment(results, is_pr) if results else None
            print(upsert_comment(api, repo, number, comments, body).capitalize() + ".")
        except ApiError as e:
            print(f"::warning::Could not write the hygiene comment ({e}). A fork's pull request has a read-only token.")
    elif results:
        print("::warning::The thread could not be read, so the comment was not written.")

    if results:
        ids = sorted({rule_id for _, rids in results for rule_id in rids})
        print(f"::error::Public hygiene findings: {', '.join(ids)}. The matched text is not shown; see the rules in the check's comment.")
        return 1
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
