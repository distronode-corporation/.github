#!/usr/bin/env python3
"""Record whether a pull request has unresolved review threads, as one commit status.

    python3 review_threads.py

Called by `.github/workflows/review-threads.yml`. It reads the event from the file at
GITHUB_EVENT_PATH and the review threads over GraphQL with the job's GITHUB_TOKEN
(passed as GH_TOKEN).

- A pull request event (`pull_request`, `pull_request_review`,
  `pull_request_review_comment`): that one pull request.
- Any other event (`schedule`, `workflow_dispatch`): every open pull request in the
  repository. GitHub has no event for a thread being resolved, so this pass is what turns
  a red status green once the last thread is resolved.

Each pull request gets ONE commit status on its head commit, context `review-threads`:
`failure` while any thread is unresolved (from any author, outdated or not), `success`
when none is. The newest status of a context is the one that counts, so a later run always
supersedes an earlier one, whichever event started it.

The job itself does not fail on a verdict, so its own check run is never a stale red. It
exits 1 only when it could not do its work (an API error, or a status write refused on a
pull request from this repository); a status of `error` is then written where possible.

A fork's pull request runs with a read-only token, so its event runs cannot write the
status: they log and summarize the verdict, and the next scheduled run (from this
repository, with a writable token) records it. Until then the required status is missing,
which blocks a merge rather than allowing one.

The step summary lists every unresolved thread: author, file:line, the first line of its
first comment, and a link.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

CONTEXT = "review-threads"
API = "https://api.github.com"
MAX_PAGES = 50
PR_EVENTS = {"pull_request", "pull_request_review", "pull_request_review_comment"}

THREADS_QUERY = """
query($owner: String!, $name: String!, $number: Int!, $after: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      number
      headRefOid
      isCrossRepository
      reviewThreads(first: 100, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id
          isResolved
          isOutdated
          path
          line
          originalLine
          comments(first: 100) {
            totalCount
            pageInfo { hasNextPage endCursor }
            nodes { author { login } body url }
          }
        }
      }
    }
  }
}
"""

COMMENTS_QUERY = """
query($id: ID!, $after: String) {
  node(id: $id) {
    ... on PullRequestReviewThread {
      comments(first: 100, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes { author { login } body url }
      }
    }
  }
}
"""

OPEN_PRS_QUERY = """
query($owner: String!, $name: String!, $after: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(states: OPEN, first: 100, after: $after) {
      pageInfo { hasNextPage endCursor }
      nodes { number }
    }
  }
}
"""


class ApiError(Exception):
    pass


Graphql = Callable[[str, dict[str, Any]], dict[str, Any]]
Post = Callable[[str, dict[str, Any]], Any]


class Http:
    """GitHub's REST and GraphQL APIs over urllib."""

    def __init__(self, token: str, base: str = API) -> None:
        self.token = token
        self.base = base

    def _request(self, method: str, path: str, body: dict[str, Any]) -> Any:
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "review-threads-check")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as e:
            raise ApiError(f"{method} {path}: HTTP {e.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise ApiError(f"{method} {path}: {type(e).__name__}") from None

    def graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        result = self._request("POST", "/graphql", {"query": query, "variables": variables})
        if not isinstance(result, dict) or result.get("errors") or not isinstance(result.get("data"), dict):
            raise ApiError("POST /graphql: the query failed")
        return result["data"]

    def post(self, path: str, body: dict[str, Any]) -> Any:
        return self._request("POST", path, body)


@dataclass
class Thread:
    author: str
    path: str
    line: int | None
    outdated: bool
    first_line: str
    url: str
    comments: int
    last_author: str


@dataclass
class Verdict:
    number: int
    sha: str
    fork: bool
    open_threads: list[Thread]

    @property
    def state(self) -> str:
        return "failure" if self.open_threads else "success"

    @property
    def description(self) -> str:
        n = len(self.open_threads)
        if n == 0:
            return "All review threads are resolved"
        return f"{n} unresolved review thread{'s' if n != 1 else ''}"


def _login(comment: dict[str, Any] | None) -> str:
    author = (comment or {}).get("author") or {}
    return author.get("login") or "ghost"


def first_line(body: str | None, limit: int = 120) -> str:
    for raw in (body or "").splitlines():
        line = raw.strip()
        if line:
            return line if len(line) <= limit else line[: limit - 3] + "..."
    return "(empty)"


def _all_comments(gql: Graphql, thread: dict[str, Any]) -> list[dict[str, Any]]:
    block = thread["comments"]
    comments = list(block["nodes"])
    page, info = 1, block["pageInfo"]
    while info["hasNextPage"]:
        page += 1
        if page > MAX_PAGES:
            raise ApiError("too many pages of review comments")
        data = gql(COMMENTS_QUERY, {"id": thread["id"], "after": info["endCursor"]})
        node = data.get("node") or {}
        if "comments" not in node:
            raise ApiError("a review thread vanished while it was read")
        comments += node["comments"]["nodes"]
        info = node["comments"]["pageInfo"]
    return comments


def read_pr(gql: Graphql, repo: str, number: int) -> Verdict:
    owner, name = repo.split("/", 1)
    after: str | None = None
    open_threads: list[Thread] = []
    sha, fork = "", False
    for _ in range(MAX_PAGES):
        data = gql(THREADS_QUERY, {"owner": owner, "name": name, "number": number, "after": after})
        pr = (data.get("repository") or {}).get("pullRequest")
        if not pr:
            raise ApiError(f"pull request #{number} not found")
        if not sha:
            sha, fork = pr["headRefOid"], bool(pr["isCrossRepository"])
        elif pr["headRefOid"] != sha:
            raise ApiError(f"#{number} got a new head commit while its threads were read")
        block = pr["reviewThreads"]
        for t in block["nodes"]:
            if t["isResolved"]:
                continue
            comments = _all_comments(gql, t)
            first = comments[0] if comments else None
            open_threads.append(
                Thread(
                    author=_login(first),
                    path=t.get("path") or "",
                    line=t.get("line") or t.get("originalLine"),
                    outdated=bool(t.get("isOutdated")),
                    first_line=first_line((first or {}).get("body")),
                    url=(first or {}).get("url") or "",
                    comments=len(comments),
                    last_author=_login(comments[-1] if comments else None),
                )
            )
        if not block["pageInfo"]["hasNextPage"]:
            return Verdict(number=number, sha=sha, fork=fork, open_threads=open_threads)
        after = block["pageInfo"]["endCursor"]
    raise ApiError("too many pages of review threads")


def open_prs(gql: Graphql, repo: str) -> list[int]:
    owner, name = repo.split("/", 1)
    after: str | None = None
    numbers: list[int] = []
    for _ in range(MAX_PAGES):
        data = gql(OPEN_PRS_QUERY, {"owner": owner, "name": name, "after": after})
        block = (data.get("repository") or {}).get("pullRequests")
        if block is None:
            raise ApiError(f"repository {repo} not found")
        numbers += [n["number"] for n in block["nodes"]]
        if not block["pageInfo"]["hasNextPage"]:
            return numbers
        after = block["pageInfo"]["endCursor"]
    raise ApiError("too many pages of open pull requests")


def write_status(post: Post, repo: str, sha: str, state: str, description: str, target_url: str) -> None:
    body = {"state": state, "context": CONTEXT, "description": description[:140]}
    if target_url:
        body["target_url"] = target_url
    post(f"/repos/{repo}/statuses/{sha}", body)


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def summary(verdicts: list[Verdict], notes: list[str]) -> str:
    out = ["## Review threads", ""]
    if not verdicts:
        out.append("No open pull requests.")
    for v in verdicts:
        out.append(f"### #{v.number} ({v.sha[:12]}): {v.description}")
        out.append("")
        if v.open_threads:
            out.append("| author | file:line | first line | link |")
            out.append("|---|---|---|---|")
            for t in v.open_threads:
                where = f"{t.path}:{t.line}" if t.line else (t.path or "(pull request)")
                if t.outdated:
                    where += " (outdated)"
                link = f"[open]({t.url})" if t.url else ""
                out.append(f"| {_cell(t.author)} | `{_cell(where)}` | {_cell(t.first_line)} | {link} |")
            out.append("")
    if notes:
        out += ["", *[f"- {n}" for n in notes]]
    return "\n".join(out) + "\n"


def run(
    gql: Graphql,
    post: Post,
    event_name: str,
    payload: dict[str, Any],
    repo: str,
    run_url: str,
    out: Callable[[str], None] = print,
) -> tuple[int, str]:
    """Evaluate and record. Returns (exit status, step summary)."""
    notes: list[str] = []
    verdicts: list[Verdict] = []
    failed = False
    pr = payload.get("pull_request") if event_name in PR_EVENTS else None
    if pr:
        numbers = [int(pr["number"])]
    else:
        try:
            numbers = open_prs(gql, repo)
        except ApiError as e:
            out(f"::error::Could not list the open pull requests: {e}")
            return 1, summary([], [f"Could not list the open pull requests: {e}"])
    for number in numbers:
        try:
            v = read_pr(gql, repo, number)
        except ApiError as e:
            failed = True
            out(f"::error::#{number}: could not read the review threads: {e}")
            notes.append(f"#{number}: could not read the review threads ({e}).")
            sha = (pr or {}).get("head", {}).get("sha") if pr else None
            fork = bool(pr) and (pr.get("head", {}).get("repo") or {}).get("full_name") != repo
            if sha and not fork:
                try:
                    write_status(post, repo, sha, "error", "Could not read the review threads", run_url)
                except ApiError:
                    pass
            continue
        verdicts.append(v)
        out(f"#{number} {v.sha[:12]}: {v.description}")
        for t in v.open_threads:
            out(f"  open: {t.author} {t.path}:{t.line} {t.url}")
        if pr and v.fork:
            out(f"::warning::#{number} is from a fork, so this run's token is read-only and cannot write the "
                f"'{CONTEXT}' status. The next scheduled run records it.")
            notes.append(f"#{number} is from a fork: the `{CONTEXT}` status is written by the next scheduled run.")
            continue
        try:
            # Read again after the write: a run that read a moment before another run wrote
            # can otherwise land last with the older verdict. A changed verdict is written
            # again, so the newest status follows the newest read.
            for _ in range(3):
                write_status(post, repo, v.sha, v.state, v.description, run_url)
                again = read_pr(gql, repo, number)
                if again.sha != v.sha or again.state == v.state:
                    break
                out(f"#{number}: the verdict changed while it was written; writing it again")
                verdicts[-1] = v = again
        except ApiError as e:
            if pr:
                failed = True
                out(f"::error::#{number}: could not write the '{CONTEXT}' status: {e}")
            else:
                out(f"::warning::#{number}: could not write the '{CONTEXT}' status: {e}")
            notes.append(f"#{number}: could not write the `{CONTEXT}` status ({e}).")
    return (1 if failed else 0), summary(verdicts, notes)


def main() -> int:
    token = os.environ.get("GH_TOKEN", "")
    repo = os.environ["GITHUB_REPOSITORY"]
    event_name = os.environ["GITHUB_EVENT_NAME"]
    with open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8") as f:
        payload = json.load(f)
    run_url = f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{repo}/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}"
    http = Http(token)
    status, text = run(http.graphql, http.post, event_name, payload, repo, run_url)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)
    return status


if __name__ == "__main__":
    sys.exit(main())
