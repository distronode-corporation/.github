"""Unit tests for review_threads.py, against a fake GraphQL and REST API."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import review_threads as rt  # noqa: E402

REPO = "octo/repo"
RUN = "https://github.com/octo/repo/actions/runs/1"


def comment(login: str | None, body: str, url: str = "https://github.com/octo/repo/pull/1#c") -> dict[str, Any]:
    return {"author": {"login": login} if login else None, "body": body, "url": url}


def thread(tid: str, resolved: bool, *, outdated: bool = False, comments: list[dict[str, Any]] | None = None,
           more: str | None = None, path: str = "a.py", line: int | None = 3, original: int | None = 3) -> dict[str, Any]:
    cs = comments if comments is not None else [comment("seer-by-sentry[bot]", "Bug here\nmore")]
    return {
        "id": tid,
        "isResolved": resolved,
        "isOutdated": outdated,
        "path": path,
        "line": line,
        "originalLine": original,
        "comments": {
            "totalCount": len(cs),
            "pageInfo": {"hasNextPage": more is not None, "endCursor": more},
            "nodes": cs,
        },
    }


class Fake:
    """Pull requests keyed by number; each a list of thread pages."""

    def __init__(self, prs: dict[int, list[list[dict[str, Any]]]], *, sha: str = "a" * 40, fork: bool = False,
                 extra_comments: dict[tuple[str, str], tuple[list[dict[str, Any]], str | None]] | None = None,
                 pr_pages: list[list[int]] | None = None) -> None:
        self.prs = prs
        self.sha = sha
        self.fork = fork
        self.extra = extra_comments or {}
        self.pr_pages = pr_pages
        self.posts: list[tuple[str, dict[str, Any]]] = []
        self.calls: list[str] = []
        self.fail_post: Exception | None = None
        self.fail_threads = False
        self.on_post = None

    def graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        if query is rt.OPEN_PRS_QUERY:
            self.calls.append("prs")
            pages = self.pr_pages or [sorted(self.prs)]
            i = int(variables["after"] or 0)
            return {"repository": {"pullRequests": {
                "pageInfo": {"hasNextPage": i + 1 < len(pages), "endCursor": str(i + 1)},
                "nodes": [{"number": n} for n in pages[i]],
            }}}
        if query is rt.COMMENTS_QUERY:
            self.calls.append(f"comments:{variables['id']}")
            nodes, nxt = self.extra[(variables["id"], variables["after"])]
            return {"node": {"comments": {"pageInfo": {"hasNextPage": nxt is not None, "endCursor": nxt}, "nodes": nodes}}}
        self.calls.append(f"threads:{variables['number']}:{variables['after']}")
        if self.fail_threads:
            raise rt.ApiError("POST /graphql: HTTP 502")
        pages = self.prs.get(variables["number"])
        if pages is None:
            return {"repository": {"pullRequest": None}}
        i = int(variables["after"] or 0)
        return {"repository": {"pullRequest": {
            "number": variables["number"],
            "headRefOid": self.sha,
            "isCrossRepository": self.fork,
            "reviewThreads": {
                "pageInfo": {"hasNextPage": i + 1 < len(pages), "endCursor": str(i + 1)},
                "nodes": pages[i],
            },
        }}}

    def get(self, path: str) -> Any:
        """The combined status: the newest status of each context, once."""
        self.calls.append("status")
        sha = path.split("/commits/")[1].split("/")[0]
        latest: dict[str, dict[str, Any]] = {}
        for p, body in self.posts:
            if p.endswith(sha):
                latest[body["context"]] = body
        return {"statuses": list(reversed(latest.values()))}

    def post(self, path: str, body: dict[str, Any]) -> Any:
        if self.fail_post:
            raise self.fail_post
        self.posts.append((path, dict(body)))
        if self.on_post:
            self.on_post()
        return {}


def pr_payload(number: int = 1, head_repo: str = REPO, sha: str = "a" * 40) -> dict[str, Any]:
    return {"pull_request": {"number": number, "head": {"sha": sha, "repo": {"full_name": head_repo}}}}


def go(fake: Fake, event: str = "pull_request", payload: dict[str, Any] | None = None) -> tuple[int, str, list[str]]:
    lines: list[str] = []
    status, text = rt.run(fake.graphql, fake.get, fake.post, event, payload if payload is not None else pr_payload(), REPO, RUN, lines.append)
    return status, text, lines


class Verdicts(unittest.TestCase):
    def test_unresolved_thread_is_failure_and_job_passes(self) -> None:
        fake = Fake({1: [[thread("t1", False)]]})
        status, text, _ = go(fake)
        self.assertEqual(status, 0)
        path, body = fake.posts[0]
        self.assertEqual(path, f"/repos/{REPO}/statuses/{'a' * 40}")
        self.assertEqual(body, {"state": "failure", "context": "review-threads",
                                "description": "1 unresolved review thread", "target_url": RUN})
        self.assertIn("seer-by-sentry[bot]", text)
        self.assertIn("`a.py:3`", text)
        self.assertIn("Bug here", text)
        self.assertNotIn("more", text)

    def test_all_resolved_is_success(self) -> None:
        fake = Fake({1: [[thread("t1", True), thread("t2", True, outdated=True)]]})
        status, text, _ = go(fake)
        self.assertEqual(status, 0)
        self.assertEqual(fake.posts[0][1]["state"], "success")
        self.assertEqual(fake.posts[0][1]["description"], "All review threads are resolved")
        self.assertIn("All review threads are resolved", text)

    def test_no_threads_is_success(self) -> None:
        fake = Fake({1: [[]]})
        go(fake)
        self.assertEqual(fake.posts[0][1]["state"], "success")

    def test_outdated_unresolved_counts_and_is_marked(self) -> None:
        fake = Fake({1: [[thread("t1", False, outdated=True, line=None, original=9)]]})
        _, text, _ = go(fake)
        self.assertEqual(fake.posts[0][1]["state"], "failure")
        self.assertIn("a.py:9 (outdated)", text)

    def test_human_and_ghost_authors_count(self) -> None:
        fake = Fake({1: [[thread("t1", False, comments=[comment("alice", "nit")]),
                          thread("t2", False, comments=[comment(None, "")], path="", line=None, original=None)]]})
        _, text, _ = go(fake)
        self.assertEqual(fake.posts[0][1]["description"], "2 unresolved review threads")
        self.assertIn("| alice |", text)
        self.assertIn("| ghost | `(pull request)` | (empty) |", text)

    def test_thread_without_comments(self) -> None:
        fake = Fake({1: [[thread("t1", False, comments=[])]]})
        _, text, _ = go(fake)
        self.assertIn("| ghost |", text)

    def test_thread_pages_are_all_read(self) -> None:
        fake = Fake({1: [[thread("t1", True)], [thread("t2", False)]]})
        go(fake)
        self.assertEqual(fake.calls[:2], ["threads:1:None", "threads:1:1"])
        self.assertEqual(fake.posts[0][1]["state"], "failure")

    def test_comment_pages_are_all_read(self) -> None:
        extra = {("t1", "c1"): ([comment("bob", "page two")], "c2"), ("t1", "c2"): ([comment("carol", "last")], None)}
        fake = Fake({1: [[thread("t1", False, more="c1")]]}, extra_comments=extra)
        status, _, lines = go(fake)
        self.assertEqual(status, 0)
        self.assertIn("comments:t1", fake.calls)
        v = rt.read_pr(fake.graphql, REPO, 1)
        self.assertEqual(v.open_threads[0].comments, 3)
        self.assertEqual(v.open_threads[0].last_author, "carol")
        self.assertEqual(v.open_threads[0].author, "seer-by-sentry[bot]")

    def test_pipes_and_long_lines_are_escaped_and_cut(self) -> None:
        body = "a|b " + "x" * 300
        fake = Fake({1: [[thread("t1", False, comments=[comment("u", "\n\n" + body)])]]})
        _, text, _ = go(fake)
        self.assertIn("a\\|b", text)
        self.assertIn("...", text)
        self.assertEqual(len(rt.first_line(body)), 120)


class Events(unittest.TestCase):
    def test_review_and_review_comment_events_use_their_pr(self) -> None:
        for event in ("pull_request_review", "pull_request_review_comment"):
            fake = Fake({7: [[thread("t1", False)]], 8: [[]]})
            go(fake, event, pr_payload(7))
            self.assertEqual(len(fake.posts), 1)
            self.assertNotIn("prs", fake.calls)

    def test_schedule_sweeps_every_open_pr(self) -> None:
        fake = Fake({1: [[thread("t1", False)]], 2: [[thread("t2", True)]]}, pr_pages=[[1], [2]])
        status, text, _ = go(fake, "schedule", {"schedule": "*/15 * * * *"})
        self.assertEqual(status, 0)
        self.assertEqual([b["state"] for _, b in fake.posts], ["failure", "success"])
        self.assertIn("#1", text)
        self.assertIn("#2", text)

    def test_dispatch_sweeps_and_writes_fork_prs_too(self) -> None:
        fake = Fake({3: [[]]}, fork=True)
        go(fake, "workflow_dispatch", {})
        self.assertEqual(fake.posts[0][1]["state"], "success")

    def test_no_open_prs(self) -> None:
        fake = Fake({})
        status, text, _ = go(fake, "schedule", {})
        self.assertEqual(status, 0)
        self.assertIn("No open pull requests.", text)
        self.assertEqual(fake.posts, [])

    def test_fork_event_run_reports_without_writing(self) -> None:
        fake = Fake({1: [[thread("t1", False)]]}, fork=True)
        status, text, lines = go(fake, payload=pr_payload(head_repo="someone/fork"))
        self.assertEqual(status, 0)
        self.assertEqual(fake.posts, [])
        self.assertTrue(any(l.startswith("::warning::") for l in lines))
        self.assertIn("next scheduled run", text)
        self.assertIn("1 unresolved review thread", text)


class Failures(unittest.TestCase):
    def test_read_failure_on_pr_event_writes_error_and_fails(self) -> None:
        fake = Fake({1: [[]]})
        fake.fail_threads = True
        status, text, _ = go(fake)
        self.assertEqual(status, 1)
        self.assertEqual(fake.posts[0][1]["state"], "error")
        self.assertIn("could not read", text)

    def test_read_failure_on_fork_event_writes_nothing(self) -> None:
        fake = Fake({1: [[]]})
        fake.fail_threads = True
        status, _, _ = go(fake, payload=pr_payload(head_repo="someone/fork"))
        self.assertEqual(status, 1)
        self.assertEqual(fake.posts, [])

    def test_error_status_write_failure_is_swallowed(self) -> None:
        fake = Fake({1: [[]]})
        fake.fail_threads = True
        fake.fail_post = rt.ApiError("HTTP 403")
        status, _, _ = go(fake)
        self.assertEqual(status, 1)

    def test_read_failure_in_sweep_fails_but_continues(self) -> None:
        fake = Fake({1: [[]], 2: [[]]})
        fake.prs.pop(1)
        fake.pr_pages = [[1, 2]]
        status, text, _ = go(fake, "schedule", {})
        self.assertEqual(status, 1)
        self.assertEqual(len(fake.posts), 1)
        self.assertIn("#1: could not read", text)

    def test_list_failure(self) -> None:
        fake = Fake({})
        def boom(q: str, v: dict[str, Any]) -> dict[str, Any]:
            raise rt.ApiError("HTTP 500")
        status, text = rt.run(boom, fake.get, fake.post, "schedule", {}, REPO, RUN, lambda s: None)
        self.assertEqual(status, 1)
        self.assertIn("Could not list", text)

    def test_missing_repository(self) -> None:
        with self.assertRaises(rt.ApiError):
            rt.open_prs(lambda q, v: {"repository": None}, REPO)

    def test_write_refused_on_pr_event_fails(self) -> None:
        fake = Fake({1: [[]]})
        fake.fail_post = rt.ApiError("HTTP 403")
        status, text, _ = go(fake)
        self.assertEqual(status, 1)
        self.assertIn("could not write", text)

    def test_write_refused_in_sweep_warns_only(self) -> None:
        fake = Fake({1: [[]]})
        fake.fail_post = rt.ApiError("HTTP 403")
        status, _, lines = go(fake, "schedule", {})
        self.assertEqual(status, 0)
        self.assertTrue(any(l.startswith("::warning::") for l in lines))

    def test_head_moves_between_pages(self) -> None:
        fake = Fake({1: [[thread("t1", True)], [thread("t2", True)]]})
        orig = fake.graphql
        def moving(q: str, v: dict[str, Any]) -> dict[str, Any]:
            data = orig(q, v)
            if v.get("after"):
                data["repository"]["pullRequest"]["headRefOid"] = "b" * 40
            return data
        with self.assertRaises(rt.ApiError):
            rt.read_pr(moving, REPO, 1)

    def test_vanished_thread(self) -> None:
        fake = Fake({1: [[thread("t1", False, more="c1")]]})
        def gql(q: str, v: dict[str, Any]) -> dict[str, Any]:
            if q is rt.COMMENTS_QUERY:
                return {"node": None}
            return fake.graphql(q, v)
        with self.assertRaises(rt.ApiError):
            rt.read_pr(gql, REPO, 1)

    def test_page_caps(self) -> None:
        endless = Fake({1: [[thread("t1", True)]] * (rt.MAX_PAGES + 1)})
        with self.assertRaises(rt.ApiError):
            rt.read_pr(endless.graphql, REPO, 1)
        many = Fake({}, pr_pages=[[1]] * (rt.MAX_PAGES + 1))
        with self.assertRaises(rt.ApiError):
            rt.open_prs(many.graphql, REPO)
        extra = {("t1", str(i)): ([comment("u", "x")], str(i + 1)) for i in range(rt.MAX_PAGES + 1)}
        deep = Fake({1: [[thread("t1", False, more="0")]]}, extra_comments=extra)
        with self.assertRaises(rt.ApiError):
            rt.read_pr(deep.graphql, REPO, 1)


class Race(unittest.TestCase):
    def test_verdict_that_changes_during_the_write_is_written_again(self) -> None:
        fake = Fake({1: [[thread("t1", False)]]})
        def resolve() -> None:
            fake.prs[1] = [[thread("t1", True)]]
            fake.on_post = None
        fake.on_post = resolve
        status, text, lines = go(fake)
        self.assertEqual(status, 0)
        self.assertEqual([b["state"] for _, b in fake.posts], ["failure", "success"])
        self.assertIn("All review threads are resolved", text)
        self.assertTrue(any("writing it again" in l for l in lines))

    def test_new_head_during_write_stops(self) -> None:
        fake = Fake({1: [[thread("t1", False)]]})
        def move() -> None:
            fake.sha = "b" * 40
            fake.prs[1] = [[]]
        fake.on_post = move
        go(fake)
        self.assertEqual(len(fake.posts), 1)


class Flapping(unittest.TestCase):
    def test_a_verdict_that_keeps_changing_is_written_three_times(self) -> None:
        fake = Fake({1: [[thread("t1", False)]]})
        def flip() -> None:
            fake.prs[1] = [[thread("t1", not fake.prs[1][0][0]["isResolved"])]]
        fake.on_post = flip
        status, _, _ = go(fake)
        self.assertEqual(status, 0)
        self.assertEqual(len(fake.posts), 3)


class FakeResponse:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *a: object) -> None:
        return None

    def read(self) -> bytes:
        return self.data


class HttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.orig = rt.urllib.request.urlopen
        self.seen: list[Any] = []

    def tearDown(self) -> None:
        rt.urllib.request.urlopen = self.orig

    def answer(self, result: Any) -> None:
        def fake(req: Any, timeout: float) -> Any:
            self.seen.append(req)
            if isinstance(result, BaseException):
                raise result
            return FakeResponse(result)
        rt.urllib.request.urlopen = fake

    def test_graphql_ok_and_headers(self) -> None:
        self.answer(b'{"data": {"x": 1}}')
        self.assertEqual(rt.Http("tok").graphql("q", {}), {"x": 1})
        req = self.seen[0]
        self.assertEqual(req.full_url, "https://api.github.com/graphql")
        self.assertEqual(req.get_header("Authorization"), "Bearer tok")

    def test_graphql_errors(self) -> None:
        for body in (b'{"errors": [{}], "data": null}', b'[]', b'{"data": null}'):
            self.answer(body)
            with self.assertRaises(rt.ApiError):
                rt.Http("t").graphql("q", {})

    def test_post_empty_body(self) -> None:
        self.answer(b"")
        self.assertIsNone(rt.Http("t").post("/x", {}))

    def test_get_sends_no_body(self) -> None:
        self.answer(b'{"statuses": []}')
        self.assertEqual(rt.Http("t").get("/x"), {"statuses": []})
        self.assertEqual(self.seen[0].get_method(), "GET")
        self.assertIsNone(self.seen[0].data)

    def test_http_and_network_errors(self) -> None:
        for err in (rt.urllib.error.HTTPError("u", 403, "no", {}, None), rt.urllib.error.URLError("down"), TimeoutError()):
            self.answer(err)
            with self.assertRaises(rt.ApiError) as cm:
                rt.Http("t").post("/x", {})
            self.assertNotIn("t ", str(cm.exception))


class Main(unittest.TestCase):
    def test_main_writes_summary(self) -> None:
        import json
        import os
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = tmp.name
        event = os.path.join(d, "event.json")
        summ = os.path.join(d, "summary.md")
        with open(event, "w") as f:
            json.dump({}, f)
        env = {"GH_TOKEN": "t", "GITHUB_REPOSITORY": REPO, "GITHUB_EVENT_NAME": "schedule",
               "GITHUB_EVENT_PATH": event, "GITHUB_STEP_SUMMARY": summ, "GITHUB_RUN_ID": "9"}
        old = dict(os.environ)
        fake = Fake({})
        orig = rt.Http
        class StubHttp:
            def __init__(self, token: str) -> None:
                self.graphql = fake.graphql
                self.get = fake.get
                self.post = fake.post
        try:
            os.environ.update(env)
            rt.Http = StubHttp  # type: ignore[misc,assignment]
            self.assertEqual(rt.main(), 0)
            os.environ.pop("GITHUB_STEP_SUMMARY")
            self.assertEqual(rt.main(), 0)
        finally:
            rt.Http = orig  # type: ignore[misc]
            os.environ.clear()
            os.environ.update(old)
        with open(summ) as f:
            self.assertIn("No open pull requests.", f.read())


class Description(unittest.TestCase):
    def test_description_is_capped(self) -> None:
        fake = Fake({})
        rt.write_status(fake.post, REPO, "a" * 40, "success", "x" * 200, "")
        self.assertEqual(len(fake.posts[0][1]["description"]), 140)
        self.assertNotIn("target_url", fake.posts[0][1])
        self.assertFalse(rt.record(fake.get, fake.post, REPO, "a" * 40, "success", "x" * 200, ""))


class ReadBeforeWrite(unittest.TestCase):
    def test_an_unchanged_verdict_is_not_written_again(self) -> None:
        fake = Fake({1: [[thread("t1", False)]]})
        go(fake, "schedule", {})
        go(fake, "schedule", {})
        go(fake)
        self.assertEqual(len(fake.posts), 1)
        fake.prs[1] = [[thread("t1", True)]]
        go(fake, "schedule", {})
        self.assertEqual([b["state"] for _, b in fake.posts], ["failure", "success"])

    def test_other_contexts_and_pages(self) -> None:
        other = [{"context": f"c{i}", "state": "success", "description": ""} for i in range(100)]
        pages = {1: {"statuses": other}, 2: {"statuses": [{"context": "review-threads", "state": "failure", "description": "d"}]}}
        get = lambda path: pages[int(path.rsplit("page=", 1)[1])]
        self.assertEqual(rt.latest_status(get, REPO, "a" * 40), ("failure", "d"))
        self.assertIsNone(rt.latest_status(lambda path: {"statuses": other[:3]}, REPO, "a" * 40))
        self.assertIsNone(rt.latest_status(lambda path: None, REPO, "a" * 40))
        self.assertEqual(rt.latest_status(lambda path: {"statuses": [{"context": "review-threads"}]}, REPO, "a"), ("", ""))
        with self.assertRaises(rt.ApiError):
            rt.latest_status(lambda path: {"statuses": other}, REPO, "a" * 40)


if __name__ == "__main__":
    unittest.main()
