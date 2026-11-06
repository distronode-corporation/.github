"""Tests for sweep.py and for event.RestApi, with fake APIs and a patched urlopen: what
is read, where the report goes, the confidential-issue guard, and that neither the
public log nor the report ever holds the matched text."""

from __future__ import annotations

import base64
import contextlib
import datetime as dt
import re
import http.client
import io
import json
import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import event  # noqa: E402
import sweep  # noqa: E402

NOW = dt.datetime(2026, 11, 9, 7, 0, tzinfo=dt.timezone.utc)
RECENT = "2026-11-08T10:00:00Z"
OLD = "2026-10-01T10:00:00Z"
BAD_IP = "34.120.7.9"
BAD_REF = "GitLab #7, note 1234509876"
HTML = "https://github.com/octo/app"
PIN_SHA = "0123456789abcdef0123456789abcdef01234567"


def user(login: str = "author", kind: str = "User") -> dict[str, Any]:
    return {"login": login, "type": kind}


class FakeGitHub:
    def __init__(self) -> None:
        self.paths: list[str] = []
        self.data: dict[str, list[Any]] = {
            "/orgs/octo/repos?type=public": [
                {"full_name": "octo/app", "has_discussions": True},
                {"full_name": "octo/old", "archived": True},
            ],
            "/repos/octo/app/issues?state=all&since=2026-11-01T07:00:00Z": [
                {"number": 7, "title": "Fix", "body": f"from {BAD_IP}", "user": user(), "html_url": f"{HTML}/pull/7", "pull_request": {}},
                {"number": 8, "title": "Bump", "body": f"from {BAD_IP}", "user": user("dependabot[bot]", "Bot"), "html_url": f"{HTML}/pull/8", "pull_request": {}},
                {"number": 9, "title": "Bug", "body": "clean", "user": user(), "html_url": f"{HTML}/issues/9"},
            ],
            "/repos/octo/app/pulls/7/reviews": [
                {"body": f"per {BAD_REF}", "submitted_at": RECENT, "user": user(), "html_url": f"{HTML}/pull/7#pullrequestreview-1"},
                {"body": f"per {BAD_REF}", "submitted_at": OLD, "user": user(), "html_url": f"{HTML}/pull/7#pullrequestreview-2"},
            ],
            "/repos/octo/app/pulls/8/reviews": [],
            "/repos/octo/app/issues/comments?since=2026-11-01T07:00:00Z": [
                {"body": "clean", "user": user(), "html_url": f"{HTML}/issues/9#issuecomment-1"},
                {"body": event.MARKER + " `ip-address`", "user": user("github-actions[bot]", "Bot"), "html_url": f"{HTML}/pull/7#issuecomment-2"},
            ],
            "/repos/octo/app/pulls/comments?since=2026-11-01T07:00:00Z": [],
            "/repos/octo/app/releases": [
                {"name": "v1", "body": f"Notes ({BAD_REF})", "published_at": RECENT, "author": user("github-actions[bot]", "Bot"), "html_url": f"{HTML}/releases/tag/v1"},
                {"name": "v0", "body": f"Notes ({BAD_REF})", "published_at": OLD, "author": user(), "html_url": f"{HTML}/releases/tag/v0"},
            ],
        }

        self.commit_date = RECENT
        self.discussions = [
            {"title": "Idea", "body": "clean", "url": f"{HTML}/discussions/4", "updatedAt": RECENT, "authorAssociation": "MEMBER", "author": {"login": "pat", "__typename": "User"},
             "comments": {"nodes": [{"body": "ok", "url": f"{HTML}/discussions/4#discussioncomment-1", "isMinimized": False, "authorAssociation": "MEMBER", "author": {"login": "pat", "__typename": "User"},
                                     "replies": {"nodes": [{"body": f"from {BAD_IP}", "url": f"{HTML}/discussions/4#discussioncomment-2", "isMinimized": False, "authorAssociation": "MEMBER", "author": {"login": "pat", "__typename": "User"}}]}}]}},
            {"title": "Old", "body": f"from {BAD_IP}", "url": f"{HTML}/discussions/3", "updatedAt": OLD, "authorAssociation": "MEMBER", "author": {"login": "pat", "__typename": "User"}, "comments": {"nodes": []}},
        ]
        # Issue 9 is clean now, but an earlier revision of it is not.
        self.edits = {
            9: {"body": "clean", "userContentEdits": {"totalCount": 2, "nodes": [{"diff": "clean"}, {"diff": f"from {BAD_IP}"}]}},
            # Dependabot's description: its revisions are skipped like the description.
            8: {"body": "clean", "userContentEdits": {"totalCount": 2, "nodes": [{"diff": "clean"}, {"diff": f"from {BAD_IP}"}]}},
        }
        self.graphql_numbers: list[int] = []

        self.pin_status = "behind"
        self.callers: dict[str, str | None] = {}  # repo -> caller text (None: no caller)
        self.editors: dict[str, dict[str, Any]] = {}  # node id -> editor

    def get(self, path: str) -> Any:
        if "/collaborators/" in path:
            return {"permission": "read"}
        if path == "/repos/octo/.github/commits?per_page=1":
            return [{"commit": {"committer": {"date": self.commit_date}}}]
        if path == "/repos/octo/.github":
            return {"default_branch": "main"}
        if path.startswith("/repos/octo/.github/compare/main..."):
            return {"status": self.pin_status}
        m = re.fullmatch(r"/repos/(octo/[\w.\-]+)/contents/\.github/workflows/[\w.\-]+\.yml", path)
        assert m, path
        text = self.callers.get(m.group(1), f"uses: octo/.github/.github/workflows/public-hygiene.yml@{PIN_SHA} # x")
        if text is None:
            raise event.ApiError("GET x: HTTP 404", 404)
        return {"content": base64.b64encode(text.encode()).decode()}

    def get_all(self, path: str, max_pages: int = event.MAX_PAGES) -> list[Any]:
        self.paths.append(path)
        return self.data[path]

    def graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        if "nodes(ids" in query:
            return {"nodes": [{"id": i, "editor": self.editors[i]} for i in variables["ids"] if i in self.editors]}
        if "issueOrPullRequest" in query:
            self.graphql_numbers.append(variables["number"])
            return {"repository": {"issueOrPullRequest": self.edits.get(variables["number"], {})}}
        return {"repository": {"discussions": {"pageInfo": {"hasNextPage": getattr(self, "discussions_more", False)}, "nodes": self.discussions}}}

    def post(self, path: str, body: dict[str, Any]) -> Any:
        raise AssertionError("the sweep never writes to GitHub")

    patch = post


class FakeGitLab:
    def __init__(self, confidential: Any = True) -> None:
        self.confidential = confidential
        self.notes: list[tuple[str, dict[str, Any]]] = []

    def get(self, path: str) -> Any:
        assert path == "/projects/123/issues/4", path
        return {"iid": 4, "confidential": self.confidential}

    def get_all(self, path: str) -> list[Any]:
        raise AssertionError(path)

    def post(self, path: str, body: dict[str, Any]) -> Any:
        self.notes.append((path, body))
        return {}

    patch = post


ENV = {"GITHUB_REPOSITORY_OWNER": "octo", "GITHUB_REPOSITORY": "octo/.github", "GITLAB_TOKEN": "t", "GITLAB_PROJECT": "123", "GITLAB_ISSUE": "4"}


def run(env: dict[str, str], gh: Any, gl: Any) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        status = sweep.run(env, gh, gl, now=NOW)
    return status, out.getvalue()


class Sweep(unittest.TestCase):
    def test_report_goes_to_the_confidential_issue_only(self) -> None:
        gh, gl = FakeGitHub(), FakeGitLab()
        status, log = run(ENV, gh, gl)
        self.assertEqual(status, 0)
        self.assertEqual(len(gl.notes), 1)
        path, note = gl.notes[0]
        self.assertEqual(path, "/projects/123/issues/4/notes")
        body = note["body"]
        self.assertIn(f"{HTML}/pull/7", body)  # the description
        self.assertIn("pullrequestreview-1", body)
        self.assertIn("pullrequestreview-2", body)  # reviews are read in full: an edit keeps the old timestamp
        self.assertIn("releases/tag/v1", body)  # published by the bot, still checked
        self.assertIn("releases/tag/v0", body)  # releases are read in full too
        self.assertIn(f"1 earlier revision(s) of a issue: {HTML}/issues/9", body)
        self.assertNotIn("revision(s) of a pull request: " + f"{HTML}/pull/8", body)
        self.assertIn(8, gh.graphql_numbers)  # read, to see who last edited it
        self.assertIn("discussioncomment-2", body)  # a reply in a recent discussion
        self.assertNotIn("discussions/3", body)  # an old discussion
        self.assertNotIn("/pull/8", body)  # Dependabot
        self.assertNotIn("issuecomment-2", body)  # the check's own comment
        self.assertNotIn("octo/old", " ".join(gh.paths))
        for secret in (BAD_IP, BAD_REF, "1234509876"):
            self.assertNotIn(secret, body)
            self.assertNotIn(secret, log)
        self.assertNotIn("github.com", log)  # the public log has counts only
        self.assertIn("7 with findings in 1 repositories", log)
        self.assertNotIn("turns its schedule off", body)
        self.assertIn("internal-name rule did not run", body)  # no key in the tests

    def test_a_quiet_repository_is_warned_about(self) -> None:
        gh, gl = FakeGitHub(), FakeGitLab()
        gh.commit_date = "2026-09-01T00:00:00Z"
        status, log = run(ENV, gh, gl)
        self.assertEqual(status, 0)
        self.assertIn("turns its schedule off at 60", gl.notes[0][1]["body"])
        self.assertIn("No commit for 69 days", log)

    def test_a_caller_pin_off_main_is_reported(self) -> None:
        # F1: the sweep runs from main's code, so an impostor pin cannot vouch for itself.
        gh, gl = FakeGitHub(), FakeGitLab()
        gh.pin_status = "diverged"
        status, _ = run(ENV, gh, gl)
        self.assertEqual(status, 1)
        self.assertIn("octo/app: caller pin", gl.notes[0][1]["body"])
        gh, gl = FakeGitHub(), FakeGitLab()
        gh.callers["octo/app"] = None
        run(ENV, gh, gl)
        self.assertIn("octo/app: caller pin (no caller workflow)", gl.notes[0][1]["body"])
        gh, gl = FakeGitHub(), FakeGitLab()
        gh.callers["octo/app"] = "uses: octo/.github/.github/workflows/public-hygiene.yml@main"
        run(ENV, gh, gl)
        self.assertIn("octo/app: caller pin (the caller pins no commit)", gl.notes[0][1]["body"])

    def test_more_revisions_than_read_is_unreadable(self) -> None:
        # F5
        gh = FakeGitHub()
        gh.edits[9] = {"body": "clean", "userContentEdits": {"totalCount": 31, "nodes": [{"diff": "clean"}] * 30}}
        gl = FakeGitLab()
        status, _ = run(ENV, gh, gl)
        self.assertEqual(status, 1)
        self.assertIn("octo/app: revisions of #9 (more than 30)", gl.notes[0][1]["body"])

    def test_more_discussions_comments_or_replies_than_read_is_unreadable(self) -> None:
        # F5
        gh = FakeGitHub()
        gh.discussions_more = True
        gh.discussions[0]["number"] = 4
        gh.discussions[0]["comments"]["pageInfo"] = {"hasNextPage": True}
        gh.discussions[0]["comments"]["nodes"][0]["replies"]["totalCount"] = 60
        gl = FakeGitLab()
        status, _ = run(ENV, gh, gl)
        self.assertEqual(status, 1)
        body = gl.notes[0][1]["body"]
        self.assertIn("octo/app: comments of discussion #4", body)
        self.assertIn("octo/app: replies in discussion #4", body)

    def test_an_outside_authors_revisions_are_checked_for_credentials_only(self) -> None:
        # Earlier revisions follow the description's author rules (an outside author:
        # credentials only).
        gh = FakeGitHub()
        outsider = {"number": 10, "title": "Bug", "body": "clean", "user": user("reporter"), "author_association": "NONE", "html_url": f"{HTML}/issues/10"}
        gh.data["/repos/octo/app/issues?state=all&since=2026-11-01T07:00:00Z"].append(outsider)
        token = "gh" + "p_" + "".join("abcdefghij0123456789"[(i * 7) % 20] for i in range(36))
        gh.edits[10] = {"body": "clean", "userContentEdits": {"totalCount": 2, "nodes": [{"diff": "clean"}, {"diff": f"crash from {BAD_IP}"}]}}
        gl = FakeGitLab()
        run(ENV, gh, gl)
        self.assertNotIn(f"{HTML}/issues/10", gl.notes[0][1]["body"])  # an address: theirs to share
        gh.edits[10]["userContentEdits"]["nodes"].append({"diff": f"token {token}"})
        gh.edits[10]["userContentEdits"]["totalCount"] = 3
        gl = FakeGitLab()
        run(ENV, gh, gl)
        self.assertIn(f"1 earlier revision(s) of a issue: {HTML}/issues/10 | `token`", gl.notes[0][1]["body"])
        self.assertNotIn(token, gl.notes[0][1]["body"])

    def test_a_person_edit_to_a_bot_comment_is_checked(self) -> None:
        # F3 in the sweep.
        gh = FakeGitHub()
        bot_comment = {"node_id": "IC_77", "body": f"from {BAD_IP}", "user": user("dependabot[bot]", "Bot"), "html_url": f"{HTML}/pull/8#issuecomment-77"}
        gh.data["/repos/octo/app/issues/comments?since=2026-11-01T07:00:00Z"].append(bot_comment)
        gl = FakeGitLab()
        run(ENV, gh, gl)
        self.assertNotIn("issuecomment-77", gl.notes[0][1]["body"])
        gh.editors["IC_77"] = {"login": "pat", "__typename": "User"}
        gl = FakeGitLab()
        run(ENV, gh, gl)
        self.assertIn("issuecomment-77", gl.notes[0][1]["body"])

    def test_a_text_too_long_to_check_is_unreadable(self) -> None:
        # F4 in the sweep.
        gh = FakeGitHub()
        gh.data["/repos/octo/app/releases"].append({"name": "v2", "body": "x " * 80_000, "author": user(), "html_url": f"{HTML}/releases/tag/v2"})
        gl = FakeGitLab()
        status, _ = run(ENV, gh, gl)
        self.assertEqual(status, 1)
        self.assertIn("a release too long to check in full", gl.notes[0][1]["body"])

    def test_bad_sweep_days(self) -> None:
        for value in ("x", "0", "999", "-3"):
            status, log = run(dict(ENV, SWEEP_DAYS=value), FakeGitHub(), FakeGitLab())
            self.assertEqual(status, 2, value)
            self.assertIn("SWEEP_DAYS", log)

    def test_main_hides_unexpected_errors(self) -> None:
        with mock.patch.object(sweep, "run", side_effect=KeyError("secret " + BAD_IP)):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(sweep.main(), 2)
        self.assertIn("KeyError", out.getvalue())
        self.assertNotIn(BAD_IP, out.getvalue())

    def test_refuses_an_issue_that_is_not_confidential(self) -> None:
        for value in (False, None, "true"):
            gl = FakeGitLab(confidential=value)
            with self.assertRaises(event.ApiError):
                run(ENV, FakeGitHub(), gl)
            self.assertEqual(gl.notes, [])

    def test_not_set_up_reads_nothing(self) -> None:
        gh = FakeGitHub()
        for missing in ("GITLAB_TOKEN", "GITLAB_PROJECT", "GITLAB_ISSUE"):
            env = {k: v for k, v in ENV.items() if k != missing}
            status, log = run(env, gh, FakeGitLab())
            self.assertEqual(status, 2)
            self.assertIn("not set up", log)
        self.assertEqual(gh.paths, [])
        status, _ = run(dict(ENV, GITHUB_REPOSITORY_OWNER=""), gh, FakeGitLab())
        self.assertEqual(status, 2)

    def test_one_unreadable_part_does_not_stop_the_sweep(self) -> None:
        gh = FakeGitHub()
        gh.data["/orgs/octo/repos?type=public"].insert(0, {"full_name": "octo/noissues"})
        original = gh.get_all

        def get_all(path: str, max_pages: int = event.MAX_PAGES) -> list[Any]:
            if path.startswith(("/repos/octo/noissues/issues?", "/repos/octo/noissues/pulls?")):
                raise event.ApiError("GET /repos/octo/noissues/x: HTTP 503")
            if path.startswith("/repos/octo/noissues/"):
                return []
            return original(path)

        gh.get_all = get_all  # type: ignore[method-assign]
        gl = FakeGitLab()
        status, log = run(ENV, gh, gl)
        self.assertEqual(status, 1)
        body = gl.notes[0][1]["body"]
        self.assertIn("octo/noissues: pull requests", body)
        self.assertIn(f"{HTML}/pull/7", body)  # the next repository was still read
        self.assertIn("2 part(s) could not be read", log)
        self.assertIn("octo/noissues: issues\n", body + "\n")
        self.assertNotIn("noissues", log)

    issues_status: int | None = 410

    def test_a_transient_issues_failure_is_reported_not_hidden(self) -> None:
        self.issues_status = 502
        try:
            self.test_issues_turned_off_falls_back_to_the_pull_request_listing(expect_status=1)
        finally:
            self.issues_status = 410

    def test_issues_turned_off_falls_back_to_the_pull_request_listing(self, expect_status: int = 0) -> None:
        gh = FakeGitHub()
        pulls = [
            {"number": 3, "title": "New", "body": f"from {BAD_IP}", "updated_at": RECENT, "user": user(), "html_url": "https://github.com/octo/prs/pull/3"},
            {"number": 2, "title": "Old", "body": f"from {BAD_IP}", "updated_at": OLD, "user": user(), "html_url": "https://github.com/octo/prs/pull/2"},
        ]

        def get_all(path: str, max_pages: int = event.MAX_PAGES) -> list[Any]:
            if path.startswith("/repos/octo/prs/issues?"):
                raise event.ApiError("GET /repos/octo/prs/issues: HTTP 410", self.issues_status)
            if path == "/repos/octo/prs/pulls?state=all&sort=updated&direction=desc":
                return pulls
            if path == "/orgs/octo/repos?type=public":
                return [{"full_name": "octo/prs"}]
            return []

        gh.get_all = get_all  # type: ignore[method-assign]
        gl = FakeGitLab()
        status, _ = run(ENV, gh, gl)
        self.assertEqual(status, expect_status)
        body = gl.notes[0][1]["body"]
        self.assertIn("pull request: https://github.com/octo/prs/pull/3", body)
        self.assertNotIn("/pull/2", body)
        self.assertEqual("octo/prs: issues" in body, expect_status == 1)

    def test_ids_must_be_numeric(self) -> None:
        with self.assertRaises(event.ApiError):
            sweep.post_report(FakeGitLab(), "group/project", "4", "x")

    def test_nothing_found_posts_nothing(self) -> None:
        gh = FakeGitHub()
        for key, items in gh.data.items():
            for item in items:
                if "body" in item:
                    item["body"] = "clean"
        gh.discussions = []
        gh.edits = {}
        gl = FakeGitLab()
        status, log = run(ENV, gh, gl)
        self.assertEqual(status, 0)
        self.assertEqual(gl.notes, [])
        self.assertIn("0 with findings", log)

    def test_main_reports_api_errors_without_text(self) -> None:
        with mock.patch.object(sweep, "run", side_effect=event.ApiError("GET /x: HTTP 403")):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(sweep.main(), 2)
        self.assertIn("HTTP 403", out.getvalue())


class FakeResponse:
    def __init__(self, body: Any, link: str = "") -> None:
        self.raw = json.dumps(body).encode()
        self.headers = {"Link": link}

    def read(self) -> bytes:
        return self.raw

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *a: Any) -> None:
        return None


class RestApiTests(unittest.TestCase):
    def test_pagination_follows_next_on_the_same_host_only(self) -> None:
        api = event.RestApi("https://api.example.org", "tok")
        pages = [
            FakeResponse([1, 2], '<https://api.example.org/x?page=2>; rel="next"'),
            FakeResponse([3], '<https://evil.example.net/x?page=3>; rel="next"'),
        ]
        seen: list[Any] = []

        def fake_urlopen(req: Any, timeout: int) -> FakeResponse:
            seen.append(req)
            return pages[len(seen) - 1]

        with mock.patch.object(event.OPENER, "open", fake_urlopen):
            with self.assertRaises(event.ApiError):  # never taken as a complete list
                api.get_all("/x")
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0].get_header("Authorization"), "Bearer tok")
        self.assertTrue(seen[0].full_url.endswith("/x?per_page=100"))

    def test_too_many_pages(self) -> None:
        api = event.RestApi("https://api.example.org", "tok")
        loop = lambda req, timeout: FakeResponse([1], '<https://api.example.org/x?p=n>; rel="next"')  # noqa: E731
        with mock.patch.object(event.OPENER, "open", loop), self.assertRaises(event.ApiError):
            api.get_all("/x?a=1")

    def test_errors_carry_status_not_body(self) -> None:
        api = event.RestApi("https://api.example.org", "tok")
        err = urllib.error.HTTPError("https://api.example.org/x", 403, "Forbidden " + BAD_IP, {}, io.BytesIO(BAD_IP.encode()))  # type: ignore[arg-type]
        with mock.patch.object(event.OPENER, "open", side_effect=err):
            with self.assertRaises(event.ApiError) as ctx:
                api.post("/x", {"body": BAD_IP})
        self.assertEqual(str(ctx.exception), "POST /x: HTTP 403")
        self.assertEqual(ctx.exception.status, 403)
        with mock.patch.object(event.OPENER, "open", side_effect=urllib.error.URLError("down")):
            with self.assertRaises(event.ApiError) as ctx:
                api.get("/y?q=1")
        self.assertEqual(str(ctx.exception), "GET /y: URLError")

    def test_low_level_failures_become_api_errors(self) -> None:
        api = event.RestApi("https://api.example.org", "tok")
        for exc in (ConnectionResetError(), TimeoutError(), http.client.IncompleteRead(b"x")):
            with mock.patch.object(event.OPENER, "open", side_effect=exc):
                with self.assertRaises(event.ApiError) as ctx:
                    api.get("/z")
            self.assertIsNone(ctx.exception.status)
        bad = FakeResponse(None)
        bad.raw = b"<html>" + BAD_IP.encode()
        with mock.patch.object(event.OPENER, "open", lambda req, timeout: bad):
            with self.assertRaises(event.ApiError) as ctx:
                api.get("/z")
        self.assertEqual(str(ctx.exception), "GET /z: the response is not JSON")

    def test_redirects_are_refused(self) -> None:
        handler = next(h for h in event.OPENER.handlers if isinstance(h, urllib.request.HTTPRedirectHandler))
        self.assertIsInstance(handler, event._NoRedirect)
        req = urllib.request.Request("https://api.example.org/x", method="POST", data=b"{}")
        with self.assertRaises(event.ApiError) as ctx:
            handler.redirect_request(req, io.BytesIO(b""), 301, "Moved", {}, "http://evil.example.net/y")
        self.assertEqual(ctx.exception.status, 301)

    def test_the_token_never_rides_a_redirect(self) -> None:
        api = event.RestApi("https://api.example.org", "tok")
        seen: list[Any] = []

        def fake_open(req: Any, timeout: int) -> FakeResponse:
            seen.append(req)
            return FakeResponse({})

        with mock.patch.object(event.OPENER, "open", fake_open):
            api.get("/x")
        self.assertIn("Authorization", seen[0].unredirected_hdrs)
        self.assertNotIn("Authorization", seen[0].headers)

    def test_graphql_errors_are_api_errors(self) -> None:
        api = event.RestApi("https://api.example.org", "tok")
        for answer in ({"errors": [{"message": "x " + BAD_IP}]}, {"data": None}, ["x"]):
            with mock.patch.object(event.OPENER, "open", lambda req, timeout, a=answer: FakeResponse(a)):
                with self.assertRaises(event.ApiError) as ctx:
                    api.graphql("query { x }", {})
            self.assertNotIn(BAD_IP, str(ctx.exception))
        with mock.patch.object(event.OPENER, "open", lambda req, timeout: FakeResponse({"data": {"ok": 1}})):
            self.assertEqual(api.graphql("query { x }", {}), {"ok": 1})

    def test_the_time_budget_stops_requests(self) -> None:
        api = event.RestApi("https://api.example.org", "tok")
        event._Deadline.start(-1)
        try:
            with self.assertRaises(event.ApiError):
                api.get("/x")
        finally:
            event._Deadline.end = None

    def test_gitlab_auth_header_and_json_bodies(self) -> None:
        api = event.RestApi("https://gitlab.example.org/api/v4", "glt", gitlab=True)
        seen: list[Any] = []

        def fake_urlopen(req: Any, timeout: int) -> FakeResponse:
            seen.append(req)
            return FakeResponse({"ok": True})

        with mock.patch.object(event.OPENER, "open", fake_urlopen):
            self.assertEqual(api.patch("/n", {"body": "x"}), {"ok": True})
        self.assertEqual(seen[0].get_header("Private-token"), "glt")
        self.assertIsNone(seen[0].get_header("Authorization"))
        self.assertEqual(json.loads(seen[0].data), {"body": "x"})
        self.assertEqual(seen[0].get_method(), "PATCH")


if __name__ == "__main__":
    unittest.main()
