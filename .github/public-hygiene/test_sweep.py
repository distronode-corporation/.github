"""Tests for sweep.py and for event.RestApi, with fake APIs and a patched urlopen: what
is read, where the report goes, the confidential-issue guard, and that neither the
public log nor the report ever holds the matched text."""

from __future__ import annotations

import contextlib
import datetime as dt
import http.client
import io
import json
import sys
import unittest
import urllib.error
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
BAD_REF = "GitLab #2, note 4021983495"
HTML = "https://github.com/octo/app"


def user(login: str = "author", kind: str = "User") -> dict[str, Any]:
    return {"login": login, "type": kind}


class FakeGitHub:
    def __init__(self) -> None:
        self.paths: list[str] = []
        self.data: dict[str, list[Any]] = {
            "/orgs/octo/repos?type=public": [
                {"full_name": "octo/app"},
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

    def get(self, path: str) -> Any:
        raise AssertionError(path)

    def get_all(self, path: str) -> list[Any]:
        self.paths.append(path)
        return self.data[path]

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


ENV = {"GITHUB_REPOSITORY_OWNER": "octo", "GITLAB_TOKEN": "t", "GITLAB_PROJECT": "123", "GITLAB_ISSUE": "4"}


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
        self.assertIn("pullrequestreview-1", body)  # the recent review
        self.assertNotIn("pullrequestreview-2", body)  # the old one
        self.assertIn("releases/tag/v1", body)  # published by the bot, still checked
        self.assertNotIn("releases/tag/v0", body)
        self.assertNotIn("/pull/8", body)  # Dependabot
        self.assertNotIn("issuecomment-2", body)  # the check's own comment
        self.assertNotIn("octo/old", " ".join(gh.paths))
        for secret in (BAD_IP, BAD_REF, "4021983495"):
            self.assertNotIn(secret, body)
            self.assertNotIn(secret, log)
        self.assertNotIn("github.com", log)  # the public log has counts only
        self.assertIn("3 with findings in 1 repositories", log)

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

        def get_all(path: str) -> list[Any]:
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

        def get_all(path: str) -> list[Any]:
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

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            self.assertEqual(api.get_all("/x"), [1, 2, 3])
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0].get_header("Authorization"), "Bearer tok")
        self.assertTrue(seen[0].full_url.endswith("/x?per_page=100"))

    def test_too_many_pages(self) -> None:
        api = event.RestApi("https://api.example.org", "tok")
        loop = lambda req, timeout: FakeResponse([1], '<https://api.example.org/x?p=n>; rel="next"')  # noqa: E731
        with mock.patch("urllib.request.urlopen", loop), self.assertRaises(event.ApiError):
            api.get_all("/x?a=1")

    def test_errors_carry_status_not_body(self) -> None:
        api = event.RestApi("https://api.example.org", "tok")
        err = urllib.error.HTTPError("https://api.example.org/x", 403, "Forbidden " + BAD_IP, {}, io.BytesIO(BAD_IP.encode()))  # type: ignore[arg-type]
        with mock.patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(event.ApiError) as ctx:
                api.post("/x", {"body": BAD_IP})
        self.assertEqual(str(ctx.exception), "POST /x: HTTP 403")
        self.assertEqual(ctx.exception.status, 403)
        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            with self.assertRaises(event.ApiError) as ctx:
                api.get("/y?q=1")
        self.assertEqual(str(ctx.exception), "GET /y: URLError")

    def test_low_level_failures_become_api_errors(self) -> None:
        api = event.RestApi("https://api.example.org", "tok")
        for exc in (ConnectionResetError(), TimeoutError(), http.client.IncompleteRead(b"x")):
            with mock.patch("urllib.request.urlopen", side_effect=exc):
                with self.assertRaises(event.ApiError) as ctx:
                    api.get("/z")
            self.assertIsNone(ctx.exception.status)
        bad = FakeResponse(None)
        bad.raw = b"<html>" + BAD_IP.encode()
        with mock.patch("urllib.request.urlopen", lambda req, timeout: bad):
            with self.assertRaises(event.ApiError) as ctx:
                api.get("/z")
        self.assertEqual(str(ctx.exception), "GET /z: the response is not JSON")

    def test_gitlab_auth_header_and_json_bodies(self) -> None:
        api = event.RestApi("https://gitlab.example.org/api/v4", "glt", gitlab=True)
        seen: list[Any] = []

        def fake_urlopen(req: Any, timeout: int) -> FakeResponse:
            seen.append(req)
            return FakeResponse({"ok": True})

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            self.assertEqual(api.patch("/n", {"body": "x"}), {"ok": True})
        self.assertEqual(seen[0].get_header("Private-token"), "glt")
        self.assertIsNone(seen[0].get_header("Authorization"))
        self.assertEqual(json.loads(seen[0].data), {"body": "x"})
        self.assertEqual(seen[0].get_method(), "PATCH")


if __name__ == "__main__":
    unittest.main()
