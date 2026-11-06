"""Tests for event.py, with a fake GitHub API: which texts it reads, the one comment it
keeps, the exit status, and that the matched text never reaches the log, the step
summary or the comment."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import event  # noqa: E402

REPO = "octo/app"
BAD_IP = "34.120.7.9"
BAD_REF = "GitLab #2, note 4021983495"
BAD_PATH = "/home/ops/wt/notes.md"
SECRETS = (BAD_IP, BAD_REF, BAD_PATH, "4021983495", "/home/ops")
HTML = "https://github.com/octo/app"


def user(login: str = "author", kind: str = "User") -> dict[str, Any]:
    return {"login": login, "type": kind}


def own_comment(cid: int, body: str) -> dict[str, Any]:
    return {"id": cid, "body": body, "user": user("github-actions[bot]", "Bot"), "html_url": f"{HTML}/pull/7#issuecomment-{cid}"}


class FakeApi:
    def __init__(self, number: int = 7, is_pr: bool = True, **parts: Any) -> None:
        self.number = number
        self.issue = parts.get("issue", {"id": 1, "title": "Fix", "body": "A clean body.", "user": user(), "html_url": f"{HTML}/pull/{number}"})
        if is_pr:
            self.issue.setdefault("pull_request", {})
        self.comments: list[dict[str, Any]] = parts.get("comments", [])
        self.reviews: list[dict[str, Any]] = parts.get("reviews", [])
        self.review_comments: list[dict[str, Any]] = parts.get("review_comments", [])
        self.fail_reads = parts.get("fail_reads", False)
        self.fail_writes = parts.get("fail_writes", False)
        self.posts: list[tuple[str, dict[str, Any]]] = []
        self.patches: list[tuple[str, dict[str, Any]]] = []

    def _check_read(self) -> None:
        if self.fail_reads:
            raise event.ApiError("GET /x: HTTP 403")

    def get(self, path: str) -> Any:
        self._check_read()
        assert path == f"/repos/{REPO}/issues/{self.number}", path
        return self.issue

    def get_all(self, path: str) -> list[Any]:
        self._check_read()
        table = {
            f"/repos/{REPO}/issues/{self.number}/comments": self.comments,
            f"/repos/{REPO}/pulls/{self.number}/reviews": self.reviews,
            f"/repos/{REPO}/pulls/{self.number}/comments": self.review_comments,
        }
        return table[path]

    def post(self, path: str, body: dict[str, Any]) -> Any:
        if self.fail_writes:
            raise event.ApiError(f"POST {path}: HTTP 403")
        self.posts.append((path, body))
        return {}

    def patch(self, path: str, body: dict[str, Any]) -> Any:
        if self.fail_writes:
            raise event.ApiError(f"PATCH {path}: HTTP 403")
        self.patches.append((path, body))
        return {}


class Runner(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.summary = Path(self.tmp.name) / "summary.md"

    def run_event(self, name: str, payload: dict[str, Any], api: FakeApi) -> tuple[int, str]:
        path = Path(self.tmp.name) / "event.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        env = {
            "GITHUB_EVENT_NAME": name,
            "GITHUB_EVENT_PATH": str(path),
            "GITHUB_REPOSITORY": REPO,
            "GITHUB_STEP_SUMMARY": str(self.summary),
        }
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            status = event.run(env, api)
        return status, out.getvalue()

    def assert_no_echo(self, api: FakeApi, log: str) -> None:
        written = [b["body"] for _, b in api.posts + api.patches]
        summary = self.summary.read_text(encoding="utf-8") if self.summary.exists() else ""
        for blob in [log, summary, *written]:
            for secret in SECRETS:
                self.assertNotIn(secret, blob)


def pr_payload(body: str = "A clean body.", title: str = "Fix", login: str = "author", kind: str = "User") -> dict[str, Any]:
    return {"action": "edited", "pull_request": {"id": 99, "number": 7, "title": title, "body": body, "user": user(login, kind), "html_url": f"{HTML}/pull/7"}}


class PullRequestEvents(Runner):
    def test_clean_pull_request_passes_without_a_comment(self) -> None:
        api = FakeApi()
        status, log = self.run_event("pull_request", pr_payload(), api)
        self.assertEqual(status, 0)
        self.assertEqual(api.posts + api.patches, [])
        self.assertIn("No findings.", self.summary.read_text())

    def test_bad_description_fails_and_posts_one_comment(self) -> None:
        api = FakeApi()
        body = f"Deployed from {BAD_IP}. Approved ({BAD_REF}). Notes in {BAD_PATH}."
        status, log = self.run_event("pull_request", pr_payload(body), api)
        self.assertEqual(status, 1)
        self.assertEqual(len(api.posts), 1)
        path, comment = api.posts[0]
        self.assertEqual(path, f"/repos/{REPO}/issues/7/comments")
        for rule_id in ("ip-address", "private-reference", "private-path"):
            self.assertIn(f"`{rule_id}`", comment["body"])
            self.assertIn(rule_id, log)
        self.assertTrue(comment["body"].startswith(event.MARKER))
        self.assertIn(f"[The pull request description]({HTML}/pull/7)", comment["body"])
        self.assert_no_echo(api, log)

    def test_bad_title_counts(self) -> None:
        api = FakeApi()
        status, _ = self.run_event("pull_request", pr_payload(title=f"Hotfix for {BAD_IP}"), api)
        self.assertEqual(status, 1)

    def test_payload_description_wins_over_a_stale_listing(self) -> None:
        stale = {"id": 1, "title": "Fix", "body": f"old {BAD_IP}", "user": user(), "html_url": f"{HTML}/pull/7", "pull_request": {}}
        api = FakeApi(issue=stale)
        status, _ = self.run_event("pull_request", pr_payload("Fixed now."), api)
        self.assertEqual(status, 0)

    def test_existing_comment_is_updated_not_duplicated(self) -> None:
        api = FakeApi(comments=[own_comment(55, event.MARKER + "\nold")])
        status, log = self.run_event("pull_request", pr_payload(f"at {BAD_IP}"), api)
        self.assertEqual(status, 1)
        self.assertEqual(api.posts, [])
        self.assertEqual(api.patches[0][0], f"/repos/{REPO}/issues/comments/55")
        self.assert_no_echo(api, log)

    def test_current_comment_is_left_alone(self) -> None:
        api = FakeApi()
        self.run_event("pull_request", pr_payload(f"at {BAD_IP}"), api)
        body = api.posts[0][1]["body"]
        api2 = FakeApi(comments=[own_comment(55, body)])
        status, log = self.run_event("pull_request", pr_payload(f"at {BAD_IP}"), api2)
        self.assertEqual(status, 1)
        self.assertEqual(api2.posts + api2.patches, [])
        self.assertIn("already current", log)

    def test_fixed_thread_marks_the_comment_resolved(self) -> None:
        api = FakeApi(comments=[own_comment(55, event.MARKER + "\nfindings")])
        status, _ = self.run_event("pull_request", pr_payload(), api)
        self.assertEqual(status, 0)
        self.assertIn("any more", api.patches[0][1]["body"])

    def test_a_marker_from_someone_else_is_not_ours(self) -> None:
        impostor = {"id": 56, "body": event.MARKER + " hi", "user": user("mallory"), "html_url": f"{HTML}/pull/7#issuecomment-56"}
        api = FakeApi(comments=[impostor])
        status, _ = self.run_event("pull_request", pr_payload(f"at {BAD_IP}"), api)
        self.assertEqual(status, 1)
        self.assertEqual(len(api.posts), 1)
        self.assertEqual(api.patches, [])

    def test_whole_thread_is_checked(self) -> None:
        api = FakeApi(
            reviews=[{"id": 3, "body": f"see {BAD_PATH}", "user": user(), "html_url": f"{HTML}/pull/7#pullrequestreview-3"}],
            review_comments=[{"id": 4, "body": "fine", "user": user(), "html_url": f"{HTML}/pull/7#discussion_r4"}],
        )
        status, log = self.run_event("pull_request", pr_payload(), api)
        self.assertEqual(status, 1)
        self.assertIn("Finding in a review: private-path", log)
        self.assertIn("[A review](", api.posts[0][1]["body"])
        self.assert_no_echo(api, log)

    def test_dependabot_text_is_skipped_but_a_lookalike_user_is_not(self) -> None:
        api = FakeApi()
        status, _ = self.run_event("pull_request", pr_payload(f"at {BAD_IP}", login="dependabot[bot]", kind="Bot"), api)
        self.assertEqual(status, 0)
        status, _ = self.run_event("pull_request", pr_payload(f"at {BAD_IP}", login="dependabot[bot]", kind="User"), FakeApi())
        self.assertEqual(status, 1)

    def test_read_only_token_still_fails_the_check(self) -> None:
        api = FakeApi(fail_writes=True)
        status, log = self.run_event("pull_request", pr_payload(f"at {BAD_IP}"), api)
        self.assertEqual(status, 1)
        self.assertIn("Could not write the hygiene comment", log)
        self.assert_no_echo(api, log)

    def test_unreadable_thread_falls_back_to_the_payload(self) -> None:
        api = FakeApi(fail_reads=True)
        status, log = self.run_event("pull_request", pr_payload(f"at {BAD_IP}"), api)
        self.assertEqual(status, 1)
        self.assertIn("event's own item only", log)
        self.assertEqual(api.posts, [])
        self.assert_no_echo(api, log)

    def test_review_events(self) -> None:
        payload = {"action": "submitted", "pull_request": {"number": 7}, "review": {"id": 5, "body": f"see {BAD_PATH}", "user": user(), "html_url": f"{HTML}/pull/7#pullrequestreview-5"}}
        status, log = self.run_event("pull_request_review", payload, FakeApi())
        self.assertEqual(status, 1)
        payload = {"action": "created", "pull_request": {"number": 7}, "comment": {"id": 6, "body": f"see {BAD_REF}", "user": user(), "html_url": f"{HTML}/pull/7#discussion_r6"}}
        api = FakeApi()
        status, log = self.run_event("pull_request_review_comment", payload, api)
        self.assertEqual(status, 1)
        self.assertIn("[A review comment](", api.posts[0][1]["body"])
        self.assert_no_echo(api, log)


class IssueEvents(Runner):
    def test_issue_and_comment(self) -> None:
        issue = {"id": 1, "number": 3, "title": "Bug", "body": f"from {BAD_IP}", "user": user(), "html_url": f"{HTML}/issues/3"}
        api = FakeApi(number=3, is_pr=False, issue=dict(issue))
        status, log = self.run_event("issues", {"action": "opened", "issue": issue}, api)
        self.assertEqual(status, 1)
        self.assertIn("[The issue description]", api.posts[0][1]["body"])
        self.assert_no_echo(api, log)

        clean_issue = dict(issue, body="Clean.")
        comment = {"id": 8, "body": f"logs at {BAD_PATH}", "user": user(), "html_url": f"{HTML}/issues/3#issuecomment-8"}
        api = FakeApi(number=3, is_pr=False, issue=dict(clean_issue))
        status, log = self.run_event("issue_comment", {"action": "created", "issue": clean_issue, "comment": comment}, api)
        self.assertEqual(status, 1)
        self.assertIn("[A comment]", api.posts[0][1]["body"])
        self.assert_no_echo(api, log)

    def test_comment_on_a_pull_request_reads_reviews_too(self) -> None:
        issue = {"id": 1, "number": 7, "title": "Fix", "body": "Clean.", "user": user(), "html_url": f"{HTML}/pull/7", "pull_request": {}}
        comment = {"id": 9, "body": "ok", "user": user(), "html_url": f"{HTML}/pull/7#issuecomment-9"}
        api = FakeApi(reviews=[{"id": 2, "body": f"x {BAD_IP}", "user": user(), "html_url": f"{HTML}/pull/7#pullrequestreview-2"}])
        status, _ = self.run_event("issue_comment", {"action": "created", "issue": issue, "comment": comment}, api)
        self.assertEqual(status, 1)

    def test_our_own_comment_is_not_scanned(self) -> None:
        issue = {"id": 1, "number": 3, "title": "Bug", "body": "Clean.", "user": user(), "html_url": f"{HTML}/issues/3"}
        ours = own_comment(10, event.MARKER + " mentions `ip-address` and /home/ops/ as a rule")
        api = FakeApi(number=3, is_pr=False, issue=dict(issue), comments=[ours])
        status, log = self.run_event("issue_comment", {"action": "edited", "issue": issue, "comment": ours}, api)
        self.assertEqual(status, 0)
        self.assertIn("Checked 1 text(s)", log)

    def test_the_rendered_comment_passes_its_own_rules(self) -> None:
        every_rule = [(event.Source("comment", "comment:1", f"{HTML}/issues/3#issuecomment-1", "a", "User", ()), sorted(event.rules.RULES_BY_ID))]
        self.assertEqual(event.rules.rule_ids(event.render_comment(every_rule, True)), [])
        self.assertEqual(event.rules.rule_ids(event.render_resolved()), [])


class Plumbing(Runner):
    def test_unrelated_event_is_a_no_op(self) -> None:
        status, log = self.run_event("push", {"ref": "refs/heads/main"}, FakeApi())
        self.assertEqual(status, 0)
        self.assertIn("Nothing to check", log)

    def test_missing_environment(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(event.run({}, FakeApi()), 2)
            self.assertEqual(event.run({"GITHUB_EVENT_PATH": "/nonexistent/x.json", "GITHUB_REPOSITORY": REPO}, FakeApi()), 2)
            self.assertEqual(event.run({"GITHUB_EVENT_PATH": "x", "GITHUB_REPOSITORY": "bad repo"}, FakeApi()), 2)

    def test_link_only_for_github_urls(self) -> None:
        source = event.Source("comment", "comment:1", "javascript:alert(1)", "a", "User", ("x",))
        self.assertEqual(event._link(source, True), "A comment")

    def test_rest_api_refuses_plain_http(self) -> None:
        with self.assertRaises(event.ApiError):
            event.RestApi("http://api.example.org", "t")

    def test_main_hides_unexpected_errors(self) -> None:
        original = event.run

        def boom(env: dict[str, str], api: Any = None) -> int:
            raise ValueError("secret text " + BAD_IP)

        event.run = boom
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(event.main(), 2)
        finally:
            event.run = original
        self.assertIn("ValueError", out.getvalue())
        self.assertNotIn(BAD_IP, out.getvalue())


if __name__ == "__main__":
    unittest.main()
