"""Tests for event.py, with a fake GitHub API: which texts it reads, the one comment it
keeps, the exit status, and that the matched text never reaches the log, the step
summary or the comment. Every planted value is synthetic."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import event  # noqa: E402

REPO = "octo/app"
BAD_IP = "34.120.7.9"
BAD_REF = "GitLab #7, note 1234509876"
BAD_PATH = "/home/ops/wt/notes.md"
SECRETS = (BAD_IP, BAD_REF, BAD_PATH, "1234509876", "/home/ops")
HTML = "https://github.com/octo/app"


def user(login: str = "author", kind: str = "User") -> dict[str, Any]:
    return {"login": login, "type": kind}


def own_comment(cid: int, body: str) -> dict[str, Any]:
    return {"id": cid, "node_id": f"IC_{cid}", "body": body, "user": user("github-actions[bot]", "Bot"), "html_url": f"{HTML}/pull/7#issuecomment-{cid}"}


class FakeApi:
    def __init__(self, number: int = 7, is_pr: bool = True, **parts: Any) -> None:
        self.number = number
        self.issue = parts.get(
            "issue",
            {"id": 1, "title": "Fix", "body": "A clean body.", "user": user(), "author_association": "MEMBER", "html_url": f"{HTML}/pull/{number}"},
        )
        if is_pr:
            self.issue.setdefault("pull_request", {})
        self.comments: list[dict[str, Any]] = parts.get("comments", [])
        self.reviews: list[dict[str, Any]] = parts.get("reviews", [])
        self.review_comments: list[dict[str, Any]] = parts.get("review_comments", [])
        self.commits: list[dict[str, Any]] = parts.get("commits", [])
        self.discussion: dict[str, Any] | None = parts.get("discussion")
        self.fail_reads = parts.get("fail_reads", False)
        self.fail_writes = parts.get("fail_writes", False)
        self.posts: list[tuple[str, dict[str, Any]]] = []
        self.patches: list[tuple[str, dict[str, Any]]] = []
        self.mutations: list[dict[str, Any]] = []

    def _check_read(self) -> None:
        if self.fail_reads:
            raise event.ApiError("GET /x: HTTP 403", 403)

    def get(self, path: str) -> Any:
        self._check_read()
        assert path == f"/repos/{REPO}/issues/{self.number}", path
        return self.issue

    def get_all(self, path: str, max_pages: int = event.MAX_PAGES) -> list[Any]:
        self._check_read()
        table = {
            f"/repos/{REPO}/issues/{self.number}/comments": self.comments,
            f"/repos/{REPO}/pulls/{self.number}/reviews": self.reviews,
            f"/repos/{REPO}/pulls/{self.number}/comments": self.review_comments,
            f"/repos/{REPO}/pulls/{self.number}/commits": self.commits,
        }
        return table[path]

    def post(self, path: str, body: dict[str, Any]) -> Any:
        if self.fail_writes:
            raise event.ApiError(f"POST {path}: HTTP 403", 403)
        self.posts.append((path, body))
        return {}

    def patch(self, path: str, body: dict[str, Any]) -> Any:
        if self.fail_writes:
            raise event.ApiError(f"PATCH {path}: HTTP 403", 403)
        self.patches.append((path, body))
        return {}

    def graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        if query.lstrip().startswith("mutation"):
            if self.fail_writes:
                raise event.ApiError("POST /graphql: HTTP 403", 403)
            self.mutations.append({"query": query, **variables})
            return {}
        self._check_read()
        return {"repository": {"discussion": self.discussion}}


class Runner(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.summary = Path(self.tmp.name) / "summary.md"

    def run_event(self, name: str, payload: dict[str, Any], api: FakeApi, **env: str) -> tuple[int, str]:
        path = Path(self.tmp.name) / "event.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        full = {
            "GITHUB_EVENT_NAME": name,
            "GITHUB_EVENT_PATH": str(path),
            "GITHUB_REPOSITORY": REPO,
            "GITHUB_STEP_SUMMARY": str(self.summary),
            **env,
        }
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            status = event.run(full, api)
        return status, out.getvalue()

    def assert_no_echo(self, api: FakeApi, log: str) -> None:
        written = [b["body"] for _, b in api.posts + api.patches] + [m.get("body", "") for m in api.mutations]
        summary = self.summary.read_text(encoding="utf-8") if self.summary.exists() else ""
        for blob in [log, summary, *written]:
            for secret in SECRETS:
                self.assertNotIn(secret, blob)


def pr_payload(body: str = "A clean body.", title: str = "Fix", login: str = "author", kind: str = "User", action: str = "edited", **extra: Any) -> dict[str, Any]:
    pr = {"id": 99, "number": 7, "title": title, "body": body, "user": user(login, kind), "author_association": "MEMBER", "html_url": f"{HTML}/pull/7"}
    return {"action": action, "pull_request": pr, "sender": user(login, kind), **extra}


class PullRequestEvents(Runner):
    def test_clean_pull_request_passes_without_a_comment(self) -> None:
        api = FakeApi()
        status, _ = self.run_event("pull_request", pr_payload(), api)
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

    def test_a_bad_title_is_named_as_the_title(self) -> None:
        api = FakeApi()
        status, _ = self.run_event("pull_request", pr_payload(title=f"Hotfix for {BAD_IP}"), api)
        self.assertEqual(status, 1)
        body = api.posts[0][1]["body"]
        self.assertIn("[The pull request title]", body)
        self.assertIn("only GitHub Support can remove", body)

    def test_a_renamed_title_is_checked_as_it_is_now(self) -> None:
        api = FakeApi()
        payload = pr_payload(title="Fix the dialler", changes={"title": {"from": f"Fix {BAD_IP}"}})
        status, log = self.run_event("pull_request", payload, api)
        self.assertEqual(status, 0)
        self.assert_no_echo(api, log)

    def test_a_token_finding_says_revoke_first(self) -> None:
        api = FakeApi()
        token = "gh" + "p_" + "".join("abcdefghij0123456789"[(i * 7) % 20] for i in range(36))
        status, log = self.run_event("pull_request", pr_payload(f"token {token}"), api)
        self.assertEqual(status, 1)
        self.assertIn("revoke or rotate it first", api.posts[0][1]["body"])
        self.assertNotIn(token, log)

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
        impostor = {"id": 56, "body": event.MARKER + " hi", "user": user("mallory"), "author_association": "NONE", "html_url": f"{HTML}/pull/7#issuecomment-56"}
        api = FakeApi(comments=[impostor])
        status, _ = self.run_event("pull_request", pr_payload(f"at {BAD_IP}"), api)
        self.assertEqual(status, 1)
        self.assertEqual(len(api.posts), 1)
        self.assertEqual(api.patches, [])

    def test_whole_thread_is_checked_commits_included(self) -> None:
        api = FakeApi(
            reviews=[{"id": 3, "body": f"see {BAD_PATH}", "user": user(), "author_association": "MEMBER", "html_url": f"{HTML}/pull/7#pullrequestreview-3"}],
            review_comments=[{"id": 4, "body": "fine", "user": user(), "html_url": f"{HTML}/pull/7#discussion_r4"}],
            commits=[
                {"sha": "a1", "html_url": f"{HTML}/commit/a1", "author": user(), "commit": {"message": f"fix: per {BAD_REF}", "author": {"email": "dev@example.org"}, "committer": {"email": "noreply@github.com"}}},
                {"sha": "a2", "html_url": f"{HTML}/commit/a2", "author": user(), "commit": {"message": "clean", "author": {"email": "pat@" + "distronode" + ".com"}, "committer": {"email": "noreply@github.com"}}},
                {"sha": "a3", "html_url": f"{HTML}/commit/a3", "author": user("dependabot[bot]", "Bot"), "commit": {"message": f"bump from {BAD_IP}", "author": {"email": "x@users.noreply.github.com"}, "committer": {"email": "noreply@github.com"}}},
            ],
        )
        status, log = self.run_event("pull_request", pr_payload(), api)
        self.assertEqual(status, 1)
        self.assertIn("Finding in a review: private-path", log)
        self.assertIn("Finding in a commit message: private-reference", log)
        self.assertIn("Finding in a commit message: internal-email", log)
        self.assertEqual(log.count("Finding in a commit message"), 2)  # the Dependabot one is skipped
        body = api.posts[0][1]["body"]
        self.assertIn("[A review](", body)
        self.assertIn(f"[A commit message]({HTML}/commit/a1)", body)
        self.assertIn("force-push the branch", body)
        self.assert_no_echo(api, log)

    def test_dependabot_text_is_skipped_unless_a_person_edited_it(self) -> None:
        api = FakeApi()
        payload = pr_payload(f"at {BAD_IP}", login="dependabot[bot]", kind="Bot", action="opened")
        status, _ = self.run_event("pull_request", payload, api)
        self.assertEqual(status, 0)
        payload["action"] = "edited"
        payload["sender"] = user("pat")
        status, _ = self.run_event("pull_request", payload, FakeApi())
        self.assertEqual(status, 1)
        status, _ = self.run_event("pull_request", pr_payload(f"at {BAD_IP}", login="dependabot[bot]", kind="User"), FakeApi())
        self.assertEqual(status, 1)

    def test_other_bots_are_checked(self) -> None:
        bot = {"id": 9, "node_id": "IC_9", "body": f"from {BAD_IP}", "user": user("some-ci[bot]", "Bot"), "author_association": "NONE", "html_url": f"{HTML}/pull/7#issuecomment-9"}
        status, _ = self.run_event("pull_request", pr_payload(), FakeApi(comments=[bot]))
        self.assertEqual(status, 1)

    def test_review_bots_are_skipped_but_people_replying_are_not(self) -> None:
        seer = {"id": 21, "body": f"e.g. `user@{BAD_IP}`", "user": user("sentry[bot]", "Bot"), "html_url": f"{HTML}/pull/7#discussion_r21"}
        copilot = {"id": 22, "body": f"see {BAD_PATH}", "user": user("Copilot", "Bot"), "html_url": f"{HTML}/pull/7#discussion_r22"}
        status, _ = self.run_event("pull_request", pr_payload(), FakeApi(review_comments=[seer, copilot]))
        self.assertEqual(status, 0)
        reply = {"id": 23, "body": f"fixed for {BAD_IP}", "user": user(), "author_association": "MEMBER", "html_url": f"{HTML}/pull/7#discussion_r23"}
        status, log = self.run_event("pull_request", pr_payload(), FakeApi(review_comments=[seer, copilot, reply]))
        self.assertEqual(status, 1)
        self.assertEqual(log.count("Finding in a review comment"), 1)

    def test_a_hidden_comment_is_skipped(self) -> None:
        hidden = {"id": 9, "node_id": "IC_9", "body": f"from {BAD_IP}", "minimized": {"reason": "spam"}, "user": user(), "html_url": f"{HTML}/pull/7#issuecomment-9"}
        status, _ = self.run_event("pull_request", pr_payload(), FakeApi(comments=[hidden]))
        self.assertEqual(status, 0)

    def test_an_outsider_is_checked_for_credentials_only(self) -> None:
        outsider = {"id": 9, "node_id": "IC_9", "body": f"crash at {BAD_PATH} from {BAD_IP}", "user": user("reporter"), "author_association": "NONE", "html_url": f"{HTML}/pull/7#issuecomment-9"}
        status, _ = self.run_event("pull_request", pr_payload(), FakeApi(comments=[outsider]))
        self.assertEqual(status, 0)

    def test_read_only_token_still_fails_the_check(self) -> None:
        api = FakeApi(fail_writes=True)
        status, log = self.run_event("pull_request", pr_payload(f"at {BAD_IP}"), api)
        self.assertEqual(status, 1)
        self.assertIn("Could not write the hygiene comment", log)
        self.assert_no_echo(api, log)

    def test_unreadable_thread_fails_closed_even_when_the_item_is_clean(self) -> None:
        api = FakeApi(fail_reads=True)
        payload = {"action": "submitted", "pull_request": {"number": 7}, "review": {"id": 5, "body": "LGTM", "user": user(), "html_url": f"{HTML}/pull/7#pullrequestreview-5"}}
        status, log = self.run_event("pull_request_review", payload, api)
        self.assertEqual(status, 2)
        self.assertIn("could not be checked in full", log)
        self.assertEqual(api.posts + api.patches, [])

    def test_unreadable_thread_still_reports_the_item(self) -> None:
        api = FakeApi(fail_reads=True)
        status, log = self.run_event("pull_request", pr_payload(f"at {BAD_IP}"), api)
        self.assertEqual(status, 1)
        self.assertIn("only the event's own item", log)
        self.assertEqual(api.posts, [])
        self.assert_no_echo(api, log)

    def test_a_spent_time_budget_fails_closed(self) -> None:
        api = FakeApi()
        status, log = self.run_event("pull_request", pr_payload(), api, PUBLIC_HYGIENE_TIME_BUDGET="-1")
        self.assertEqual(status, 2)
        self.assertIn("time budget", log)

    def test_review_events(self) -> None:
        payload = {"action": "submitted", "pull_request": {"number": 7}, "review": {"id": 5, "body": f"see {BAD_PATH}", "user": user(), "html_url": f"{HTML}/pull/7#pullrequestreview-5"}}
        status, _ = self.run_event("pull_request_review", payload, FakeApi())
        self.assertEqual(status, 1)
        payload = {"action": "created", "pull_request": {"number": 7}, "comment": {"id": 6, "body": f"see {BAD_REF}", "user": user(), "html_url": f"{HTML}/pull/7#discussion_r6"}}
        api = FakeApi()
        status, log = self.run_event("pull_request_review_comment", payload, api)
        self.assertEqual(status, 1)
        self.assertIn("[A review comment](", api.posts[0][1]["body"])
        self.assert_no_echo(api, log)


class IssueEvents(Runner):
    def test_issue_and_comment(self) -> None:
        issue = {"id": 1, "number": 3, "title": "Bug", "body": f"from {BAD_IP}", "user": user(), "author_association": "MEMBER", "html_url": f"{HTML}/issues/3"}
        api = FakeApi(number=3, is_pr=False, issue=dict(issue))
        status, log = self.run_event("issues", {"action": "opened", "issue": issue}, api)
        self.assertEqual(status, 1)
        self.assertIn("[The issue description]", api.posts[0][1]["body"])
        self.assert_no_echo(api, log)

        clean_issue = dict(issue, body="Clean.")
        comment = {"id": 8, "node_id": "IC_8", "body": f"logs at {BAD_PATH}", "user": user(), "html_url": f"{HTML}/issues/3#issuecomment-8"}
        api = FakeApi(number=3, is_pr=False, issue=dict(clean_issue))
        status, log = self.run_event("issue_comment", {"action": "created", "issue": clean_issue, "comment": comment}, api)
        self.assertEqual(status, 1)
        self.assertIn("[A comment]", api.posts[0][1]["body"])
        self.assert_no_echo(api, log)

    def test_a_deleted_comment_clears_the_finding(self) -> None:
        issue = {"id": 1, "number": 3, "title": "Bug", "body": "Clean.", "user": user(), "html_url": f"{HTML}/issues/3"}
        gone = {"id": 8, "node_id": "IC_8", "body": f"logs at {BAD_PATH}", "user": user(), "html_url": f"{HTML}/issues/3#issuecomment-8"}
        api = FakeApi(number=3, is_pr=False, issue=dict(issue), comments=[own_comment(10, event.MARKER + "\nfindings")])
        status, _ = self.run_event("issue_comment", {"action": "deleted", "issue": issue, "comment": gone}, api)
        self.assertEqual(status, 0)
        self.assertIn("any more", api.patches[0][1]["body"])

    def test_comment_on_a_pull_request_reads_reviews_too(self) -> None:
        issue = {"id": 1, "number": 7, "title": "Fix", "body": "Clean.", "user": user(), "html_url": f"{HTML}/pull/7", "pull_request": {}}
        comment = {"id": 9, "node_id": "IC_9", "body": "ok", "user": user(), "html_url": f"{HTML}/pull/7#issuecomment-9"}
        api = FakeApi(reviews=[{"id": 2, "body": f"x {BAD_IP}", "user": user(), "html_url": f"{HTML}/pull/7#pullrequestreview-2"}])
        status, _ = self.run_event("issue_comment", {"action": "created", "issue": issue, "comment": comment}, api)
        self.assertEqual(status, 1)

    def test_our_own_comment_is_not_scanned(self) -> None:
        issue = {"id": 1, "number": 3, "title": "Bug", "body": "Clean.", "user": user(), "html_url": f"{HTML}/issues/3"}
        ours = own_comment(10, event.MARKER + " mentions `ip-address` and /home/ops/ as a rule")
        api = FakeApi(number=3, is_pr=False, issue=dict(issue), comments=[ours])
        status, log = self.run_event("issue_comment", {"action": "edited", "issue": issue, "comment": ours}, api)
        self.assertEqual(status, 0)
        self.assertIn("Checked 2 text(s)", log)

    def test_the_rendered_comment_passes_its_own_rules(self) -> None:
        kinds = ("title", "description", "comment", "commit message")
        every_rule = [
            (event.Source(kind, f"{kind}:1", f"{HTML}/issues/3#issuecomment-1", "a", "User", ()), sorted(event.rules.RULES_BY_ID))
            for kind in kinds
        ]
        self.assertEqual(event.rules.rule_ids(event.render_comment(every_rule, event.Target("pr", 3))), [])
        self.assertEqual(event.rules.rule_ids(event.render_resolved()), [])


def discussion(body: str = "Clean.", comments: list[dict[str, Any]] | None = None, more: bool = False) -> dict[str, Any]:
    return {
        "id": "D_1",
        "title": "Idea",
        "body": body,
        "url": f"{HTML}/discussions/4",
        "authorAssociation": "MEMBER",
        "author": {"login": "pat", "__typename": "User"},
        "comments": {"pageInfo": {"hasNextPage": more, "endCursor": "c1"}, "nodes": comments or []},
    }


def gql_comment(cid: str, body: str, login: str = "pat", kind: str = "User", replies: list[dict[str, Any]] | None = None, total: int | None = None) -> dict[str, Any]:
    replies = replies or []
    return {
        "id": cid,
        "body": body,
        "url": f"{HTML}/discussions/4#discussioncomment-{cid}",
        "isMinimized": False,
        "authorAssociation": "MEMBER",
        "author": {"login": login, "__typename": kind},
        "replies": {"totalCount": len(replies) if total is None else total, "nodes": replies},
    }


class DiscussionAndReleaseEvents(Runner):
    def test_discussion_reply_finding_posts_one_discussion_comment(self) -> None:
        reply = gql_comment("R_1", f"see {BAD_PATH}")
        api = FakeApi(discussion=discussion(comments=[gql_comment("C_1", "ok", replies=[reply])]))
        payload = {"action": "created", "discussion": {"number": 4, "node_id": "D_1", "title": "Idea", "body": "Clean."}, "comment": {"node_id": "C_1", "body": "ok", "user": user()}}
        status, log = self.run_event("discussion_comment", payload, api)
        self.assertEqual(status, 1)
        self.assertEqual(len(api.mutations), 1)
        self.assertIn("addDiscussionComment", api.mutations[0]["query"])
        self.assertEqual(api.mutations[0]["id"], "D_1")
        self.assert_no_echo(api, log)

    def test_discussion_comment_is_updated_and_resolved(self) -> None:
        ours = gql_comment("C_9", event.MARKER + "\nold", login="github-actions", kind="Bot")
        api = FakeApi(discussion=discussion(comments=[ours]))
        payload = {"action": "edited", "discussion": {"number": 4, "title": "Idea", "body": "Clean.", "user": user()}}
        status, _ = self.run_event("discussion", payload, api)
        self.assertEqual(status, 0)
        self.assertIn("updateDiscussionComment", api.mutations[0]["query"])
        self.assertEqual(api.mutations[0]["id"], "C_9")

    def test_too_many_replies_fails_closed(self) -> None:
        api = FakeApi(discussion=discussion(comments=[gql_comment("C_1", "ok", total=51)]))
        payload = {"action": "edited", "discussion": {"number": 4, "title": "Idea", "body": "Clean.", "user": user()}}
        status, _ = self.run_event("discussion", payload, api)
        self.assertEqual(status, 2)

    def test_release_notes_are_checked_without_a_comment(self) -> None:
        api = FakeApi()
        payload = {"action": "published", "release": {"id": 12, "name": "v1.2", "body": f"Notes ({BAD_REF})", "author": user(), "html_url": f"{HTML}/releases/tag/v1.2"}}
        status, log = self.run_event("release", payload, api)
        self.assertEqual(status, 1)
        self.assertEqual(api.posts + api.patches + api.mutations, [])
        self.assertIn("Finding in a release: private-reference", log)
        self.assert_no_echo(api, log)


class Plumbing(Runner):
    def test_a_run_without_the_key_says_so_and_checks_everything_else(self) -> None:
        with mock.patch.object(event.rules, "DENYLIST_KEY", b""):
            status, log = self.run_event("pull_request", pr_payload(f"at {BAD_IP}"), FakeApi())
        self.assertEqual(status, 1)  # the other rules still ran
        self.assertIn("internal-name rule did not run", self.summary.read_text())
        self.summary.unlink()
        with mock.patch.object(event.rules, "DENYLIST_KEY", bytes(range(32))):
            self.run_event("pull_request", pr_payload(), FakeApi())
        self.assertNotIn("did not run", self.summary.read_text())

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
        source = event.Source("comment", "comment:1", "javascript:alert(1)", "a", "User", ())
        self.assertEqual(event._link(source, event.Target("pr", 1)), "A comment")

    def test_rest_api_refuses_plain_http(self) -> None:
        with self.assertRaises(event.ApiError):
            event.RestApi("http://api.example.org", "t")

    def test_main_hides_unexpected_errors(self) -> None:
        with mock.patch.object(event, "run", side_effect=ValueError("secret text " + BAD_IP)):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(event.main(), 2)
        self.assertIn("ValueError", out.getvalue())
        self.assertNotIn(BAD_IP, out.getvalue())

    def test_main_reports_api_errors(self) -> None:
        with mock.patch.object(event, "run", side_effect=event.ApiError("GET /x: HTTP 502", 502)):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(event.main(), 2)
        self.assertIn("HTTP 502", out.getvalue())


if __name__ == "__main__":
    unittest.main()
