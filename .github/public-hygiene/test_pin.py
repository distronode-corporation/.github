"""Tests for pin.py, with a fake API."""

from __future__ import annotations

import base64
import contextlib
import io
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import event  # noqa: E402
import pin  # noqa: E402

SHA = "0123456789abcdef0123456789abcdef01234567"
CALLER_SHA = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"


OTHER = "fedcba9876543210fedcba9876543210fedcba98"
TAG_OBJ = "1111111111111111111111111111111111111111"


class FakeApi:
    def __init__(self, status: str | None = "behind", error: int | None = None, caller: str | None = None) -> None:
        self.status, self.error = status, error
        # v1.0.0 is a lightweight tag on SHA, v1.1.0 an annotated one on SHA, v0.9.0 on another commit.
        self.tags = {"v1.0.0": {"type": "commit", "sha": SHA}, "v1.1.0": {"type": "tag", "sha": TAG_OBJ}, "v0.9.0": {"type": "commit", "sha": OTHER}}
        self.caller = caller

    def get(self, path: str) -> Any:
        if path == "/repos/octo/.github":
            return {"default_branch": "main"}
        if path.startswith("/repos/octo/.github/git/ref/tags/"):
            tag = path.rsplit("/", 1)[1]
            if tag not in self.tags:
                raise event.ApiError("GET x: HTTP 404", 404)
            return {"object": self.tags[tag]}
        if path == f"/repos/octo/.github/git/tags/{TAG_OBJ}":
            return {"object": {"type": "commit", "sha": SHA}}
        if path.startswith("/repos/octo/app/contents/"):
            assert path == f"/repos/octo/app/contents/.github/workflows/public-hygiene.yml?ref={CALLER_SHA}", path
            return {"content": base64.b64encode((self.caller or "").encode()).decode()}
        assert path == f"/repos/octo/.github/compare/main...{SHA}", path
        if self.error:
            raise event.ApiError("GET x: HTTP %d" % self.error, self.error)
        return {"status": self.status}


class Pin(unittest.TestCase):
    def test_on_the_default_branch(self) -> None:
        for status in ("identical", "behind"):
            ok, message = pin.check(FakeApi(status), "octo/.github", SHA)
            self.assertTrue(ok, status)
            self.assertIn("is on octo/.github main", message)

    def test_off_the_default_branch(self) -> None:
        for status in ("ahead", "diverged", None):
            ok, message = pin.check(FakeApi(status), "octo/.github", SHA)
            self.assertFalse(ok, status)
            self.assertIn("Re-pin", message)

    def test_unknown_commit(self) -> None:
        ok, message = pin.check(FakeApi(error=404), "octo/.github", SHA)
        self.assertFalse(ok)
        self.assertIn("not known", message)
        with self.assertRaises(event.ApiError):
            pin.check(FakeApi(error=502), "octo/.github", SHA)

    def test_bad_input(self) -> None:
        self.assertFalse(pin.check(FakeApi(), "octo/.github", "abc123")[0])
        self.assertFalse(pin.check(FakeApi(), "not a repo", SHA)[0])

    def test_the_comment_must_name_a_tag_on_the_pinned_commit(self) -> None:
        api = FakeApi()
        for comment, ok in (
            ("# v1.0.0", True),
            ("#v1.0.0", True),
            ("# v1.1.0", True),  # an annotated tag, peeled to its commit
            ("# v0.9.0", False),  # a tag on another commit
            ("# v2.0.0", False),  # no such tag
            ("# main", False),  # a branch name drifts
            ("# master", False),
            ("# v1", False),  # not a tag here
            ("# .github main at the merge of #9", False),  # a description is never checked
            ("# release v1.0.0", False),
            ("", False),
            (None, False),
        ):
            with self.subTest(comment=comment):
                self.assertEqual(pin.check_comment(api, "octo/.github", SHA, comment)[0], ok)

    def test_check_caller(self) -> None:
        line = "    uses: octo/.github/.github/workflows/public-hygiene.yml@{} {}\n"
        self.assertEqual(pin.check_caller(FakeApi(), "octo/.github", line.format(SHA, "# v1.0.0")), [])
        problems = pin.check_caller(FakeApi("ahead"), "octo/.github", line.format(SHA, "# main"))
        self.assertEqual(len(problems), 2)  # off main, and a branch-name comment
        self.assertEqual(pin.check_caller(FakeApi(), "octo/.github", "jobs: {}\n"), ["The caller pins no commit of the shared workflow."])

    def test_main_checks_the_callers_comment(self) -> None:
        env = {
            "WORKFLOW_REPOSITORY": "octo/.github", "WORKFLOW_SHA": SHA,
            "CALLER_REPOSITORY": "octo/app", "CALLER_SHA": CALLER_SHA,
            "CALLER_WORKFLOW_REF": "octo/app/.github/workflows/public-hygiene.yml@refs/pull/7/merge",
        }
        for comment, code in (("# v1.0.0", 0), ("# main", 1), ("# a description", 1)):
            api = FakeApi(caller=f"    uses: octo/.github/.github/workflows/public-hygiene.yml@{SHA} {comment}\n")
            with mock.patch.dict("os.environ", env), mock.patch.object(pin, "RestApi", lambda *a, k=None, api=api, **kw: api):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(pin.main(), code, comment)
            if code:
                self.assertIn("must be exactly", out.getvalue())

    def test_a_caller_that_cannot_be_named_is_an_error(self) -> None:
        with self.assertRaises(event.ApiError):
            pin.caller_text(FakeApi(), "octo/app", "other/repo/.github/workflows/x.yml@refs/heads/main", CALLER_SHA)

    def test_main(self) -> None:
        env = {"WORKFLOW_REPOSITORY": "octo/.github", "WORKFLOW_SHA": SHA}
        for api, code in ((FakeApi("behind"), 0), (FakeApi("ahead"), 1)):
            with mock.patch.dict("os.environ", env), mock.patch.object(pin, "RestApi", lambda *a, **k: api):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(pin.main(), code)
        with mock.patch.dict("os.environ", env), mock.patch.object(pin, "RestApi", lambda *a, **k: FakeApi(error=502)):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(pin.main(), 2)


if __name__ == "__main__":
    unittest.main()
