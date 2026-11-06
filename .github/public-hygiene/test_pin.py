"""Tests for pin.py, with a fake API."""

from __future__ import annotations

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


class FakeApi:
    def __init__(self, status: str | None = "behind", error: int | None = None) -> None:
        self.status, self.error = status, error

    def get(self, path: str) -> Any:
        if path == "/repos/octo/.github":
            return {"default_branch": "main"}
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
