"""Tests for check.yml's `caller-pin-current` guard on a pull request, run against a
scratch git repository: the caller must pin the newest v* release tag on the base branch,
not the highest tag anywhere and not a pre-release."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

CHECK_YML = Path(__file__).resolve().parent.parent / "workflows" / "check.yml"


def guard_script() -> str:
    """The `run: |` block of the `caller-pin-current` job."""
    lines = CHECK_YML.read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "caller-pin-current:")
    run = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |")
    indent = len(lines[run]) - len(lines[run].lstrip())
    block = []
    for line in lines[run + 1 :]:
        if line.strip() and len(line) - len(line.lstrip()) <= indent:
            break
        block.append(line)
    return textwrap.dedent("\n".join(block)) + "\n"


# A caller checks out `.github/public-hygiene` alone, without the workflows; this runs
# in this repository's own CI.
@unittest.skipUnless(CHECK_YML.exists() and shutil.which("git") and shutil.which("bash"), "needs check.yml, git and bash")
class CallerPinOnAPullRequest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        empty = self.dir / "gitconfig"
        empty.write_text("")
        self.env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.dir),
            "GIT_CONFIG_GLOBAL": str(empty),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.com",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.com",
        }
        self.repo = self.dir / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.a = self.commit("a")

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=self.repo, env=self.env, check=True, capture_output=True, text=True
        ).stdout.strip()

    def commit(self, name: str) -> str:
        (self.repo / name).write_text(name)
        self.git("add", name)
        self.git("commit", "-q", "-m", name)
        return self.git("rev-parse", "HEAD")

    def guard(self, pin: str, base: str) -> subprocess.CompletedProcess[str]:
        self.git("update-ref", "refs/remotes/origin/main", base)
        workflows = self.repo / ".github" / "workflows"
        workflows.mkdir(parents=True, exist_ok=True)
        (workflows / "public-text.yml").write_text(
            f"    uses: example-org/.github/.github/workflows/public-hygiene.yml@{pin} # v1.0.0\n"
        )
        env = {**self.env, "EVENT_NAME": "pull_request", "GITHUB_BASE_REF": "main"}
        return subprocess.run(["bash", "-c", guard_script()], cwd=self.repo, env=env, capture_output=True, text=True)

    def test_a_tag_off_the_base_branch_or_a_pre_release_is_not_the_newest(self) -> None:
        self.git("tag", "v1.0.0", self.a)
        b = self.commit("b")
        self.git("tag", "v1.1.0-rc1", b)
        self.git("checkout", "-q", "-b", "other")
        self.git("tag", "v9.0.0", self.commit("x"))
        self.git("checkout", "-q", "main")
        result = self.guard(self.a, b)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("v1.0.0", result.stdout)

    def test_a_newer_release_tag_on_the_base_branch_must_be_pinned(self) -> None:
        self.git("tag", "v1.0.0", self.a)
        b = self.commit("b")
        self.git("tag", "v1.2.0", b)
        result = self.guard(self.a, b)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("v1.2.0", result.stdout)

    def test_a_tag_outside_the_pin_comment_shape_is_refused(self) -> None:
        self.git("tag", "v1.0.0.1", self.a)
        result = self.guard(self.a, self.a)
        self.assertNotEqual(result.returncode, 0)

    def test_no_release_tag_is_refused(self) -> None:
        result = self.guard(self.a, self.a)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("(none)", result.stdout)


if __name__ == "__main__":
    unittest.main()
