"""Tests for rules.py: every rule fires on its planted examples, stays quiet on the
look-alikes, and nothing ever hands back the matched text.

    python3 -m unittest discover -s .github/public-hygiene -t .github/public-hygiene

Token-shaped and key-shaped examples are assembled at run time from pieces, so that
this repository's secret scan does not read them as real credentials.
"""

from __future__ import annotations

import contextlib
import io
import string
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rules  # noqa: E402

ALNUM = string.ascii_letters + string.digits


def fake(prefix: str, length: int, alphabet: str = ALNUM) -> str:
    """A token-shaped string: `prefix` plus `length` varied characters."""
    return prefix + "".join(alphabet[(i * 7 + 3) % len(alphabet)] for i in range(length))


HEX = "0123456789abcdef"
DOMAIN = "distronode" + ".com"
G = "git" + "lab"

# rule id -> (texts that must fire it, texts that must not)
CASES: dict[str, tuple[list[str], list[str]]] = {
    "token": (
        [
            "token " + fake("gh" + "p_", 36),
            fake("github" + "_pat_", 60),
            "use " + fake("gl" + "pat-", 20),
            fake("sk" + "_live_", 24),
            fake("AK" + "IA", 16, string.ascii_uppercase + string.digits),
            fake("AI" + "za", 35),
            fake("xo" + "xb-", 24),
            fake("np" + "m_", 36),
            fake("sk-" + "ant-", 40),
            fake("SK", 32, HEX),
            fake("ey" + "J", 20) + "." + fake("ey" + "J", 20) + "." + fake("", 20),
            "-----BEGIN " + "RSA PRIVATE" + " KEY-----",
            "https://deploy:" + fake("", 12) + "@registry.example.org/x",
            "password=" + "Hunter2" + "Hunter9xyz",
            "api_key: " + fake("", 20),
            "DB_" + "PASSWORD=" + "Hunter2" + "Hunter9xyz",
            "--pass" + "word=" + "Hunter2" + "Hunter9xyz",
            "CLIENT_" + "SECRET: " + fake("", 24),
            "STRIPE_SECRET_" + "KEY=" + fake("", 24),
            '{"pass' + 'word": "' + "Hunter2" + 'Hunter9xyz"}',
            "postgres://app:" + "s3cr3tP4ss" + "w0rd@db.example.org/app",
        ],
        [
            "gh" + "p_" + "x" * 36,  # one repeated character: a fixture
            fake("AK" + "IA", 9, string.ascii_uppercase) + "EXAMPLE",  # the AWS docs key
            "it holds exactly the password: Simulator.app",
            "password: ${{ secrets.MATCH_PASSWORD }}",
            "a token was refreshed",
            "sk-short",
            "postgres://user:password@localhost/app",
            "redis://default:${REDIS_PASSWORD}@cache:6379",
            "amqp://guest:<password>@queue.example.org",
        ],
    ),
    "secret-name-gsm": (
        [
            "Both lanes read `APP_SENTRY_DSN` from GSM at build time.",
            "Stored in Secret Manager:\n- `STORE_CLIENT_SECRET`\n- `STORE_TENANT_ID`",
            "The source of truth is GSM `scheduler-us-env`.",
            "they go into `distronode" + "-env` on every origin",
        ],
        [
            "GSM-7 encoding counts 160 characters per SMS segment.",
            "GSM and LTE both carry the call.",
            "A secret manager such as 1Password holds it.",
            "Secret Manager is not involved.",
            "GSM\n\nAPI_KEY is unrelated, two paragraphs later.",
            "GSM\r\n\r\nAPI_KEY is unrelated, in a CRLF body.",
        ],
    ),
    "secret-name-list": (
        ["Needs `APPLE_API_KEY`, `MATCH_PASSWORD` and `PLAY_SERVICE_TOKEN`."],
        [
            "Needs `APPLE_API_KEY` and `MATCH_PASSWORD`.",
            "Uses GITHUB_TOKEN, GH_TOKEN and ACTIONS_RUNTIME_TOKEN.",
            "Error codes: INVALID_TOKEN, EXPIRED_TOKEN, MISSING_API_KEY.",
            "NEXT_PUBLIC_ZENDESK_KEY, NEXT_PUBLIC_HELPSCOUT_KEY, STRIPE_PUBLISHABLE_KEY",
            "MONKEY, TURKEY and DONKEY are not names.",
        ],
    ),
    "credential-health": (
        [
            "The push path is not verified in production.",
            "Not yet verified in prod.",
            "The key's expiry is not checked.",
            "The token's expiration date has never been verified.",
            "That API key is unrotated.",
            "The signing key has not been rotated since September.",
            "Seller id stored with `verified=false`.",
        ],
        [
            "The avatar image is not rotated on upload.",
            "The screen is never rotated in landscape.",
            "Verified in production on 3.2.0.",
            "The session token expires after an hour.",
        ],
    ),
    "iam-wif": (
        [
            "gcloud iam service-accounts create release-bot",
            "run add-iam-policy-binding on the secret",
            "set attribute.condition to the repository id",
            "projects/1/locations/global/workloadIdentityPools/gh",
            "member principalSet://iam.googleapis.com/x",
            "grant roles/secretmanager.secretAccessor",
            "impersonate release@corp-project.iam.gserviceaccount.com",
            "allow sts:AssumeRoleWithWebIdentity",
        ],
        [
            "the user roles/admin page",
            "Workload identity federation means no stored key.",
            "/workspace/roles/viewer is a route",
        ],
    ),
    "operator-command": (
        [
            "gcloud secrets versions access latest",
            "aws iam attach-role-policy --role-name x",
            "kubectl -n web set env deploy/web A=1",
            "kubectl rollout restart deploy/web",
            "mount it with envFrom",
            "gh secret set STORE_KEY",
            "wrangler secret put RELAY_KEY",
        ],
        [
            "kubectl get pods is read-only",
            "the aws region list",
            "GitHub secrets are encrypted.",
        ],
    ),
    "internal-email": (
        [
            "mail sean@" + DOMAIN,
            "QA ran as appqa@ on an iPhone",
            "contact ops@mail." + DOMAIN,
            "written as `review@` plus the company domain",
        ],
        [
            "opensource@" + DOMAIN,
            "Co-Authored-By: Claude <noreply@anthropic.com>",
            "ada@example.com",
            "cc @seandean",
            "pin `react@^18` and git@github.com:o/r.git",
            "the `PublishPipelineArtifact@` task",
        ],
    ),
    "private-path": (
        [
            "see /home/ops/wt/notes.md",
            "screenshots in /Users/sean/Desktop/",
            "C:\\Users\\sean\\AppData",
            "findings in `~/.cache/v3-tmp/qa/FINDINGS.md`",
            "keys in ~/.config/mcp/secrets.env",
            "per `distronode-website/k8s/aws-ca/deployment.yaml`",
            "see infra/scheduler/image-digest.env",
            "docs/district_windows.md says so",
            "telemetry-broadcaster/src/index.ts",
        ],
        [
            "/home/runner/work/x/x is the runner",
            "/home/user/.config/app and C:\\Users\\<name>\\AppData",
            "/home/xxx/project",
            "the cache lives in ~/.cache/district-ai",
            "mirrors `distronode-website/contracts/mobile/` byte for byte",
            "from distronode-website/src/lib/x.ts",
            "docs/store-listing.md in this repository",
        ],
    ),
    "machine-name": (
        [
            "Run locally on the ThinkPad with Gradle.",
            "The iMac session tripped the breaker.",
            "The ThinkPad manager reviewed it.",
            "handed to distronode-imac",
            "the session distronode-com-c4 owns it",
        ],
        [
            "Tested on an iMac with macOS 26.",
            "Latitude and longitude are both stored.",
            "the user distronode-com opened it",
        ],
    ),
    "ip-address": (
        [
            "the origin at 34.120.7.9",
            "trusts the pod CIDR 10.42.0.0/16",
            "egress from 192.168.4.20",
            "ssh deploy@34.120.7.9",
            "HOST=34.120.7.9",
            "--server=34.120.7.9",
            "LB -> 34.120.7.9",
            "tunnel 127.0.0.1 -> 10.0.0.5",
            "ingress \u2192 34.120.7.9",
            "the 34.120.7.9-prod box",
            "range 34.120.7.9-34.120.7.20",
            "v6 2600:1f18:abcd::1 answers",
        ],
        [
            "use 192.0.2.10 and 2001:db8::1 in examples",
            "listen on 127.0.0.1 and ::1",
            "version 3.0.1.4 ships",
            "jdom2 2.0.6 \u2192 2.0.6.1",
            "patch versions like 26.0.2.1+1",
            "ships 4.2.1.3-beta to testers",
            "1.2 -> 1.2.0.1",
            "failed on policy 10.1.1.3",
            "package 3.0.12.0 is signed",
            "resolve through 1.1.1.1",
            "at 12:30:45 UTC",
            "allow 0.0.0.0/0",
            "moves from 0.4.9.1 to 0.4.9.2",
            "requires lib==4.2.1.3",
            "999.10.10.10 is not an address",
            "it ships as 3.0.12.0",
            "2a::b::c is not an address",
            "fe80::1 is link-local",
        ],
    ),
    "private-gitlab": (
        [
            f"https://{G}.com/distronode-corporation/distronode-com/-/issues/2",
            f"{G}.com/distronode-corporation/secret-project",
        ],
        [
            f"https://{G}.com/distronode-corporation/district-ios",
            f"https://{G}.com/distronode-corporation/district-core-rust.git",
            f"The mirror is https://{G}.com/distronode-corporation/district-ios.",
            f"https://{G}.com/distronode-corporation",
            f"https://{G}.gnome.org/GNOME/gtk/-/issues/1",
        ],
    ),
    "private-reference": (
        [
            "approved (GitLab #2, note 4021983495)",
            "the web change (MR !102)",
            "per the decisions log",
            "distronode-com#2",
            "byte-equal to monorepo main ac4071d14",
            "Syncs to monorepo commit 46e1740a6",
        ],
        [
            "fixes #12 and closes #13",
            "a merge request on upstream",
            "the monorepo layout is described in CONTRIBUTING",
        ],
    ),
    "cloud-account-id": (
        [
            "arn:aws:iam::123456789012:role/x",
            "123456789012.dkr.ecr.ca-central-1.amazonaws.com",
            "projects/123456789/locations/global",
            "AWS account 123456789012",
            "in project `corp` (number 123456789012)",
            "the 1234-5678-9012 account",
            fake("acct" + "_", 16),
            fake("AC", 32, HEX),
        ],
        [
            "job 113638136978 passed",
            "https://github.com/o/r/pull/12#issuecomment-123456789012",
            "receipt 000000000001.json",
            "the project id is a string",
        ],
    ),
    "cloud-resource": (
        ["instance i-038f542bda0fa863e", "sg-0123456789abcdef0", "host distronode-web-us-east"],
        ["i-18n strings", "the web origin"],
    ),
    "internal-host": (
        [
            "https://llm.internal/v1",
            "redis.default.svc.cluster.local:6379",
            "talks to web.default.svc.cluster.local",
            "ssh admin@build-box.local",
            "reach db.corp:5432 first",
            "fetch from vault.lan/v1/kv",
            "https://origin-us." + DOMAIN + "/api",
        ],
        [
            "mode: .internal and KnowledgeMode.internal",
            "appsettings.local.json",
            "`self.local` and `config.internal` are fields",
            "at okhttp3.internal.http.RealInterceptorChain",
            "build-box.local in a sentence",
            "https://www." + DOMAIN + "/pricing",
            "originate." + DOMAIN,
        ],
    ),
}


class RuleCases(unittest.TestCase):
    def test_every_rule_has_positive_and_negative_cases(self) -> None:
        self.assertEqual(set(CASES), set(rules.RULES_BY_ID))
        for rule_id, (positive, negative) in CASES.items():
            self.assertTrue(positive, rule_id)
            self.assertTrue(negative, rule_id)

    def test_positive_cases_fire(self) -> None:
        for rule_id, (positive, _) in CASES.items():
            for text in positive:
                with self.subTest(rule=rule_id, case=positive.index(text)):
                    self.assertIn(rule_id, rules.rule_ids(text))

    def test_negative_cases_stay_quiet(self) -> None:
        for rule_id, (_, negative) in CASES.items():
            for text in negative:
                with self.subTest(rule=rule_id, case=negative.index(text)):
                    self.assertNotIn(rule_id, rules.rule_ids(text))

    def test_rule_ids_and_descriptions(self) -> None:
        for rule in rules.RULES:
            self.assertRegex(rule.id, r"^[a-z]+(?:-[a-z]+)*$")
            self.assertTrue(rule.description.endswith("."), rule.id)
            self.assertLess(len(rule.description), 200, rule.id)

    def test_invisible_characters_do_not_hide_a_match(self) -> None:
        self.assertIn("private-reference", rules.rule_ids("Git\u200bLab #2"))

    def test_public_urls_are_not_findings_but_tokens_in_them_are(self) -> None:
        self.assertEqual(rules.rule_ids("https://github.com/o/r/actions/runs/1/job/123456789012"), [])
        token = fake("gh" + "p_", 36)
        self.assertIn("token", rules.rule_ids(f"https://github.com/o/r?t={token}"))

    def test_long_adversarial_bodies_scan_in_linear_time(self) -> None:
        # GitHub caps a body at 65,536 characters. Each shape here once made a pattern
        # quadratic (minutes for one body); every one must now take well under a second.
        import time

        for unit in ("a-", "a.", ".", "eyJa.", "A_", "a@", "a://b@", "1.", "x@y."):
            text = (unit * (65536 // len(unit) + 1))[:65536]
            start = time.perf_counter()
            rules.scan(text)
            self.assertLess(time.perf_counter() - start, 3.0, unit)

    def test_empty_text(self) -> None:
        self.assertEqual(rules.scan(None), [])
        self.assertEqual(rules.scan(""), [])
        self.assertEqual(rules.rule_ids(None, ""), [])

    def test_skipped_authors_need_the_bot_type(self) -> None:
        self.assertTrue(rules.is_skipped_author("dependabot[bot]", "Bot"))
        self.assertFalse(rules.is_skipped_author("dependabot[bot]", "User"))
        for bot in ("sentry[bot]", "seer-by-sentry[bot]", "Copilot", "copilot-pull-request-reviewer[bot]"):
            self.assertTrue(rules.is_skipped_author(bot, "Bot"), bot)
        self.assertFalse(rules.is_skipped_author("Copilot", "User"))
        self.assertFalse(rules.is_skipped_author("someone[bot]", "Bot"))
        self.assertFalse(rules.is_skipped_author(None, None))


ALL_POSITIVES = [text for positive, _ in CASES.values() for text in positive]


def secret_parts(text: str) -> list[str]:
    """Every run of 6 or more characters that a finding covers, for the no-echo checks."""
    norm = rules.normalize(text)
    return [norm[f.start : f.end] for f in rules.scan(text) if f.end - f.start >= 6]


class NeverEchoes(unittest.TestCase):
    def test_finding_holds_no_text(self) -> None:
        for text in ALL_POSITIVES:
            for finding in rules.scan(text):
                shown = repr(finding) + str(finding)
                for part in secret_parts(text):
                    self.assertNotIn(part, shown)
                self.assertEqual(set(vars(finding)), {"rule", "start", "end"})

    def test_cli_prints_rule_ids_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "body.md"
            path.write_text("\n\n".join(ALL_POSITIVES), encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                status = rules._main([str(path)])
        self.assertEqual(status, 1)
        printed = out.getvalue() + err.getvalue()
        for text in ALL_POSITIVES:
            for part in secret_parts(text):
                self.assertNotIn(part, printed)
        for rule_id in rules.RULES_BY_ID:
            self.assertIn(rule_id, printed)

    def test_cli_clean_and_usage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "body.md"
            path.write_text("A clean body.", encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(rules._main([str(path)]), 0)
            self.assertIn("clean", out.getvalue())
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(rules._main([]), 2)
            self.assertEqual(rules._main(["--bogus"]), 2)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(rules._main(["--list"]), 0)
        for rule_id in rules.RULES_BY_ID:
            self.assertIn(f"`{rule_id}`", out.getvalue())


if __name__ == "__main__":
    unittest.main()
