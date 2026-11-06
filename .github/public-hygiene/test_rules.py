"""Tests for rules.py: every rule fires on its planted examples, stays quiet on the
look-alikes, and nothing ever hands back the matched text.

    python3 -m unittest discover -s .github/public-hygiene -t .github/public-hygiene

Every planted value is synthetic: made-up ids, names, paths and addresses of the right
shape, never a real one. Token-shaped and key-shaped examples are assembled at run time
from pieces, so that this repository's secret scan does not read them as credentials.
The organization's own terms are never written here: the `internal-name` tests hash
made-up terms into a temporary denylist.
"""

from __future__ import annotations

import contextlib
import io
import os
import string
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rules  # noqa: E402

ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
DOMAIN = "distronode" + ".com"
G = "git" + "lab"


def fake(prefix: str, length: int, alphabet: str = ALNUM) -> str:
    """A token-shaped string: `prefix` plus `length` varied characters."""
    return prefix + "".join(alphabet[(i * 7 + 3) % len(alphabet)] for i in range(length))


# rule id -> (texts that must fire it, texts that must not). `internal-name` is tested
# separately, against a made-up denylist.
CASES: dict[str, tuple[list[str], list[str]]] = {
    "token": (
        [
            "token " + fake("gh" + "p_", 36),
            fake("github" + "_pat_", 60),
            "use " + fake("gl" + "pat-", 20),
            fake("sk" + "_live_", 24),
            fake("AK" + "IA", 16, string.ascii_uppercase + string.digits),
            fake("AI" + "za", 35),
            "Authorization: Bearer " + fake("ya" + "29.", 40),
            "refresh " + fake("1//" + "0", 40),
            "license " + fake("", 36, HEX) + "NR" + "AL",
            fake("xo" + "xb-", 24),
            fake("np" + "m_", 36),
            fake("sk-" + "ant-", 40),
            fake("SK", 32, HEX),
            fake("ey" + "J", 20) + "." + fake("ey" + "J", 20) + "." + fake("", 20),
            "-----BEGIN " + "OPENSSH PRIVATE" + " KEY-----",
            "https://deploy:" + fake("", 12) + "@registry.example.org/x",
            "password=" + "Hunter2" + "Hunter9xyz",
            # A real value that merely contains a placeholder word is still a secret.
            "password=" + "there4" + "Real9xQ",
            "api_key: " + "Yourself7" + "Qz2kL",
            "token=" + "Sampled42" + "Lq9vZ",
            "password: " + "S3cure!" + "Pass#2041",
            "the demo account pass" + "word is " + "Zq8" + "rT2vLx9",
            "pw=" + "Kx92mLq" + "7ZtPq",
            "api_key: " + fake("", 20),
            "X_" + "TOKEN=" + fake("", 24),
            '{"to' + 'ken": "' + fake("", 24) + '"}',
            "DB_" + "PASSWORD=" + "Hunter2" + "Hunter9xyz",
            "--pass" + "word=" + "Hunter2" + "Hunter9xyz",
            "CLIENT_" + "SECRET: " + fake("", 24),
            "STRIPE_SECRET_" + "KEY=" + fake("", 24),
            '{"pass' + 'word": "' + "Hunter2" + 'Hunter9xyz"}',
            "postgres://app:" + "s3cr3tP4ss" + "w0rd@db.example.org/app",
            "redis://:" + "s3cr3tP4ss" + "w0rd@cache.example.org:6379",
            "curl -H 'Authorization: Bearer " + fake("", 40, HEX) + "'",
            "auth token " + fake("", 32, HEX),
        ],
        [
            "gh" + "p_" + "x" * 36,  # one repeated character: a fixture
            fake("AK" + "IA", 9, string.ascii_uppercase) + "EXAMPLE",  # the AWS docs key
            "it holds exactly the password: Simulator.app",
            "password: ${{ secrets.MATCH_PASSWORD }}",
            "the password: field is now masked",
            "api_key: YOUR_API_KEY_HERE_123",
            "token=YourTokenHere2041",
            "password: xxxxxxxx1234",
            "api_key: ${{ secrets.WIDGET_API_KEY }}",
            "a token was refreshed",
            "sk-short",
            "postgres://user:password@localhost/app",
            "redis://default:${REDIS_PASSWORD}@cache:6379",
            "redis://:password@cache:6379",
            "amqp://guest:<password>@queue.example.org",
        ],
    ),
    "secret-name-gsm": (
        [
            "Both lanes read `APP_SENTRY_DSN` from GSM at build time.",
            "Stored in Secret Manager:\n- `WIDGET_CLIENT_SECRET`\n- `WIDGET_TENANT_ID`",
            "stored in secret manager as `APPLE_API_KEY`",
            "The key lives in 1Password as STORE_SIGNING_KEY",
            "The source of truth is Secret Manager `booking-zz-env`.",
            "It reads the `booking-zz-env` secret at boot.",
        ],
        [
            "GSM-7 encoding counts 160 characters per SMS segment.",
            "GSM and LTE both carry the call.",
            "GSM codec: the decoder reads `frame-key` from the header.",
            "A secret manager such as 1Password holds it.",
            "Secret Manager is not involved.",
            "GSM\n\nAPI_KEY is unrelated, two paragraphs later.",
            "GSM\r\n\r\nAPI_KEY is unrelated, in a CRLF body.",
            "Uses forward-secret key exchange.",
            "Set the environment variables first.",
        ],
    ),
    "secret-name-list": (
        [
            "Needs `APPLE_API_KEY`, `MATCH_PASSWORD` and `PLAY_SERVICE_TOKEN`.",
            "Set RELAY_API_KEY_SECONDARY, WIDGET_SECRET_KEY_LIVE and STORE_API_KEY_NIGHTLY_SYNC.",
        ],
        [
            "Needs `APPLE_API_KEY` and `MATCH_PASSWORD`.",
            "Uses GITHUB_TOKEN, GH_TOKEN and ACTIONS_RUNTIME_TOKEN.",
            "Error codes: INVALID_TOKEN, EXPIRED_TOKEN, MISSING_API_KEY.",
            "NEXT_PUBLIC_ZENDESK_KEY, NEXT_PUBLIC_HELPSCOUT_KEY, STRIPE_PUBLISHABLE_KEY",
            "Handles APP_KEY_CODE, APP_KEY_DOWN and APP_TOKEN_TYPE.",
            "Adds DAILY_API_KEY, ZOOM_CLIENT_SECRET and SENDGRID_API_KEY to .env.example (upstream).",
            "MONKEY, TURKEY and DONKEY are not names.",
        ],
    ),
    "credential-health": (
        [
            "The push path is not verified in production.",
            "It isn't tested in prod yet.",
            "The new key hasn't been verified in production.",
            "The key's expiry is not checked.",
            "The token's expiration date has never been verified.",
            "That API key is unrotated.",
            "The signing key has not been rotated since September.",
            "We haven't rotated the token since the leak.",
            "Seller id `WIDGET_SELLER_ID` stored with `verified=false`.",
            "The old mail key is still live; rotation owed.",
            "The PAT expires 2041-12-01 and has no owner.",
        ],
        [
            "The avatar image is not rotated on upload.",
            "The screen is never rotated in landscape.",
            "When the screen is rotated the token field is not rotated with it.",
            "The unrotated image keeps its EXIF key.",
            "Implements key rotation; rotation is due every 90 days for user API keys.",
            "Verified in production on 3.2.0.",
            "The session token expires after an hour.",
            "Not tested on production hardware yet; CI only.",
            "Bug: the session cookie expiry is not checked before reuse.",
            "returns verified: false when the email is unconfirmed",
            "This endpoint is not verified against production yet, only staging.",
        ],
    ),
    "monitoring-gap": (
        [
            "The hosted relay has only the Acme uptime probe on /healthz.",
            "It runs with Workers Logs off.",
            "nothing reports its errors",
            "There is no alerting on the relay.",
        ],
        [
            "Crash reports are off by default.",
            "Logging is off in release builds.",
            "The uptime of the call is shown.",
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
            "aws ssm get-parameter --name /acme/prod/db",
            "kubectl -n web set env deploy/web A=1",
            "kubectl rollout restart deploy/web",
            "mount it with envFrom",
            "gh secret set STORE_KEY",
            "wrangler secret put RELAY_KEY",
            "--project=acme-prod-7",
        ],
        [
            "kubectl get pods is read-only",
            "the aws region list",
            "GitHub secrets are encrypted.",
            "You need the gcloud CLI installed locally.",
            "CI runs `gcloud firebase test android run` on Test Lab.",
            "Docs: aws sts get-caller-identity prints the account.",
            "tsc --project tsconfig.json",
        ],
    ),
    "internal-email": (
        [
            "mail jdoe@" + DOMAIN,
            "QA ran as appqa@ on an iPhone",
            "contact ops@mail." + DOMAIN,
            "written as `review@` plus the company domain",
        ],
        [
            "opensource@" + DOMAIN,
            "Co-Authored-By: Claude <noreply@anthropic.com>",
            "ada@example.com",
            "cc @someone",
            "pin `react@^18` and git@github.com:o/r.git",
            "the `PublishPipelineArtifact@` task",
            "Use `outer@ for (row in rows)` and `break@outer` to exit.",
        ],
    ),
    "private-path": (
        [
            "see /home/ops/wt/notes.md",
            "screenshots in /Users/pat/Desktop/",
            "C:\\Users\\pat\\AppData",
            "findings in `~/.cache/tool-x/qa/notes.md`",
            "keys in ~/.config/mcp/settings.env",
            "keys in /root/.config/gcloud/",
            "the key ~/.ssh/district_deploy",  # the app-cache exception is for the cache only
            "per monorepo `docs/some_contract.md`",
            "see the monorepo's infra/README.md",
        ],
        [
            "/home/runner/work/x/x is the runner",
            "/home/user/.config/app and C:\\Users\\<name>\\AppData",
            "/home/xxx/project",
            "the cache lives in ~/.cache/district-ai",
            "docs/store-listing.md in this repository",
            "This crate used to live in a monorepo branch upstream.",
        ],
    ),
    "ip-address": (
        [
            "the origin at 34.120.7.9",
            "trusts the pod CIDR 10.77.0.0/16",
            "egress from 192.168.4.20",
            "the CIDR 10.0.0.0 range",
            "gateway 172.16.4.0",
            "ssh deploy@34.120.7.9",
            "HOST=34.120.7.9",
            "--server=34.120.7.9",
            "LB -> 34.120.7.9",
            "tunnel 127.0.0.1 -> 10.0.0.5",
            "ingress " + rules.ARROW + " 34.120.7.9",
            "the 34.120.7.9-prod box",
            "range 34.120.7.9-34.120.7.20",
            "Upgrade from 34.110.20.30 to 34.110.20.31",
            "[34.110.20.30] and 34.110.20.30:443",
            "v6 2600:1f18:abcd::1 answers",
        ],
        [
            "use 192.0.2.10 and 2001:db8::1 in examples",
            "listen on 127.0.0.1 and ::1",
            "version 3.0.1.4 ships",
            "jdom2 2.0.6 " + rules.ARROW + " 2.0.6.1",
            "patch versions like 26.0.2.1+1",
            "ships 4.2.1.3-beta to testers",
            "1.2 -> 1.2.0.1",
            "failed on policy 10.1.1.3",
            "package 3.0.12.0 is signed",
            "Bumps sqlcipher from 4.6.1.2 to 4.6.1.3.",
            'AssemblyVersion("3.1.4.2") now matches',
            "resolve through 1.1.1.1 or 2606:4700:4700::1111",
            "the standard range 100.64.0.0/10",
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
            f"https://{G}.com/distronode-corporation/secret-project/-/issues/2",
            f"{G}.com/distronode-corporation/secret-project",
            f"git@{G}.com:distronode-corporation/secret-project.git",
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
            "approved (GitLab #7, note 1234509876)",
            "decided in #7 note 1234509876",
            "the web change (MR !102)",
            "GitLab issue 7 has the decision",
            "tracked in confidential #240",
            "byte-equal to monorepo main abc1234de",
            "Syncs to monorepo commit 0fedcba98",
        ],
        [
            "fixes #12 and closes #13",
            "a merge request on upstream",
            "the monorepo layout is described in CONTRIBUTING",
            "Fixed upstream in GNOME GitLab !1234, and the MR !77 in libadwaita.",
            "See note 12345678 in the spec appendix.",
        ],
    ),
    "cloud-account-id": (
        [
            "arn:aws:iam::123456789012:role/x",
            "123456789012.dkr.ecr.ca-central-1.amazonaws.com",
            "projects/123456789/locations/global",
            "Poll `/projects/12345678/pipelines/1/bridges`.",
            "AWS account 123456789012",
            "the 111122223333 account",
            "NR account 7654321, EU region",
            "accountId=7654321",
            "GitLab project 12345678",
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
    "console-link": (
        [
            "https://console.cloud.google.com/security/secret-manager?project=acme-prod-7",
            "https://us-east-1.console.aws.amazon.com/ec2/home",
            "https://one.eu.newrelic.com/nr1-core?account=7654321",
            "dash.cloudflare.com/" + fake("", 32, HEX) + "/workers",
            "https://" + fake("", 32, HEX) + "@o4508123456789.ingest.de.sentry.io/1",
        ],
        [
            "https://sentry.io and https://docs.sentry.io/platforms/",
            "the Google Cloud console",
        ],
    ),
    "cloud-resource": (
        ["instance i-0f1e2d3c4b5a69788", "sg-0123456789abcdef0", "old-style i-0123abcd"],
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
            "postgres.acme.svc:5432",
        ],
        [
            "mode: .internal and KnowledgeMode.internal",
            "appsettings.local.json",
            "`self.local` and `config.internal` are fields",
            "at okhttp3.internal.http.RealInterceptorChain",
            "build-box.local in a sentence",
            "https://www." + DOMAIN + "/pricing",
        ],
    ),
}

# Made-up organization terms for the `internal-name` tests: (term, text that must fire).
FAKE_TERMS = [
    ("acme-vault-env", "mounts the acme-vault-env Secret"),
    ("acme-origin", "the host acme-origin-zz-test answers"),
    ("origin.acme.example", "dial origin-zz.acme.example directly"),
    ("toolbox/deploy", "see toolbox/deploy/run.sh"),
    ("toolbox/deploy", "see /toolbox/deploy/run.sh"),
    ("toolbox/deploy", "see https://code.example.org/toolbox/deploy/run.sh"),
    ("notes/ops_", "per notes/ops_runbook.md"),
    ("acme-com-c#", "the session acme-com-c12 owns it"),
    ("lab manager", "the lab manager reviewed it"),
    ("'s laptop9", "run it on Pat's laptop9 first"),
    ("'s laptop9", "run it on Pat" + chr(0x2019) + "s laptop9 first"),
    ("on the laptop9", "built on the laptop9 last night"),
    ("acme-com#", "decided in acme-com#7"),
    ("9876543210", "account 9876543210 holds it"),
]
FAKE_QUIET = [
    "the lab reviewed it",
    "the manager reviewed it",
    "acme-com opened it",
    "a laptop9 user",
]


class RuleCases(unittest.TestCase):
    def test_every_rule_has_positive_and_negative_cases(self) -> None:
        self.assertEqual(set(CASES) | {"internal-name"}, set(rules.RULES_BY_ID))
        for rule_id, (positive, negative) in CASES.items():
            self.assertTrue(positive, rule_id)
            self.assertTrue(negative, rule_id)

    def test_positive_cases_fire(self) -> None:
        for rule_id, (positive, _) in CASES.items():
            for i, text in enumerate(positive):
                with self.subTest(rule=rule_id, case=i):
                    self.assertIn(rule_id, rules.rule_ids(text))

    def test_negative_cases_stay_quiet(self) -> None:
        for rule_id, (_, negative) in CASES.items():
            for i, text in enumerate(negative):
                with self.subTest(rule=rule_id, case=i):
                    self.assertNotIn(rule_id, rules.rule_ids(text))

    def test_rule_ids_and_descriptions(self) -> None:
        for rule in rules.RULES:
            self.assertRegex(rule.id, r"^[a-z]+(?:-[a-z]+)*$")
            self.assertTrue(rule.description.endswith("."), rule.id)
            self.assertLess(len(rule.description), 220, rule.id)

    def test_format_characters_do_not_hide_a_match(self) -> None:
        # Category Cf, and (F10) the other default-ignorable characters and the blank
        # braille pattern.
        for ch in (0x200B, 0x2063, 0x202E, 0x00AD, 0xFEFF, 0x34F, 0xFE0F, 0x180B, 0xE0100, 0x3164, 0xFFA0, 0x115F, 0x2800):
            with self.subTest(char=hex(ch)):
                self.assertIn("private-reference", rules.rule_ids("Git" + chr(ch) + "Lab #5"))

    def test_public_urls_are_not_findings_but_tokens_in_them_are(self) -> None:
        self.assertEqual(rules.rule_ids("https://github.com/o/r/actions/runs/1/job/123456789012"), [])
        token = fake("gh" + "p_", 36)
        self.assertIn("token", rules.rule_ids(f"https://github.com/o/r?t={token}"))

    def test_outside_authors_are_checked_for_credentials_only(self) -> None:
        crash_log = "Crash log at /home/jdoe/.local/share/x/log.txt, ICE candidate 192.168.1.20"
        self.assertTrue(rules.rule_ids(crash_log))
        self.assertEqual(rules.rule_ids(crash_log, outside=True), [])
        token = "token " + fake("gh" + "p_", 36)
        self.assertEqual(rules.rule_ids(token, outside=True), ["token"])
        self.assertTrue(rules.is_outside_author("NONE", "User"))
        self.assertTrue(rules.is_outside_author("CONTRIBUTOR", "User"))
        self.assertFalse(rules.is_outside_author("MEMBER", "User"))
        self.assertFalse(rules.is_outside_author("NONE", "Bot"))
        self.assertFalse(rules.is_outside_author(None, "User"))

    def test_empty_text(self) -> None:
        self.assertEqual(rules.scan(None), [])
        self.assertEqual(rules.scan(""), [])
        self.assertEqual(rules.rule_ids(None, ""), [])

    def test_skipped_authors_are_upstream_and_review_bots_only(self) -> None:
        for bot in ("dependabot[bot]", "renovate[bot]", "sentry[bot]", "seer-by-sentry[bot]", "Copilot", "copilot-pull-request-reviewer[bot]"):
            self.assertTrue(rules.is_skipped_author(bot, "Bot"), bot)
            self.assertFalse(rules.is_skipped_author(bot, "User"), bot)  # a person named like a bot
        for bot in ("github-actions[bot]", "some-ci[bot]"):
            self.assertFalse(rules.is_skipped_author(bot, "Bot"), bot)
        # F9: review bots are skipped for comments only; their titles, descriptions and
        # commits are checked.
        for bot in ("sentry[bot]", "Copilot"):
            self.assertFalse(rules.is_skipped_author(bot, "Bot", comment=False), bot)
        self.assertTrue(rules.is_skipped_author("dependabot[bot]", "Bot", comment=False))
        self.assertFalse(rules.is_skipped_author(None, None))


TEST_KEY = bytes(range(32))  # a made-up key, for these tests only


class InternalNames(unittest.TestCase):
    def setUp(self) -> None:
        for name, value in (
            ("DENYLIST_KEY", TEST_KEY),
            ("DENYLIST", frozenset(rules.term_hash(t, TEST_KEY) for t, _ in FAKE_TERMS)),
            ("CANARY", rules.term_hash(rules.CANARY_TERM, TEST_KEY)),
        ):
            patcher = mock.patch.object(rules, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_each_term_fires_in_context(self) -> None:
        for term, text in FAKE_TERMS:
            with self.subTest(term=term, text=text):
                self.assertIn("internal-name", rules.rule_ids(text))

    def test_look_alikes_stay_quiet(self) -> None:
        for text in FAKE_QUIET:
            with self.subTest(text=text):
                self.assertNotIn("internal-name", rules.rule_ids(text))

    def test_case_and_format_characters_do_not_matter(self) -> None:
        self.assertIn("internal-name", rules.rule_ids("mounts the ACME-VAULT-ENV Secret"))
        self.assertIn("internal-name", rules.rule_ids("mounts the acme-vault" + chr(0x200B) + "-env Secret"))

    def test_empty_denylist_finds_nothing(self) -> None:
        with mock.patch.object(rules, "DENYLIST", frozenset()):
            self.assertFalse(rules.internal_names_enabled())
            self.assertNotIn("internal-name", rules.rule_ids(FAKE_TERMS[0][1]))

    def test_no_key_skips_this_rule_only(self) -> None:
        text = FAKE_TERMS[0][1] + " from 34.120.7.9"
        with mock.patch.object(rules, "DENYLIST_KEY", b""):
            self.assertFalse(rules.internal_names_enabled())
            without = rules.rule_ids(text)
        self.assertNotIn("internal-name", without)
        self.assertIn("ip-address", without)
        self.assertEqual(rules.rule_ids(text), sorted(without + ["internal-name"]))

    def test_a_different_key_matches_nothing_and_says_so(self) -> None:
        with mock.patch.object(rules, "DENYLIST_KEY", bytes(32)):
            self.assertFalse(rules.internal_names_enabled())  # the canary does not match
            self.assertNotIn("internal-name", rules.rule_ids(FAKE_TERMS[0][1]))
        with mock.patch.object(rules, "CANARY", ""):
            self.assertFalse(rules.internal_names_enabled())

    def test_keys_in_hex_or_text(self) -> None:
        self.assertEqual(rules._key_bytes(" 00ff \n"), bytes([0, 255]))
        self.assertEqual(rules._key_bytes("not hex"), b"not hex")


class Denylist(unittest.TestCase):
    def test_the_committed_list_is_hashes_only(self) -> None:
        path = rules.HERE / "denylist.txt"
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")]
        canary = [line for line in lines if line.startswith("canary:")]
        terms = [line for line in lines if not line.startswith("canary:")]
        self.assertEqual(len(canary), 1)
        self.assertRegex(canary[0], rf"^canary:[0-9a-f]{{{rules.DIGEST_CHARS}}}$")
        self.assertGreater(len(terms), 50)
        for line in terms:
            self.assertRegex(line, rf"^[0-9a-f]{{{rules.DIGEST_CHARS}}}$")
        self.assertEqual(len(terms), len(set(terms)))
        self.assertEqual(rules.load_denylist(path), frozenset(terms))
        self.assertEqual(rules.load_canary(path), canary[0][len("canary:"):])

    def test_hash_terms_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plain = Path(tmp) / "terms.txt"
            plain.write_text("# a comment\nAcme-Vault-Env\n\n", encoding="utf-8")
            keyfile = Path(tmp) / "key"
            keyfile.write_text(TEST_KEY.hex() + "\n", encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(rules._main(["--hash-terms", str(plain), "--key-file", str(keyfile)]), 0)
            self.assertEqual(out.getvalue().split(), ["canary:" + rules.term_hash(rules.CANARY_TERM, TEST_KEY), rules.term_hash("acme-vault-env", TEST_KEY)])
            self.assertNotIn("acme", out.getvalue().lower())
            self.assertNotIn(TEST_KEY.hex(), out.getvalue())
            keyfile.write_text("0011", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(rules._main(["--hash-terms", str(plain), "--key-file", str(keyfile)]), 2)

    def test_missing_file_is_an_empty_list(self) -> None:
        self.assertEqual(rules.load_denylist(Path("/nonexistent/denylist.txt")), frozenset())
        self.assertEqual(rules.load_canary(Path("/nonexistent/denylist.txt")), "")


class Limits(unittest.TestCase):
    # About 20 s; the per-event self-test skips it (the repository's own CI runs it).
    @unittest.skipIf(os.environ.get("PUBLIC_HYGIENE_SKIP_SLOW") == "1", "slow; run in CI")
    def test_long_adversarial_bodies_scan_in_linear_time(self) -> None:
        # GitHub caps a body at 65,536 characters. Each shape here once made a pattern
        # quadratic (seconds to minutes for one body); each must now take well under that.
        units = ("a-", "a.", ".", "eyJa.", "A_", "a@", "a://b@", "1.", "x@y.", "1-", "i-0", "sk-a",
                 "kubectl -n ", "-n kubectl ", "kubectl --context=a ", "a/", "a's ", "a#1 ")
        shapes = [(unit * (65536 // len(unit) + 1))[:65536] for unit in units]
        # A keyword, then a long run of whitespace: adjacent `\s*` once backtracked.
        shapes += [(kw + ws * 65536)[:65536] for kw in ("gitlab", "project number", "gcloud iam") for ws in (" ", "\n")]
        # NFKC expansion: U+FDFA is 18 characters after NFKC.
        shapes.append(chr(0xFDFA) * 65536)
        for text in shapes:
            start = time.perf_counter()
            rules.scan(text)
            self.assertLess(time.perf_counter() - start, 4.0, repr(text[:12]))

    def test_combining_mark_runs_normalize_in_linear_time(self) -> None:
        # F13: CPython 3.12, the runner's, reorders a run of combining marks in quadratic
        # time inside NFKC (6 s for this text before the cap on mark runs).
        text = "a" + chr(0x301) * 32_768 + chr(0x316) * 32_768
        start = time.perf_counter()
        rules.scan(text, outside=True)
        self.assertLess(time.perf_counter() - start, 1.0)
        self.assertLessEqual(len(rules.normalize(text)), 1 + rules.MAX_MARK_RUN)

    def test_mark_runs_are_capped_but_ordinary_accents_kept(self) -> None:
        self.assertEqual(rules.normalize("e" + chr(0x301)), "\u00e9")
        self.assertEqual(rules.rule_ids("Git" + chr(0x301) * 40 + "Lab #5"), rules.rule_ids("Git" + chr(0x301) * 30 + "Lab #5"))

    @unittest.skipIf(os.environ.get("PUBLIC_HYGIENE_SKIP_SLOW") == "1", "slow; run in CI")
    def test_findings_among_many_public_urls_scan_in_linear_time(self) -> None:
        # F14: the public-URL filter was findings times URLs.
        half = rules.MAX_SCAN_CHARS // 2
        text = "dev@ " * (half // 5) + "http://github.com/ " * (half // 19)
        start = time.perf_counter()
        rules.scan(text)
        self.assertLess(time.perf_counter() - start, 2.5)

    def test_inside_is_a_binary_search_with_the_same_answers(self) -> None:
        ranges = [(0, 5), (10, 20), (30, 31)]
        starts = [a for a, _ in ranges]
        for span, want in (((0, 5), True), ((11, 19), True), ((4, 11), False), ((25, 26), False), ((30, 31), True), ((31, 32), False)):
            self.assertEqual(rules._inside(span, ranges, starts), want, span)
        self.assertFalse(rules._inside((1, 2), [], []))

    def test_a_cut_after_nfkc_is_reported(self) -> None:
        # F4: U+FB00 folds to two characters, so a text under the cap can be cut after NFKC.
        self.assertTrue(rules.was_truncated(chr(0xFB00) * 75_100 + " from 10.20.30.40"))
        self.assertFalse(rules.was_truncated(chr(0xFB00) * 1_000))

    def test_expansion_is_not_folded_and_long_text_is_capped(self) -> None:
        self.assertEqual(rules.normalize(chr(0xFDFA) * 100), chr(0xFDFA) * 100)
        long_text = "a " * rules.MAX_SCAN_CHARS
        self.assertEqual(len(rules.normalize(long_text)), rules.MAX_SCAN_CHARS)
        self.assertTrue(rules.was_truncated(long_text))
        self.assertFalse(rules.was_truncated("short"))
        self.assertFalse(rules.was_truncated(None))


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
        for rule_id in CASES:
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
