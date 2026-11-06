"""Tests for the `token` rule's placeholder and reference logic: real values that look a
little like placeholders still fire, and placeholders, templates, masks and code
references stay quiet. Carried over from the independent review of the follow-up to #9,
plus the branches it found unpinned and the Go, PHP and camelCase keys.

Every value is synthetic and assembled from pieces, like test_rules.py's.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rules  # noqa: E402

J = "".join


class Case(unittest.TestCase):
    def fire(self, texts: list[str]) -> None:
        for text in texts:
            with self.subTest(text=text):
                self.assertIn("token", rules.rule_ids(text))

    def quiet(self, texts: list[str]) -> None:
        for text in texts:
            with self.subTest(text=text):
                self.assertNotIn("token", rules.rule_ids(text))


class R1ReferenceWordCaseAndAccess(Case):
    """Finding 2: TEMPLATE_PREFIX is case-insensitive and any `.`, `(`, `[` after the word
    counts, so a human password that starts with a reference word is skipped."""

    def test_real_values_fire(self) -> None:
        self.fire([
            J(["password=", "Github", ".Prod2041"]),
            J(["password=", "GITHUB", ".Prod2041x"]),
            J(["password=", "Github(", "2041)xQ"]),
            J(["password=", "Github[", "2041]xQz"]),
            J(["password=", "Steps.", "Kx92mLq7"]),
            J(["password=", "Inputs.", "Kx92mLq7"]),
            J(["password=", "Correct.Horse.", "Github.2041"]),
            J(["password=", "Kx92mLq7.", "github"]),
            J(['{"password": "', "Github.", 'Prod2041"}']),
            J(["password=", chr(0x131) + "nputs.", "Kx92mLq7"]),  # a dotless i folds to i under IGNORECASE
        ])

    def test_code_references_stay_quiet(self) -> None:
        self.quiet([
            "token=secrets.WIDGET_TOKEN_2",
            "apiKey: process.env.WIDGET_API_KEY_2",
            'apiKey: process.env["WIDGET_API_KEY_2"]',
            "api_key=os.environ['WIDGET_API_KEY_2']",
            "api_key = os.environ.get('KEY_2')",
            'password = os.getenv("DB_PASSWORD_2")',
            'token = os.Getenv("WIDGET_TOKEN_2")',
            'password = System.getenv("DB_PASSWORD_2")',
            "password = ENV['DB_PASSWORD_2']",
            "password = ENV.fetch('DB_PASSWORD_2')",
            'token = Deno.env.get("TOKEN_2")',
            'api_key = st.secrets["widget_key_2"]',
            "token: inputs.github-token-2",
            "token: steps.app2.outputs.token",
            "password: env.DB_PASSWORD_V2",
            "token: needs.build2.outputs.token",
            "password: vault:secret/data/app#db2",
        ])


class R2PlaceholderCharacters(Case):
    """Finding 1: one `$ % * { }` anywhere in a value marks it a placeholder, in the
    assignment path and in a URL's user info."""

    def test_real_values_fire(self) -> None:
        self.fire([
            J(["password=", "Kx9$m", "Lq7ZtPq2"]),
            J(["password=", "Kx9%m", "Lq7ZtPq2"]),
            J(["password=", "Kx9*m", "Lq7ZtPq2"]),
            J(["password=", "Kx9{m", "Lq7ZtPq2"]),
            J(["password=", "q7!Zr", "$2mK#9pLx&"]),
            J(["token=", "AbCd%2BEf", "Gh12%2F34xQ"]),
            J(["https://api.example.org/v1?access_token=", "AbCd%2BEf", "Gh12%2F34xQ"]),
            J(["postgres://app:", "Kx92%40m", "Lq7ZtPq@db.example.org/app"]),
            J(["postgres://app:", "Kx92$m", "Lq7ZtPq@db.example.org/app"]),
        ])

    def test_templates_and_masks_stay_quiet(self) -> None:
        self.quiet([
            "token=${{secrets.WIDGET_TOKEN_2}}",
            "token=${WIDGET_TOKEN_2}",
            "password: $DB_PASSWORD_2",
            "password=%DB_PASSWORD_2%",
            'token: "{{ .Values.token2 }}"',
            "token: ****1234abcd",
            "password={db_password_2}",
            "password: '%(db_password_2)s'",
            "token=$(gh auth token2)",
            "redis://default:${REDIS_PASSWORD}@cache:6379",
            "amqp://guest:<password>@queue.example.org",
            "postgres://u:$DB_PASSWORD@db.example.org/app",
        ])


class R3WholeWordResidue(Case):
    """Finding 3: one whole placeholder word anywhere skips the value, whatever else it holds."""

    def test_real_values_fire(self) -> None:
        self.fire([
            J(["token=", "Sample42", "Lq9vZ"]),
            J(["token=", "Kx9Here", "2mLq7Z"]),
            J(["password=", "Your", "Mom2041Kx!"]),
            J(["password=", "Insert", "2041Coin!"]),
            J(["password=", "Replace", "9xKq2Lm"]),
            J(["api_key: ", "Example", "9xKq2Lm7"]),
            J(["token=", "Kx92-XXXX", "-mLq7ZtPq"]),
            J(["Authorization: Bearer ", "AbCdEf12", "Here", "9xKqLmZt3Pq7Wv"]),
        ])


class R4ConcatenatedPlaceholders(Case):
    """Finding 4: placeholder words run together (no case or separator boundary) and the
    `changeme` family are no longer read as placeholders."""

    def test_placeholders_stay_quiet(self) -> None:
        self.quiet([
            "token=YOURTOKENHERE2041",
            "api_key=yourapikeyhere2041",
            "API_KEY=pasteyourkeyhere123",
            "token=dummytoken1234",
            "token=exampletoken1234",
            "password=ChangeMe2041",
            "password=change_me_2041",
            "password=changeit123",
            "api_key: YOUR_API_KEY_HERE_123",
            "token=YourTokenHere2041",
            "password=replace-me-2041",
            "token=TODO-add-token-2",
        ])


class R5TestsThatPinTheBranches(Case):
    """Finding 5: the branches the committed tests leave unpinned (each survives removal)."""

    def test_xxxx_branch(self) -> None:
        # `xxxxxxxx1234` has 5 distinct characters, so it is quiet without the xxxx branch;
        # this one has 13.
        self.quiet(["token=xxxx-" + "1234-5678-90ab"])

    def test_environ_getenv_with_a_digit(self) -> None:
        # The committed `os.environ.get` / `os.getenv(` cases have no digit, so they are
        # quiet without the reference words. A quoted name does not help either: the quote
        # ends the value (`os.getenv(`), so only an unquoted name carries a digit into it.
        self.quiet(["password = os.environ.get(DB_PASSWORD_2)", "password = getenv(DB_PASSWORD_2)"])

    def test_index_and_call_accesses(self) -> None:
        self.quiet(["api_key=os.environ[WIDGET_API_KEY_2]", "apiKey: process.env[WIDGET_API_KEY_2]"])




class R5MoreBranches(Case):
    """Finding 5, continued: each reference branch decides at least one case."""

    def test_the_end_of_value_alternative_is_gone(self) -> None:
        # A value that ends with a reference word was skipped; it is a value.
        self.fire([J(["password=", "Kx92mLq7.", "github"]), J(["password=", "Kx92mLq7.", "env"])])

    def test_each_reference_word_needs_a_name_after_the_dot(self) -> None:
        for word in ("secrets", "vars", "env", "inputs", "steps", "needs", "github"):
            with self.subTest(word=word):
                self.quiet([f"token: {word}.WIDGET_TOKEN_2"])
                self.fire([J(["password=", word.capitalize(), ".Prod2041x"])])


class EmbeddedPlaceholderShapes(Case):
    """Seer on the follow-up: a template span or `CHANGE_ME` inside a value with enough
    else in it is a value, not a placeholder."""

    def test_real_values_with_an_embedded_shape_fire(self) -> None:
        self.fire([
            J(["password=", "Kx9{name}", "Lq7ZtPq2"]),
            J(["token=", "Kx92changeme", "Lq7ZtPqW"]),
            J(["password=", "Kx92change_it", "Lq7ZtPq"]),
            J(["password=", "Kx92%NAME%", "Lq7ZtPqWm"]),
            J(["password=", "Kx92${a}", "Lq7ZtPqW"]),
        ])

    def test_values_that_are_mostly_a_template_stay_quiet(self) -> None:
        self.quiet([
            "token=${WIDGET_TOKEN_2}",
            "token=prefix-${WIDGET_TOKEN_2}",
            "password=change_me_2041",
            "password=ChangeMe2041",
            "token: ****1234abcd",
        ])


class GoPhpAndCamelCaseKeys(Case):
    """O1: Go's `:=`, PHP's `=>` and camelCase keys reach the realness test, both ways."""

    def test_real_values_fire(self) -> None:
        v = J(["Kx92m", "Lq7ZtPq"])
        self.fire([
            f'token := "{v}"',
            f'password := "{v}"',
            f'"token" => "{v}"',
            f"'api_key' => '{v}'",
            f"clientSecret: {v}",
            f'dbPassword = "{v}"',
            f"refreshToken: {v}",
            f"githubToken: {v}",
            f"secretKey={v}",
            f"privateKey := {v}",
            f'"clientSecret": "{v}"',
            f"signingKey => {v}",
        ])

    def test_placeholders_and_references_stay_quiet(self) -> None:
        self.quiet([
            'token := os.Getenv("WIDGET_TOKEN_2")',
            "'api_key' => env.WIDGET_API_KEY_2",
            "clientSecret: process.env.CLIENT_SECRET_2",
            "dbPassword = YOUR_DB_PASSWORD_HERE_2",
            "refreshToken: ${{ secrets.REFRESH_TOKEN_2 }}",
        ])

    def test_not_keys(self) -> None:
        v = J(["Kx92m", "Lq7ZtPq"])
        self.quiet([f"publicKey: {v}", f"monkey: {v}", f"clientId: {v}", f"keyboard: {v}", f"tokenizer := {v}"])


class CodePathsStayFlagged(Case):
    """O2, decided: a code path through an arbitrary object stays a finding. Any rule that
    quiets `settings.S3_KEY_2` would also quiet a `summer.winter2041` password."""

    def test_code_paths_fire(self) -> None:
        self.fire([
            "api_key = settings.AWS_S3_SECRET_KEY_2",
            "token = config.OPENAI_API_KEY_V2",
            "password = Rails.application.credentials.db_password_2",
        ])


if __name__ == "__main__":
    unittest.main()
