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

    def test_an_unclosed_opener_is_a_value_unless_the_value_was_cut(self) -> None:
        # Seer: an opener with no closer used to count as a template to the end of the
        # value, so `$(...` at the start of a real secret hid it.
        self.fire([
            J(["password=", "$(Kx92m", "Lq7ZtPqW"]),
            J(["token=", "${Kx92m", "Lq7ZtPqW"]),
            J(["password=", "%(Kx92m", "Lq7ZtPqW"]),
            J(["password=", "{{Kx92m", "Lq7ZtPqW"]),
        ])
        # Cut at a space or a closing parenthesis: the closer is just beyond the value.
        self.quiet(["token=$(gh auth token2)", 'token: "{{ .Values.token2 }}"', "password: '%(db_password_2)s'"])
        # Seer round 2: a real secret with an unclosed opener, then a space, a quote or a
        # line end, is still a value: no closer follows.
        self.fire([
            J(["password=", "$(Kx92m", "Lq7ZtPqW", " and more text"]),
            J(['token: "', "${Kx92m", 'Lq7ZtPqW"']),
            J(["password=", "{{Kx92m", "Lq7ZtPqW", "\nnext line }}"]),  # the closer is on another line
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
            f'$clientSecret = "{v}"',  # PHP and PowerShell variables
            f"$dbPassword = '{v}'",
            f'$refreshToken := "{v}"',
        ])

    def test_placeholders_and_references_stay_quiet(self) -> None:
        self.quiet([
            'token := os.Getenv("WIDGET_TOKEN_2")',
            "'api_key' => env.WIDGET_API_KEY_2",
            "clientSecret: process.env.CLIENT_SECRET_2",
            "dbPassword = YOUR_DB_PASSWORD_HERE_2",
            "refreshToken: ${{ secrets.REFRESH_TOKEN_2 }}",
            "$clientSecret = getenv(CLIENT_SECRET_2)",
            "$dbPassword = $env:DB_PASSWORD_2",
        ])

    def test_not_keys(self) -> None:
        v = J(["Kx92m", "Lq7ZtPq"])
        self.quiet([f"publicKey: {v}", f"monkey: {v}", f"clientId: {v}", f"keyboard: {v}", f"tokenizer := {v}"])


class ReviewOfTheCutTemplate(Case):
    """The independent review of the cut-template change and Seer round 3: each test pins
    one fix, both ways."""

    def test_a_cut_counts_only_when_the_tail_closes_that_opener(self) -> None:
        # The tail must close the template before any quote or backtick, as one closed
        # span with no second opener of its kind, and only that opener is credited.
        v = J(["Kx92m", "Lq7ZtPqW"])
        self.fire([
            '{"password": "${' + v + '"}',
            '{"password":"Ab${' + v + '","user":"x"}',
            'password="q7$(' + J(["Lm2vR9", "xT4kP8w"]) + '" (rotated)',
            "Set `DB_PASSWORD=q7$(" + J(["Lm2vR9", "xT4kP8w"]) + "` in the env (see [docs](https://x.example))",
            "password=${" + v + "$(x more)",
            "password: {{" + v + " # see {{ docs }}",
        ])
        self.quiet([
            "token=$(gh auth token2)",
            "password: {% raw %}{{ db_password2 }}{% endraw %}",
            "password=$(openssl rand -hex 32)",
        ])

    def test_variable_references_stay_quiet(self) -> None:
        self.quiet([
            "$password = $env:DB_PASSWORD_2",
            "password: $env:DB_PASSWORD2",
            "$dbPassword = $dbPassword2;",
            "postgres://app:$dbPassword2@localhost/db",
            "password=%DbPassword2%",
        ])
        # A `$` in front of a value is not a variable unless the rest reads as one.
        self.fire([J(["password=$", "Kx92m", "Lq7ZtPqW"]), J(["password=$", "kx92m", "Lq7ZtPqW"])])

    def test_pascal_case_keys(self) -> None:
        v = J(["Kx92m", "Lq7ZtPq"])
        self.fire([
            f"ClientSecret: {v}",
            f"DbPassword = {v}",
            f"RefreshToken={v}",
            f"JwtSecret: {v}",
            f"WebhookSecret: {v}",
            f"AdminPassword: {v}",
            f'$ClientSecret = "{v}"',
            f'{{"ClientSecret": "{v}"}}',
        ])
        self.quiet([f"PublicKey: {v}", f"Monkey: {v}", f"Tokenizer: {v}", f"ClientId: {v}", f"SecretsManager: {v}"])

    def test_a_url_value_is_judged_by_its_parts(self) -> None:
        v = J(["Kx92m", "Lq7ZtPqW", "2vR8"])
        self.quiet([
            "token: https://docs.example.org/v2/tokens",
            "refreshToken: https://docs.example.org/v2/tokens",
            "api_key: https://dashboard.vendor.org/settings/api2",
            "token: https://hooks.example.com/services/${HOOK_PATH_2}",
        ])
        self.fire([
            f"token: https://hooks.example.com/services/T0001/B0002/{v}",
            f"webhook_token=https://hooks.example.com/hook?key={v}&x=1",
            f"token: https://{v}@git.example.org/r.git",
        ])

    def test_two_different_placeholder_words_mark_a_placeholder(self) -> None:
        self.quiet([
            "token=YourGitHubTokenHere1",
            "OPENAI_API_KEY=sk-your-openai-key-here-1",
            "TWILIO_AUTH_TOKEN=your_twilio_auth_token1",
            "SECRET_KEY=django-insecure-your-secret-key-1",
        ])
        # Secret nouns with no placeholder word, or one placeholder word alone, are not
        # enough: the residue still counts.
        self.fire([J(["token=", "Kx92m", "Lq7Zt", "TokenAuth"]), J(["password=", "Sample", "Kx92m", "Lq7ZtPq"])])

    def test_the_value_is_what_the_key_pattern_captured(self) -> None:
        # A key with a placeholder word or `is` in it used to be read as part of the value.
        self.fire(["x-token-here-secret=Ab12345x", "is-example-password=Ab12345x", "token-sample-password=Ab12345x"])


class CodePathsStayFlagged(Case):
    """O2, decided: a code path through an arbitrary object stays a finding. Any rule that
    quiets `settings.S3_KEY_2` would also quiet a `summer.winter2041` password."""

    def test_code_paths_fire(self) -> None:
        self.fire([
            "api_key = settings.AWS_S3_SECRET_KEY_2",
            "token = config.OPENAI_API_KEY_V2",
            "password = Rails.application.credentials.db_password_2",
        ])


class GapsLeftBy11(Case):
    """The detection gaps #11 left: a flag and its value as two arguments, YAML block
    scalars, Python triple-quoted strings, PHP's `define`, PowerShell's
    `ConvertTo-SecureString ... -AsPlainText`, and quoted values with a space. Each is read
    with the same placeholder and reference logic as an assignment."""

    V = J(["Kx92m", "Lq7ZtPqW"])
    S = J(["Kx9 2m", "Lq7 ZtPq"])

    def test_a_flag_and_its_value(self) -> None:
        v, s = self.V, self.S
        self.fire([
            f"--password {v}",
            f"-password {v}",
            f"--api-key {v}",
            f"--db-password '{v}'",
            f'--token "{v}"',
            f"mysql --password {v} -h db",
            f"--access-token\t{v}",
            f'--client-secret "{s}"',
        ])
        self.quiet([
            "--password $DB_PASSWORD",
            '--password "$DB_PASSWORD"',
            "--token ${{ secrets.GH_TOKEN_2 }}",
            '--token "${{ secrets.GH_TOKEN_2 }}"',
            '--token "$env:GH_TOKEN"',
            "--api-key ${API_KEY_2}",
            "--password %DB_PASSWORD%",
            "--token $(gh auth token)",
            "--token <your-token>",
            "--password changeme",
            "--password CHANGE_ME_2",
            "--api-key YOUR_API_KEY_HERE",
            "--password example2024",
            "--password ****",
            "--password PASSWORD",
            '--password "Your password here 2"',
            # Not this key, or not a value.
            "--password-stdin < pw2.txt",
            "--token-file /run/secrets/token2",
            "--secret id=npmrc,src=$HOME/.npmrc",
            "use the --token argument",
            "--token  The token to use (v2)",
        ])

    def test_a_yaml_block_scalar(self) -> None:
        v = self.V
        self.fire([
            f"password: |\n  {v}",
            f"client_secret: >-\n    {v}",
            f"DB_PASSWORD: |+\n  '{v}'",
            f"  api_key: |2\n    {v}\n",
            f'"token": |\n  {v}',
        ])
        self.quiet([
            "password: |\n  ${{ secrets.DB_PASSWORD_2 }}",
            "password: |\n  {{ .Values.db.password2 }}",
            "secret: |\n  $DB_SECRET_2",
            "password: |\n  changeme",
            "token: |\n  <paste the token2 here>",
            "token: >\n  The token the bot uses.",
            f"description: |\n  {v}",  # not a key
        ])

    def test_a_python_triple_quoted_string(self) -> None:
        v = self.V
        self.fire([f'password = """{v}"""', f"api_key = '''{v}'''", f'TOKEN="""{v}"""'])
        self.quiet([
            'password = """changeme"""',
            "api_key = '''YOUR_API_KEY_HERE'''",
            'token = """${TOKEN_2}"""',
            'password = """\nThe password field must be 8 characters.\n"""',
        ])

    def test_php_define(self) -> None:
        v, s = self.V, self.S
        self.fire([
            f"define('DB_PASSWORD', '{v}');",
            f'define( "AUTH_TOKEN" , "{v}" );',
            f"define('SECRET_KEY', '{s}');",
        ])
        self.quiet([
            "define( 'DB_PASSWORD', 'password_here' );",  # wp-config-sample.php
            "define('DB_PASSWORD', 'your-db-password');",
            "define('DB_PASSWORD', getenv('DB_PASSWORD_2'));",
            "define('DB_PASSWORD', $_ENV['DB_PASSWORD_2']);",
            f"define('DB_HOST', '{v}');",  # not a key
        ])

    def test_powershell_convertto_securestring(self) -> None:
        v, s = self.V, self.S
        self.fire([
            f'$secret = ConvertTo-SecureString "{v}" -AsPlainText -Force',
            f"ConvertTo-SecureString -String '{v}' -AsPlainText -Force",
            f"ConvertTo-SecureString -AsPlainText -Force -String '{v}'",
            f"ConvertTo-SecureString '{v}' -Force -AsPlainText",
            f'ConvertTo-SecureString "{s}" -AsPlainText -Force',
        ])
        self.quiet([
            "$pw = ConvertTo-SecureString $env:DB_PASSWORD_2 -AsPlainText -Force",
            'ConvertTo-SecureString "$Password2" -AsPlainText -Force',
            'ConvertTo-SecureString "$DbPassword" -AsPlainText -Force',
            'ConvertTo-SecureString "${env:PW_2}" -AsPlainText -Force',
            "ConvertTo-SecureString '<password>' -AsPlainText -Force",
            "ConvertTo-SecureString 'your_pass_here' -AsPlainText -Force",
            "ConvertTo-SecureString (Get-Content pw2.txt) -AsPlainText -Force",
            f"ConvertTo-SecureString '{v}'",  # an encrypted standard string, not the password
        ])
        # A PascalCase variable is one only when its words are letters and digits end it.
        self.fire([J(["password=$", "Kx92m", "Lq7ZtPq"])])

    def test_a_quoted_value_with_a_space(self) -> None:
        s = self.S
        self.fire([
            f"password = '{s}'",
            f'"password": "{s}"',
            f'clientSecret: "{s}"',
            f"DB_PASSWORD='{s}'",
            # A link that holds a secret, or a secret with a joiner in it, is still one.
            f'token: "see https://hooks.example.com/services/T0001/B0002/{self.V}2vR8 now"',
            J(['password = "', "Kx9/2mLq7 ", "ZtPq+W4", '"']),
        ])
        self.quiet([
            'password: "Minimum 8 characters"',
            'token: "Use the API token from step 2"',
            '"secret": "Base64 encoded value"',
            '"password": "The password, at least 12 characters (letters and digits)."',
            "token: \"isn't set yet, see #12\"",
            'password: "${{ secrets.DB_PASSWORD_2 }}"',
            "token: '{{ .Values.token2 }}'",
            "api_key: '%(api_key)s and more'",
            'password: "your password here"',
            '"password": "<your password>"',
            'password: "**** ****"',
            'password = "Enter your password: "',
            # Ranges and hyphenated words are prose (Seer, round 1).
            'password: "Use letters (a-z, A-Z, 0-9) and symbols"',
            'password_hint: "Mix upper-case, lower-case and 0-9 digits."',
            '"secret": "A well-known value for end-to-end tests"',
            # Symbols and links in help text are prose too (Seer, round 2).
            'password_help: "Use 8+ characters, see https://docs.example.org/v2/passwords"',
            'token: "See docs/auth/v2 or run gh auth login (key=value form)"',
            '"api_key": "Create one at https://dashboard.vendor.org/settings/api2 first."',
            # Code between two string literals, not a quoted value (the survey's two hits).
            'f.do(t, "GET", "/v1/verify?token="+magic2, "", "")',
            'J(["password=", chr(0x131) + "nputs.", "Kx92mLq7"])',
        ])


class SeerRound3(Case):
    """Seer round 3 on #15: PowerShell's `$Env:` drive in any case is a reference, and a
    flag's `key=value` option list (BuildKit's `--secret id=...`) is not the secret."""

    def test_env_drive_in_any_case_is_a_reference(self) -> None:
        self.quiet([
            "ConvertTo-SecureString $Env:DB_PASSWORD_2 -AsPlainText -Force",
            "ConvertTo-SecureString $ENV:DbPassword2 -AsPlainText",
            "$password = $Env:DB_PASSWORD_2",
        ])
        self.fire([
            J(["ConvertTo-SecureString '", "Kx92mLq7", "ZtPq' -AsPlainText"]),
            J(["password = $Env:", "Kx9-2mLq7", "ZtPq"]),  # not a name shape
        ])

    def test_a_flag_option_list_is_not_the_secret(self) -> None:
        self.quiet([
            "docker buildx build --secret id=npmrc2,src=$HOME/.npmrc .",
            "docker build --secret id=gh_token2,env=GH_TOKEN .",
            '--secret "id=npmrc2,src=/run/secrets/x"',
        ])
        self.fire([
            J(["--secret ", "Kx92mLq7", "ZtPq"]),
            J(["--password ", "Kx92mLq7", "ZtPqAbCd=="]),  # padding is not a key
            J(['--token "', "Kx9 2mLq7", 'ZtPq"']),
            J(["--api-key ", "kx92mlq7ztpq", "abcdefgh="]),  # a trailing `=` is padding
        ])


class SeerRound4(Case):
    """Seer round 4 on #15: a technical name written with its number (`SHA256`, `OAuth2`)
    is prose in a quoted value with spaces, judged on a whole word only."""

    def test_technical_names_are_prose(self) -> None:
        self.quiet([
            'token: "Uses SHA256 with OAuth2 and Base64 encoding"',
            'secret: "Sign with HS256, verify with RS256 and X509 certificates"',
            'password: "hash it with sha256, then base64 it"',
            'api_key: "Runs on Ubuntu22 with Python3 and IPv6"',
        ])

    def test_secrets_beside_or_shaped_like_them_still_fire(self) -> None:
        self.fire([
            J(['token: "', "Kx92 mLq7 ", 'ZtPq 88aB"']),  # no word is a technical name
            J(['secret: "', "XK92-MQ47-", 'ZT81 is the code"']),  # a hyphenated group is judged whole
            J(['token: "SHA256 ', "Kx92mLq7", 'ZtPq"']),  # the name drops out, the rest is a secret
            J(['password = "', "Kx9 2mLq7", 'Zt"']),
        ])


if __name__ == "__main__":
    unittest.main()
