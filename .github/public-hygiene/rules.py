#!/usr/bin/env python3
"""Rules for text that must not appear in a public repository's issues, pull requests,
discussions, releases and commit messages.

    python3 rules.py --list                 # the rules table
    python3 rules.py FILE [FILE...]         # scan files ('-' is stdin); prints rule ids only
    python3 rules.py --hash-terms FILE --key-file KEYFILE   # denylist lines for FILE's terms
    python3 rules.py --self-test            # run the tests in this directory

Every public repository in the organization calls the reusable workflow
`.github/workflows/public-hygiene.yml`, which scans that text with these rules. The same
file is what an author runs on a body before `gh pr create` or `gh issue create`.

A finding names a rule id and nothing else. Nothing in this module returns, prints or
logs the text that matched: `Finding` holds the rule id and offsets only, and the CLI
prints rule ids. That is the point of the check, since the run log and the bot's comment
are as public as the text they flag.

Two kinds of rule:

- Shape rules, public here: token formats, secret-name shapes, cloud ids, IP addresses,
  local paths, operator commands. They name no organization-specific value.
- `internal-name`: the organization's own vocabulary (component and directory names,
  machine and session names, host prefixes, account and project ids). Those terms are
  never written here. `denylist.txt` holds a keyed hash (HMAC-SHA256, truncated) of each
  one, and the scan hashes the candidate tokens of a text the same way (identifiers, host
  labels, path pairs, word pairs and triples; see `_candidates`). The key is the
  organization secret PUBLIC_HYGIENE_DENYLIST_KEY, given to the check in the environment
  variable of the same name. Without the key nobody can test a guess against the list,
  so it tells a reader how many terms there are and nothing else. A run without the key
  (a fork's pull request, Dependabot), or with a key the list was not built with (the
  `canary:` line is the keyed hash of CANARY_TERM), skips this one rule and says so;
  every other rule still runs. The plain list and the key are kept outside the repository, and
  `--hash-terms` turns the list into denylist lines.

What is out of scope, on purpose:

- The em and en dash rule of the file-level `check-public-hygiene.py`: a style rule, and
  bodies by outside contributors and bots carry dashes.
- That file's blanket GitLab rule: a pull request may cite an upstream bug on any GitLab
  host. Only the organization's own group is checked (`private-gitlab`).
- That file's phone rule: the apps are diallers, and their pull requests discuss example
  and malformed numbers as a matter of course.

Documented exceptions (the allowlist), each next to the rule it narrows:

- `internal-email`: the public contact address (PUBLIC_ADDRESSES).
- `private-gitlab`: the group's public mirrors and profile (PUBLIC_GITLAB_PROJECTS).
- Every rule but `token`: text inside a public URL (PUBLIC_URL): GitHub, the public
  website, and the App Store, Google Play and Microsoft Store pages, so a store id or a
  run id in a link is not a finding.
- `ip-address`: loopback, the documentation ranges, the public resolvers, and four-part
  versions (single-digit parts, a version word or operator before, a build suffix after).
- `token`: test-fixture shapes (one repeated character, the AWS documentation key),
  placeholders (`YOUR_API_KEY_HERE`, `yourtokenhere`, `CHANGE_ME`, templates such as
  `${X}`, `{{ x }}` and `%(x)s`, `<your-token>`, `****` masks), and code references
  (`secrets.NAME`, `process.env.NAME`, `os.environ[`, `os.getenv(`). A placeholder word
  inside a value that keeps four or more other letters is still a value.
- `private-path`: placeholder home directories and an app's own cache directory.
- `secret-name-*`: the names every workflow uses, browser-public names, error codes, and
  names listed as an `.env.example` file's contents.
- `private-reference`: merge requests cited with an upstream project (GNOME, GTK and the
  other GitLab-hosted projects in UPSTREAM_GITLAB).

Every pattern is linear on a body of any length: no unbounded repeat can start at every
position of a run and scan to its end, repeats inside repeated groups are bounded, and
adjacent whitespace quantifiers are possessive (written `*+`, Python 3.11 or newer), and
the public-URL filter is a binary search. Before NFKC, runs of combining marks are capped
at MAX_MARK_RUN (NFKC is quadratic on such runs in CPython 3.12), and a text that NFKC
would expand more than twofold is scanned without NFKC. The scanned form is capped at
MAX_SCAN_CHARS, and a cut text is reported (`was_truncated`), never passed quietly. test_rules.py holds the worst shapes
found by fuzzing to a time bound.

Planted examples in the tests are synthetic and assembled at run time, so that this
repository's own secret scan does not trip on them.
"""

from __future__ import annotations

import bisect
import hashlib
import hmac
import os
import ipaddress
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

HERE = Path(__file__).resolve().parent

# The GitLab group's public projects: read-only mirrors of public GitHub repositories,
# plus the group profile. A link to one of these is a public URL. Anything else under the
# group is a private project.
PUBLIC_GITLAB_PROJECTS = frozenset(
    {
        "gitlab-profile",
        "bridgewatch",
        "district-android",
        "district-core-rust",
        "district-core-swift",
        "district-ios",
        "district-linux",
        "district-macos",
        "district-windows",
    }
)

# Company domains. An address at one of them names a person or an internal mailbox,
# except the public contact address below.
COMPANY_DOMAINS = ("distronode.com", "distronode.ca")
PUBLIC_ADDRESSES = frozenset({"opensource@distronode.com"})

# Authors whose text is skipped. Matched on login AND account type, so a user named like a
# bot is still scanned. Every other bot is scanned like a person.
# - Upstream bots: their text is generated from public upstream content.
# - Code review bots: they quote the pull request's own public diff, and on a change to
#   these rules that means quoting the planted examples; nobody here can edit their
#   comments either.
UPSTREAM_BOTS = frozenset({"dependabot[bot]", "renovate[bot]"})
REVIEW_BOTS = frozenset({"sentry[bot]", "seer-by-sentry[bot]", "Copilot", "copilot-pull-request-reviewer[bot]"})
SKIPPED_BOTS = UPSTREAM_BOTS | REVIEW_BOTS

# The scan's ceiling, in characters after normalization. A release body may hold 125,000.
MAX_SCAN_CHARS = 150_000

ARROW = chr(0x2192)


@dataclass(frozen=True)
class Finding:
    """One match: the rule and where it is. Never the matched text."""

    rule: str
    start: int
    end: int

    def __repr__(self) -> str:  # explicit, so a debug print cannot leak text
        return f"Finding(rule={self.rule!r}, start={self.start}, end={self.end})"


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    finder: Callable[[str], Iterator[tuple[int, int]]]
    # False: the rule still applies inside an allowed public URL (a token in a URL is a
    # token wherever it is).
    honours_public_urls: bool = True
    # True: checked for every author. False: only for the organization's own people and
    # for bots (see `scan(..., outside=True)`).
    for_everyone: bool = False


# --------------------------------------------------------------------------- helpers


def _spans(*patterns: re.Pattern[str], keep: Callable[[re.Match[str], str], bool] | None = None):
    def finder(text: str) -> Iterator[tuple[int, int]]:
        for pattern in patterns:
            for m in pattern.finditer(text):
                if keep is None or keep(m, text):
                    yield m.start(), m.end()

    return finder


def _c(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


IC = re.IGNORECASE


def _window(text: str, m: re.Match[str], before: int, after: int) -> str:
    return text[max(0, m.start() - before) : m.end() + after]


# --------------------------------------------------------------------------- token

TOKEN_PATTERNS = (
    _c(r"(?<![\w-])gh[pousr]_[A-Za-z0-9]{36,}(?![\w-])"),
    _c(r"(?<![\w-])github_pat_[A-Za-z0-9_]{50,}"),
    _c(r"(?<![\w-])gl(?:pat|dt|rt|ptt|cbt|oas|soat|ffct|imt|agent|ft|wt)-[A-Za-z0-9_\-]{20,}"),
    _c(r"(?<![\w-])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}"),
    _c(r"(?<![\w-])whsec_[A-Za-z0-9+/=]{24,}"),
    _c(r"(?<![A-Za-z0-9])(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}(?![A-Za-z0-9])"),
    _c(r"(?<![\w-])AIza[0-9A-Za-z_\-]{35}(?![\w-])"),
    _c(r"(?<![\w-])GOCSPX-[A-Za-z0-9_\-]{20,}"),
    _c(r"(?<![\w.-])ya29\.[A-Za-z0-9_\-]{20,}"),  # Google OAuth access token
    _c(r"(?<![\w/])1//0[A-Za-z0-9_\-]{20,}"),  # Google OAuth refresh token
    _c(r"(?<![\w-])xox[abposr]-[A-Za-z0-9\-]{10,}"),
    _c(r"hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"),
    _c(r"(?<![\w-])npm_[A-Za-z0-9]{36}(?![\w-])"),
    _c(r"(?<![\w-])pypi-AgE[A-Za-z0-9_\-]{50,}"),
    _c(r"(?<![\w-])sk-ant-[A-Za-z0-9_\-]{20,}"),
    _c(r"(?<![\w-])sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}"),
    _c(r"(?<![\w-])NR(?:AK|AA|II|JS)-[A-Z0-9]{20,}"),
    _c(r"(?<![A-Za-z0-9])[A-Za-z0-9]{30,40}NRAL(?![A-Za-z0-9])"),  # New Relic license key
    _c(r"(?<![\w-])SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{30,}"),
    _c(r"(?<![\w-])SK[0-9a-f]{32}(?![\w-])"),
    _c(r"(?<![\w-])KEY[0-9A-F]{32}_[A-Za-z0-9]{16,}"),
    _c(r"(?<![\w-])sntry[su]_[A-Za-z0-9+/=_\-]{20,}"),
    _c(r"(?<![\w-])eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    _c(r"-----BEGIN (?:[A-Z0-9]+ ){0,4}PRIVATE KEY(?: BLOCK)?-----"),
    _c(r"\bBearer\s++[A-Za-z0-9._~+/\-]{20,}=*", IC),
    _c(r"\bauth\s++token\s*+[:=]?\s*+[0-9a-f]{32}\b", IC),
    # A password in a URL's user info.
    _c(r"(?<![\w+.\-])[a-z][a-z0-9+.\-]{0,30}://[^\s/:@]{0,100}:[^\s/@]{6,200}@[\w.\-]+", IC),
    # `password = value` and friends. Prefixed names and flags count too (`DB_PASSWORD=`,
    # `CLIENT_SECRET:`, `--password=`), with a key suffix (`SECRET_KEY`) and a quoted key
    # (`"password":`). The lookbehind refuses a start after a hyphen and the prefix is
    # bounded, so a long `a-a-a-...` chain is linear.
    _c(
        r"(?<![\w-])(?:-{1,2})?(?:[A-Za-z0-9]+[_\-]){0,4}"
        r"(?:password|passwd|pwd|pw|secret|token|api[_\-]?key|api[_\-]?token|access[_\-]?token|auth[_\-]?token)"
        r"(?:[_\-](?:access[_\-])?key)?['\"]?\s*+(?::=|=>|[:=])\s*+['\"`]?[^\s'\"`,;)<>]{8,200}",
        IC,
    ),
    # The same with a camelCase key (`clientSecret`, `dbPassword`, `refreshToken`,
    # `secretKey`, `privateKey`), case-sensitive so that `publicKey` and `monkey` are not
    # keys. Go's `:=` and PHP's `=>` count as delimiters in both.
    _c(
        r"(?<![\w$-])(?:[a-z][a-z0-9]{0,30}(?:[A-Z][a-z0-9]{0,30}){0,3}(?:Secret|Password|Passwd|Pwd|Token)"
        r"|(?:[a-z][a-z0-9]{0,30}(?:[A-Z][a-z0-9]{0,30}){0,3})?(?:[Ss]ecret|[Pp]rivate|[Aa]ccess|[Ss]igning|[Aa]pi|[Ee]ncryption|[Mm]aster)Key)"
        r"(?![a-z])['\"]?\s*+(?::=|=>|[:=])\s*+['\"`]?[^\s'\"`,;)<>]{8,200}"
    ),
    # A password written in prose: `the password is ...`.
    _c(r"\bpassword\s++(?:is|was)\s++['\"`]?[^\s'\"`,;)<>]{8,200}", IC),
)

ASSIGNMENT_VALUE = _c(r"(?::=|=>|[:=]|\bis|\bwas|\bBearer|\btoken)\s*+['\"`]?([^\s'\"`,;)<>]{8,200})$", IC)
URL_PASSWORD = _c(r"://[^\s/:@]*:([^\s/@]+)@")
# a template or a mask, not a character a real password may hold:
# `${X}`, `$(cmd)`, `{{ x }}`, `{% x %}`, `{name}`, `%(x)s`, a whole `$NAME`, `%NAME%`, `<your-token>`,
# `***`. A lone `$ % * { }` is a password character, and `%2B` is URL encoding.
# A template's whole span (`${X}`, `${{ x }}`, `$(cmd)`, `{{ x }}`, `{% x %}`, `{name}`,
# `%(x)s`, a whole `$NAME`, `%NAME%`). A value that is a template and little else is a
# placeholder; a real secret that merely holds a brace or a percent sign is not. Spans
# are bounded, and a value is at most 200 characters.
_TEMPLATE_SPAN_PARTS = (
    r"\$\{\{.{0,200}?(?:\}\}|{END})|\$\{[^{}]{0,200}(?:\}|{END})|\$\([^()]{0,200}(?:\)|{END})|\{\{.{0,200}?(?:\}\}|{END})"
    r"|\{%.{0,200}?(?:%\}|{END})|\{[A-Za-z_][\w.\-]{0,100}\}|%\([^()]{0,100}(?:\)s?|{END})"
    r"|^\$(?:[A-Z_][A-Z0-9_]*|[a-z_][a-z0-9_]*)$|%[A-Z_][A-Z0-9_]{2,}%|^%[a-z_][a-z0-9_]*%$"
)
# Closed templates only. An opener with no closer is a template only where the value
# itself was cut short by a character values cannot hold (`$(gh auth token)` stops at
# the space; `{{ .Values.x }}` at the first space): TEMPLATE_SPAN_CUT accepts the end of
# the value as the closer, and is used only then.
TEMPLATE_SPAN = _c(_TEMPLATE_SPAN_PARTS.replace("|{END}", ""))
TEMPLATE_SPAN_CUT = _c(_TEMPLATE_SPAN_PARTS.replace("{END}", "$"))
# A mask or an angle-bracket placeholder: never a secret, whatever surrounds it.
MASK_SHAPE = _c(r"<[^<>]+>|\*{3,}")
PLACEHOLDER_WORDS = frozenset(
    {"password", "passwd", "pass", "secret", "changeme", "example", "redacted", "hunter2", "token", "xxxxxx"}
)
# Placeholder words, matched as whole words of a value (`YOUR_API_KEY_HERE`,
# `yourTokenHere`), never inside one: a real secret may contain `here` or `your`.
PLACEHOLDER_WORDS_IN_VALUE = frozenset(
    {"your", "here", "example", "placeholder", "sample", "dummy", "redacted", "changeme", "todo", "fixme", "insert", "replace"}
)
# words that fill a placeholder out without making it a value.
PLACEHOLDER_FILLER = frozenset(
    {"api", "key", "keys", "token", "secret", "password", "pass", "pwd", "access", "auth", "client", "id", "app",
     "account", "my", "me", "a", "an", "the", "to", "with", "real", "actual", "own", "goes", "put", "paste",
     "enter", "value", "new", "it"}
)
_SEGMENTS = PLACEHOLDER_WORDS_IN_VALUE | PLACEHOLDER_FILLER
_SEGMENT_MAX = max(map(len, _SEGMENTS))
CHANGE_ME = _c(r"(?<![a-z])change[_\-]?(?:me|it)(?![a-z])", IC)
VALUE_WORD = _c(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
# the reference words as code spells them (case-sensitive), each
# followed by an access to a name (`.NAME`, `.name`) or a call or index that ends the value
# (`os.environ[`, `os.getenv(`), so `Github.Prod2041` and `Github(2041)` are values.
_NAME_AFTER = r"(?:[a-z_]|[A-Z][A-Z0-9_]*+(?![a-z]))"
TEMPLATE_PREFIX = _c(
    r"(?:[A-Za-z_$][\w$]{0,30}\.){0,3}"
    r"(?:(?:secrets|vars|env|inputs|steps|needs|github|environ|getenv)(?=\." + _NAME_AFTER + r"|[(\[](?:$|" + _NAME_AFTER + r"))"
    r"|ENV(?=\[|\.fetch\()|Getenv(?=\())"
    # A secret store's path rather than the secret (`vault:secret/data/app#key`).
    r"|^vault:(?=[a-z][\w\-]*/)"
)


def _split(word: str) -> list[str] | None:
    """`word` cut wholly into _SEGMENTS (`yourtokenhere` -> your, token, here), or None."""
    back: list[int | None] = [0] + [None] * len(word)
    for i in range(1, len(word) + 1):
        for j in range(max(0, i - _SEGMENT_MAX), i):
            if back[j] is not None and word[j:i] in _SEGMENTS:
                back[i] = j
                break
    if back[-1] is None:
        return None
    parts, i = [], len(word)
    while i:
        j = back[i]
        parts.append(word[j:i])
        i = j
    return parts


def _is_placeholder_value(value: str, cut: bool = False) -> bool:
    """`cut`: the value was cut short by a character values cannot hold, so an opener
    whose closer lies beyond the cut still counts as a template."""
    spans_re = TEMPLATE_SPAN_CUT if cut else TEMPLATE_SPAN
    if TEMPLATE_PREFIX.match(value) or MASK_SHAPE.search(value):
        return True
    # A value that is mostly template (`prefix-${NAME}`) is a placeholder; a template span
    # inside a value that is mostly not (`Kx9{name}Lq7ZtPq2`) is a value.
    spans = sum(m.end() - m.start() for m in spans_re.finditer(value))
    if spans * 2 >= len(value):
        return True
    rest = spans_re.sub(" ", value)
    # `CHANGE_ME` or a placeholder word marks a placeholder only when what is left, besides
    # them, filler words and digits, is too short to be a secret: `Sample42Lq9vZ` keeps
    # `Lq`, `v`, `Z`.
    marked = False
    without = CHANGE_ME.sub(" ", rest)
    marked = marked or without != rest
    residue = 0
    for w in VALUE_WORD.findall(without):
        w = w.lower()
        if w.isdigit():
            continue
        if len(w) >= 4 and set(w) == {"x"}:  # `xxxx`, `XXXXXXXX`
            marked = True
            continue
        parts = _split(w)
        if parts is None:
            residue += len(w)
        else:
            marked = marked or any(p in PLACEHOLDER_WORDS_IN_VALUE for p in parts)
    return marked and residue < 4


VALUE_CUT_CHARS = frozenset(")'\"`,;<> \t\n")


def _token_payload_is_real(m: re.Match[str], text: str) -> bool:
    """Drop the shapes test fixtures and documentation use: one repeated character, a
    short alphabet, the AWS documentation key, placeholders."""
    found = m.group(0)
    if found.upper().endswith("EXAMPLE"):
        return False
    userinfo = URL_PASSWORD.search(found)
    if userinfo:
        # `postgres://user:password@localhost` and `://u:${PASS}@h` are documentation.
        secret = userinfo.group(1)
        return not (_is_placeholder_value(secret) or secret.lower() in PLACEHOLDER_WORDS or len(set(secret)) < 6)
    assignment = ASSIGNMENT_VALUE.search(found)
    if assignment:
        # `password: Simulator.app` is prose; a value with no digit is a word, not a secret.
        # `token=x` also matches at `token`, so the captured value can start with the
        # delimiter; strip it before the placeholder test.
        value = assignment.group(1).lstrip(":='\"`")
        # The character after the match, in the text: a quote, a space or a closing
        # parenthesis there means the value was cut short at it.
        cut = text[m.end() : m.end() + 1] in VALUE_CUT_CHARS
        if _is_placeholder_value(value, cut):
            return False
        return bool(re.search(r"\d", value) and re.search(r"[A-Za-z]", value)) and len(set(value)) >= 8
    body = re.sub(r"^[A-Za-z]+[_\-]", "", found)
    return len(set(body)) >= 8


# --------------------------------------------------------------------------- secret names

_SECRET_WORD = r"(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?|DSN|PAT|PEM|P8|CERT|SELLER_ID|TENANT_ID|CLIENT_ID)"
# An UPPER_SNAKE name with a secret-like word in it: at least one part before the word,
# and up to three after it (`BILLING_API_KEY_PRIMARY`).
SECRET_NAME_SNAKE = _c(r"(?<![\w-])[A-Z][A-Z0-9]*(?:_[A-Z0-9]+){0,6}_" + _SECRET_WORD + r"(?:_[A-Z0-9]+){0,3}(?![\w-])")
# Names in that shape that are not secrets: error codes and states, key events and
# token kinds.
ERROR_CODE_PREFIX = _c(r"(?:INVALID|MISSING|EXPIRED|BAD|NO|WRONG|UNKNOWN|REVOKED|STALE|REFRESH|RESET|ROTATE)_")
NOT_A_SECRET = _c(r".*_(?:KEY|TOKEN)_(?:CODE|TYPE|EVENT|DOWN|UP|PRESS|COUNT|LENGTH|LIMIT|KIND|NAME|PREFIX|FORMAT)(?:_[A-Z0-9]+)*")
# Values meant to be public: a browser bundle's variables and publishable keys.
PUBLIC_NAME = _c(r"(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_)[A-Z0-9_]*|[A-Z0-9_]*_(?:PUBLIC|PUBLISHABLE)_KEY(?:_ID)?")
# A kebab-case secret name, the shape Secret Manager names take.
SECRET_NAME_KEBAB = _c(
    r"(?<![\w./-])[a-z][a-z0-9]*(?:-[a-z0-9]+){1,8}-(?:env|secret|secrets|token|dsn|password|credentials)(?![\w-])"
)
# Names every workflow uses, which say nothing about the organization.
COMMON_SECRET_NAMES = frozenset(
    {"GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"}
)
# Secret stores. `GSM` is upper case only, and a telephony word too, so with it only an
# UPPER_SNAKE secret name counts; the other stores take a kebab name as well.
GSM_WORD = _c(r"(?<![\w-])GSM(?![\w-])")
SECRET_STORE = _c(
    r"(?<![\w-])(?:secrets?\s++manager|secretmanager|gcloud\s++secrets|parameter\s++store|key\s++vault"
    r"|hashicorp\s++vault|1password|bitwarden|doppler|(?:repository|organization|org|environment)\s++secrets?|ci/cd\s++variables?)(?![\w-])",
    IC,
)
SECRET_WORD_NEAR = _c(r"\bsecret\b", IC)
ENV_EXAMPLE = _c(r"\.env\.(?:example|sample|template)\b|\benv\.example\b", IC)


def _secret_names(text: str) -> Iterator[re.Match[str]]:
    for m in SECRET_NAME_SNAKE.finditer(text):
        name = m.group(0)
        if name in COMMON_SECRET_NAMES or ERROR_CODE_PREFIX.match(name) or PUBLIC_NAME.fullmatch(name) or NOT_A_SECRET.fullmatch(name):
            continue
        yield m


def _paragraphs(text: str) -> Iterator[tuple[int, str]]:
    start = 0
    for m in re.finditer(r"\n[ \t]*+\n", text):
        yield start, text[start : m.start()]
        start = m.end()
    yield start, text[start:]


def _find_secret_name_gsm(text: str) -> Iterator[tuple[int, int]]:
    for offset, para in _paragraphs(text):
        snake = any(True for _ in _secret_names(para))
        kebab = SECRET_NAME_KEBAB.search(para)
        gsm = GSM_WORD.search(para)
        store = SECRET_STORE.search(para)
        if gsm and snake:
            yield offset + gsm.start(), offset + gsm.end()
        if store and (snake or kebab):
            yield offset + store.start(), offset + store.end()
        # A kebab secret name called a secret in so many words (`the booking-zz-env secret`).
        for k in SECRET_NAME_KEBAB.finditer(para):
            if SECRET_WORD_NEAR.search(para, max(0, k.start() - 20), k.start()) or SECRET_WORD_NEAR.search(para, k.end(), k.end() + 20):
                yield offset + k.start(), offset + k.end()


def _find_secret_name_list(text: str) -> Iterator[tuple[int, int]]:
    for offset, para in _paragraphs(text):
        if ENV_EXAMPLE.search(para):
            continue  # an example env file's names are public configuration
        names: dict[str, re.Match[str]] = {}
        for m in _secret_names(para):
            names.setdefault(m.group(0), m)
        if len(names) >= 3:
            yield offset + min(m.start() for m in names.values()), offset + max(m.end() for m in names.values())
    # The same, across a whole text without an example file.
    if not ENV_EXAMPLE.search(text):
        names = {m.group(0): m for m in _secret_names(text)}
        if len(names) >= 3:
            yield min(m.start() for m in names.values()), max(m.end() for m in names.values())


# --------------------------------------------------------------------------- credential health

_NEG = r"(?:not|never|\w{1,6}n't)"
CREDENTIAL_WORD = _c(
    r"\b(?:key|keys|secret|secrets|token|tokens|password|passwords|credential|credentials|cert|certs|certificate|pat|pats|dsn)\b"
    r"(?!\s++(?:field|input|box|view|picker|button|label|text|prompt))",
    IC,
)

# Each counts only with a credential word, or a secret-like name, close by: these
# phrases also describe screens, images, cookies and staging builds.
CREDENTIAL_HEALTH = (
    _c(r"\b" + _NEG + r"\s++(?:yet\s++)?(?:been\s++)?(?:verified|tested|confirmed|proven)\s++(?:in|on|against)\s++prod(?:uction)?\b", IC),
    _c(r"\b(?:unverified|untested)\s++(?:in|on)\s++prod(?:uction)?\b", IC),
    _c(r"\bexpir(?:y|ation|es)(?:\s++date)?\s++(?:is\s++|was\s++|has\s++)?" + _NEG + r"\s++(?:yet\s++)?(?:been\s++)?(?:checked|verified|known|confirmed)\b", IC),
    _c(r"\bexpiry\s++(?:unknown|unchecked)\b", IC),
    _c(r"\bverified\s*+[=:]\s*+false\b", IC),
    _c(r"\bun-?rotated\b", IC),
    _c(r"\b" + _NEG + r"\s++(?:yet\s++)?(?:been\s++)?rotated\b", IC),
    _c(r"\brotation\s++(?:is\s++)?(?:overdue|pending|outstanding|owed|not\s++done)\b", IC),
    _c(r"\bstill\s++live\b", IC),
    _c(r"\bexpires?\s++(?:on\s++)?\d{4}-\d{2}-\d{2}\b", IC),
)
# A phrase that needs no credential word: `not verified in production` said of anything is
# the shape of the notes this rule exists for, and `in prod` (not `on production
# hardware`) is the operator's phrase.
CREDENTIAL_HEALTH_ALONE = _c(r"\b" + _NEG + r"\s++(?:yet\s++)?(?:been\s++)?(?:verified|tested)\s++in\s++prod(?:uction)?\b", IC)


def _find_credential_health(text: str) -> Iterator[tuple[int, int]]:
    for m in CREDENTIAL_HEALTH_ALONE.finditer(text):
        yield m.start(), m.end()
    for pattern in CREDENTIAL_HEALTH:
        for m in pattern.finditer(text):
            window = _window(text, m, 40, 20)
            if CREDENTIAL_WORD.search(window) or any(True for _ in _secret_names(window)):
                yield m.start(), m.end()


# --------------------------------------------------------------------------- monitoring gaps

MONITORING_GAP = (
    _c(r"\b(?:workers?|server|relay|origin|cluster|prod(?:uction)?|backend|edge)\s++(?:logs?|logging|alerting|monitoring|tracing)\s++(?:is\s++|are\s++)?(?:off|disabled|turned\s++off)\b", IC),
    _c(r"\bonly\s++(?:has\s++)?(?:the\s++|an?\s++)?(?:[A-Za-z]+\s++){0,3}uptime\s++(?:probe|check|monitor)\b", IC),
    _c(r"\bnothing\s++reports\s++(?:its\s++)?errors\b", IC),
    _c(r"\bno\s++(?:alerting|alerts|monitoring|paging)\s++(?:on|for)\s++(?:the\s++)?(?:relay|origin|cluster|prod|production|server|backend)\b", IC),
)

# --------------------------------------------------------------------------- IAM and WIF

IAM_WIF = (
    _c(r"\bgcloud\s++iam\b", IC),
    _c(r"\b(?:add|remove|set|get)-iam-policy(?:-binding)?\b", IC),
    _c(r"\battribute[._-]?condition\b", IC),
    _c(r"--attribute-mapping\b", IC),
    _c(r"\bworkloadIdentityPools\b"),
    _c(r"--workload-identity-pool\b", IC),
    _c(r"\bprincipal(?:Set)?://", IC),
    _c(r"(?<![\w/-])roles/(?:[a-z][A-Za-z0-9]*\.[A-Za-z0-9.]+|owner|editor|viewer)\b"),
    _c(r"(?<![A-Za-z0-9._\-])[A-Za-z0-9._\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com\b", IC),
    _c(r"(?<![A-Za-z0-9._\-])[A-Za-z0-9._\-]+\.svc\.id\.goog\b", IC),
    _c(r"\b(?:iam|sts):[A-Z][A-Za-z]+\b"),
)

# --------------------------------------------------------------------------- operator commands

_GCLOUD_GROUPS = (
    "iam|secrets|kms|projects|compute|container|run|functions|sql|storage|services|auth|config|artifacts"
    "|builds|organizations|resource-manager|logging|pubsub|scheduler|dns|deploy|app|redis|filestore|beta|alpha"
)
OPERATOR_COMMAND = (
    _c(r"\bgcloud\s++(?:" + _GCLOUD_GROUPS + r")\s++[a-z][a-z\-]+", IC),
    _c(r"\baws\s++(?:iam|sts|ssm|secretsmanager|kms|organizations|ec2|ecr|sso)\s++(?!get-caller-identity\b)[a-z][a-z\-]+"),
    # The flag group is bounded, so `kubectl -n kubectl -n ...` is linear.
    _c(r"\bkubectl\s++(?:(?:-n|--namespace|--context)[ =]\S{1,253}+\s++){0,4}(?:set|patch|apply|edit|create|delete|rollout|scale|annotate|label|replace|exec|cp|drain|cordon)\b", IC),
    _c(r"\benvFrom\b"),
    _c(r"\bgh\s++secret\s++(?:set|delete)\b", IC),
    _c(r"\bglab\s++variable\s++(?:set|update|delete)\b", IC),
    _c(r"\bwrangler\s++secret\s++(?:put|delete|bulk)\b", IC),
    # A cloud project flag with a project-id-shaped value (`tsc --project tsconfig` is not).
    _c(r"--project=[a-z][a-z0-9]{1,20}-[a-z0-9\-]{1,20}[a-z0-9]\b"),
)

# --------------------------------------------------------------------------- email

EMAIL = _c(
    r"(?<![\w.%+\-])[A-Za-z0-9_%+\-](?:[A-Za-z0-9._%+\-]*[A-Za-z0-9_%+\-])?"
    r"@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,})(?![\w\-])"
)
# A mailbox name with the @ and no domain (`name@`, then the domain spelt out in words).
# Lower case only (a CamelCase name before an @ is a CI task or an annotation), not before
# a version operator, and not a Kotlin label (`outer@ for`, `break@outer`).
BARE_MAILBOX = _c(r"(?<![\w.%+\-@/])[a-z][a-z0-9._%+\-]*[a-z0-9]@(?=$|[\s),.;:!?'\"`\]])", re.M)
KOTLIN_LABEL_AFTER = _c(r"\s*+(?:for|while|do|forEach|run|let|apply|also|with|loop|repeat)\b")


def _find_internal_email(text: str) -> Iterator[tuple[int, int]]:
    for m in EMAIL.finditer(text):
        domain = m.group(1).lower()
        if not any(domain == d or domain.endswith("." + d) for d in COMPANY_DOMAINS):
            continue
        if m.group(0).lower() in PUBLIC_ADDRESSES:
            continue
        yield m.start(), m.end()
    for m in BARE_MAILBOX.finditer(text):
        if KOTLIN_LABEL_AFTER.match(text, m.end()):
            continue
        yield m.start(), m.end()


# --------------------------------------------------------------------------- private paths

PRIVATE_PATH = (
    _c(r"(?<![\w.\-])/home/(?!runner/)[a-z_][\w.\-]*/"),
    _c(r"(?<![\w.\-])/root/\.[\w.\-]+"),
    _c(r"(?<![\w.\-])/Users/(?!runner/|Shared/)[A-Za-z][\w.\-]*/"),
    _c(r"(?<![\w])[A-Za-z]:\\{1,2}Users\\{1,2}(?!runneradmin\\|Public\\|Default\\)[^\\\s]+", IC),
    _c(r"(?:~|\$HOME|\$\{HOME\})/\.(?:cache|claude|ssh|aws|gnupg|kube|docker|netrc|pgpass)\b"),
    _c(r"(?:~|\$HOME|\$\{HOME\})/\.config/(?:mcp|gcloud|gh|glab-cli)\b"),
    # Any path written as the private monorepo's: `monorepo docs/x.md`, `the monorepo's infra/`.
    _c(r"\bmonorepo(?:'s)?\s++[`'\"(]?[\w.\-]{1,100}/[\w./\-]{0,200}", IC),
)
# Home directories that are placeholders in documentation, not someone's machine.
PLACEHOLDER_USER = _c(r"(?:/home/|/Users/|[A-Za-z]:\\{1,2}Users\\{1,2})(?:alice|bob|carol|user|username|you|me|name|example|x+|[<%$]\S*)[/\\]?", IC)


def _find_private_path(text: str) -> Iterator[tuple[int, int]]:
    for pattern in PRIVATE_PATH:
        for m in pattern.finditer(text):
            if PLACEHOLDER_USER.fullmatch(m.group(0).rstrip("`)'\".,;:")):
                continue
            # `~/.cache/district...` is an app's cache directory, documented publicly.
            if m.group(0).endswith(".cache") and text[m.end() : m.end() + 9].lower() == "/district":
                continue
            yield m.start(), m.end()


# --------------------------------------------------------------------------- IP addresses

IPV4 = _c(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(/\d{1,2})?(?![\w]|\.\d)")
IPV6 = _c(r"(?<![\w:])((?:[0-9a-fA-F]{1,4}:){1,7}(?::|(?::[0-9a-fA-F]{1,4}){1,6}|[0-9a-fA-F]{1,4}))(/\d{1,3})?(?![\w:])")
# Version words and operators before a four-part version. A bare `@` or `=` is also how a
# host is written (`user@host`, `HOST=addr`), so neither counts.
VERSION_CONTEXT = _c(
    r"(?:\bv|\bversion\s*+:?\s*+|\bver\.?\s*+|\brelease\s++|\bbuild\s++|\bmsix\s++|\bpackage\s++|\bpolicy\s++|\bsection\s++|"
    r"(?:==|>=|<=|~=|!=|\^|~)\s*+|\bbump(?:s|ed)?\s++|version\(\s*+['\"])$",
    IC,
)
# An arrow from a two- or three-part version (an upgrade line), not a hop to a host. A
# four-part quad before the arrow is an address itself, so `addr -> addr` still counts.
VERSION_ARROW = _c(r"(?<![\d.])\d+(?:\.\d+){1,2}\s*+(?:->|" + ARROW + r")\s*+$")
VERSION_SUFFIX = _c(r"\+[0-9A-Za-z]|-(?:alpha|beta|rc|pre|preview|dev|snapshot|nightly)\b", IC)
DOC_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "127.0.0.0/8",
        "0.0.0.0/8",  # "this network": never a host, and the shape of 0.x versions
        "255.255.255.255/32",
        "2001:db8::/32",
        "::1/128",
        "::/128",
    )
)
PRIVATE_NETS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))
# The private ranges themselves, written as the standards define them, say nothing of ours.
STANDARD_RANGES = frozenset(str(n) for n in PRIVATE_NETS)

# Addresses every network document uses: the public resolvers and the cloud metadata
# address. They identify nothing of ours.
WELL_KNOWN_ADDRESSES = frozenset(
    {
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "169.254.169.254",
        "100.100.100.100",
        "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844",
        "2620:fe::fe", "2620:fe::9",
    }
)


def _find_ip(text: str) -> Iterator[tuple[int, int]]:
    for m in IPV4.finditer(text):
        try:
            addr = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        cidr = m.group(2)
        if any(addr in net for net in DOC_NETS) or (m.group(1) in WELL_KNOWN_ADDRESSES and not cidr):
            continue
        if cidr and m.group(1) + cidr in STANDARD_RANGES:
            continue
        private = any(addr in net for net in PRIVATE_NETS)
        if not cidr:
            before = text[max(0, m.start() - 40) : m.start()]
            if VERSION_CONTEXT.search(before[-16:]) or VERSION_ARROW.search(before):
                continue
            if VERSION_SUFFIX.match(text, m.end()):
                continue
            if not private:
                # A network address (`.0`) is never a public host without a prefix length,
                # and four single-digit parts are a version (`4.6.1.2`, `3.1.4.2`).
                if m.group(1).endswith(".0") or all(len(p) == 1 for p in m.group(1).split(".")):
                    continue
        yield m.start(), m.end()
    for m in IPV6.finditer(text):
        raw = m.group(1)
        if "::" not in raw and raw.count(":") != 7:
            continue
        try:
            addr6 = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if any(addr6 in net for net in DOC_NETS) or (str(addr6) in WELL_KNOWN_ADDRESSES and not m.group(2)):
            continue
        # Global unicast and unique local only; this keeps `a::b` style code out.
        if not (raw.lower().startswith(("2", "3", "fc", "fd"))):
            continue
        yield m.start(), m.end()


# --------------------------------------------------------------------------- GitLab

GITLAB_GROUP_URL = _c(r"gitlab\.com[:/]distronode-corporation(?:/(?P<project>[A-Za-z0-9_.\-]+))?", IC)


def _find_private_gitlab(text: str) -> Iterator[tuple[int, int]]:
    for m in GITLAB_GROUP_URL.finditer(text):
        project = m.group("project")
        if project is None:
            continue  # the group page lists only public projects to the public
        name = project.lower().rstrip(".")  # a sentence's full stop
        if name.endswith(".git"):
            name = name[: -len(".git")]
        if name in PUBLIC_GITLAB_PROJECTS:
            continue
        yield m.start(), m.end()


# GitLab-hosted upstream projects the apps cite. A merge request named with one of these
# within UPSTREAM_WINDOW characters is theirs, not ours.
UPSTREAM_GITLAB = _c(
    r"\b(?:gnome|gtk|glib|libadwaita|freedesktop|mesa|gstreamer|pipewire|wayland|kde|inkscape|f-droid|fdroid|debian|archlinux|gitlab\.[a-z0-9.\-]+\.[a-z]+)\b",
    IC,
)
UPSTREAM_WINDOW = 40
PRIVATE_REFERENCE = (
    _c(r"\bgitlab\s*+(?:issue|mr|merge\s++request|work\s++item|epic)\s*+#?\s?\d+", IC),
    _c(r"\bgitlab\s*+[#!]\s?\d+", IC),
    _c(r"\b(?:MR|merge\s++request)\s*+!\d+", IC),
    _c(r"\bconfidential\s++(?:issue\s++)?#\d+", IC),
    _c(r"\bmonorepo(?:'s)?\s++(?:origin/)?(?:commit|sha|branch|main|MR|merge\s++request|pipeline|job)\s++(?:[`'\"]|[0-9a-f]{7,40}\b|!\d)", IC),
)
# A note id counts only with a tracker reference near it (`#7, note 1234509876`), not in
# a spec's `note 12345678`.
NOTE_ID = _c(r"\bnote\s++(?:id\s++)?#?\d{8,}\b", IC)
NOTE_CONTEXT = _c(r"gitlab|#\d+|\bdecision", IC)


def _find_private_reference(text: str) -> Iterator[tuple[int, int]]:
    for pattern in PRIVATE_REFERENCE:
        for m in pattern.finditer(text):
            if "!" in m.group(0) and UPSTREAM_GITLAB.search(_window(text, m, UPSTREAM_WINDOW, UPSTREAM_WINDOW)):
                continue
            yield m.start(), m.end()
    for m in NOTE_ID.finditer(text):
        if NOTE_CONTEXT.search(_window(text, m, 40, 10)):
            yield m.start(), m.end()


# --------------------------------------------------------------------------- cloud accounts and resources

CLOUD_ACCOUNT_ID = (
    _c(r"\barn:aws[\w\-]*:[\w\-]*:[\w\-]*:\d{12}:"),
    _c(r"\b\d{12}\.dkr\.ecr\."),
    _c(r"(?<![\w])projects/\d{6,}\b"),
    _c(r"\b(?:aws|gcp|google\s++cloud|new\s++relic|nr|sentry|stripe|cloudflare|twilio|telnyx|gitlab|github)\b[^\n]{0,30}?\b(?:account|project|org(?:anization)?)(?:\s++(?:id|number|no\.?))?\s*+[:#=]?\s*+\d{6,}\b", IC),
    _c(r"\b(?:project|account)\s++(?:id|number|no\.?)\s*+[:#=]?\s*+\d{6,}\b", IC),
    _c(r"\bproject\b[^\n]{0,40}?\bnumber\b\W{0,3}\d{6,}\b", IC),
    _c(r"(?:[?&]|\b)(?:account|accountId|account_id|projectId|project_id)=\d{6,}\b", IC),
    _c(r"(?<![\w.\-/])\d{4}-\d{4}-\d{4}(?![\w\-])"),
    _c(r"(?<![\w.\-/])\d{12}\s++(?:aws\s++)?account\b", IC),
    _c(r"\b\d{6,}-compute@developer\.gserviceaccount\.com\b", IC),
    _c(r"\bservice-\d{6,}@"),
    _c(r"(?<![\w-])acct_[A-Za-z0-9]{16}(?![\w-])"),
    _c(r"(?<![\w-])AC[0-9a-f]{32}(?![\w-])"),
    _c(r"(?<![\w/])projects/[a-z][a-z0-9\-]{4,28}[a-z0-9]/(?:secrets|locations|serviceAccounts|keyRings|topics|subscriptions|global|zones|regions|instances|databases)\b"),
)

# Links into a vendor's console, and a vendor organization's ingest id. An organization's
# own Sentry host (`<slug>.sentry.io`) is every Sentry customer's, so it is not a shape
# rule; this organization's slug is in the hashed denylist.
CONSOLE_LINK = (
    _c(r"(?<![a-z0-9.\-])(?:console\.cloud\.google\.com|(?:[a-z0-9\-]{1,63}\.)?console\.aws\.amazon\.com|one(?:\.eu)?\.newrelic\.com|dash\.cloudflare\.com"
       r"|portal\.azure\.com|partner\.microsoft\.com/dashboard|appstoreconnect\.apple\.com|play\.google\.com/console)\b", IC),
    _c(r"(?<![\w.\-])o\d{5,}\.ingest\.", IC),
)

CLOUD_RESOURCE = (
    _c(r"(?<![\w-])(?:i|sg|subnet|vpc|vol|eni|ami|igw|nat|rtb)-(?:[0-9a-f]{17}|[0-9a-f]{8})(?![\w-])"),
)

# --------------------------------------------------------------------------- internal hosts

# From check-public-hygiene.py: private-use host suffixes, lower case only (a qualified
# enum case such as `Mode.internal` is not a host). Narrower than the file check, because
# prose quotes code (`self.local`, `okhttp3.internal`): a cluster-local service name is
# always a host; the other suffixes count only in a host's position, after `://` or `@`,
# or before a port or a path.
CLUSTER_LOCAL = _c(r"(?<![\w.\-])(?:[a-z0-9\-]+\.){1,10}svc\.cluster\.local(?![\w\-])")
INTERNAL_SUFFIX = _c(
    r"(?:(?<=://)|(?<=@))(?:[a-z0-9\-]+\.){1,10}(?:internal|local|lan|corp|svc)(?![\w\-]|\.\w)"
    r"|(?<![\w.\-])(?:[a-z0-9\-]+\.){1,10}(?:internal|local|lan|corp|svc)(?=:\d|/)"
)

# --------------------------------------------------------------------------- internal names (hashed)

DIGEST_CHARS = 20
KEY_ENV = "PUBLIC_HYGIENE_DENYLIST_KEY"


def _key_bytes(key: str) -> bytes:
    key = key.strip()
    try:
        return bytes.fromhex(key)
    except ValueError:
        return key.encode("utf-8")


# The denylist key, from the environment. Empty: `internal-name` does not run.
DENYLIST_KEY = _key_bytes(os.environ.get(KEY_ENV, ""))


def term_hash(term: str, key: bytes | None = None) -> str:
    """HMAC-SHA256 of the lower-cased term under the denylist key, truncated."""
    k = DENYLIST_KEY if key is None else key
    return hmac.new(k, term.lower().encode("utf-8"), hashlib.sha256).hexdigest()[:DIGEST_CHARS]


# A fixed public term whose keyed hash `denylist.txt` carries on its `canary:` line, so a
# wrong or rotated key is noticed rather than matching nothing in silence.
CANARY_TERM = "public-hygiene-canary"


def internal_names_enabled() -> bool:
    """False when this run has no denylist key, or a key the denylist was not built with,
    so `internal-name` cannot run."""
    return bool(DENYLIST_KEY) and bool(DENYLIST) and bool(CANARY) and term_hash(CANARY_TERM) == CANARY


def _denylist_lines(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def load_denylist(path: Path = HERE / "denylist.txt") -> frozenset[str]:
    return frozenset(line for line in _denylist_lines(path) if not line.startswith("canary:"))


def load_canary(path: Path = HERE / "denylist.txt") -> str:
    found = [line[len("canary:"):] for line in _denylist_lines(path) if line.startswith("canary:")]
    return found[0] if found else ""


DENYLIST = load_denylist()
CANARY = load_canary()

# Candidate tokens. Each pattern has a lookbehind that refuses a start inside a run of its
# own characters, so a long run is matched once, not once per position.
TOKEN_RE = _c(r"(?<![a-z0-9_.\-])[a-z0-9_](?:[a-z0-9_.\-]{0,200}[a-z0-9_])?", IC)
# A path, relative, absolute or inside a URL (`scheme://host/a/b`); each part is bounded.
PATH_RE = _c(r"(?<![a-z0-9_.\-~/])(?:[a-z][a-z0-9+.\-]{0,20}://[^/\s]{1,253})?/?(?:~|[a-z0-9_.\-]{1,100})(?:/[a-z0-9_.\-]{1,100}){1,20}", IC)
WORD_RE = _c(r"(?<![a-z0-9'])[a-z0-9]{1,60}(?:'s)?(?![a-z0-9])", IC)
REF_RE = _c(r"(?<![a-z0-9_.\-])([a-z0-9][a-z0-9_.\-]{0,60})[#!]\d", IC)
DIGITS = re.compile(r"\d+")


def _token_keys(t: str) -> Iterator[str]:
    yield t
    if any(ch.isdigit() for ch in t):
        yield DIGITS.sub("#", t)
    if len(t) <= 80:
        for i, ch in enumerate(t):
            if ch == "-":
                yield t[:i]
        if "." in t:
            labels = t.split(".")
            yield from labels
            head = labels[0].split("-")[0]
            yield head + "." + ".".join(labels[1:])


def _candidates(text: str) -> Iterator[tuple[int, int, str]]:
    """(start, end, key) for every token, host label, path pair and word pair of `text`."""
    for m in TOKEN_RE.finditer(text):
        for key in _token_keys(m.group(0).lower()):
            yield m.start(), m.end(), key
    for m in PATH_RE.finditer(text):
        segs = m.group(0).lower().split("/")
        for a, b in zip(segs, segs[1:]):
            yield m.start(), m.end(), a + "/" + b
            if "_" in b:
                yield m.start(), m.end(), a + "/" + b.split("_")[0] + "_"
    prev: re.Match[str] | None = None
    prev2: re.Match[str] | None = None
    for m in WORD_RE.finditer(text):
        if prev is not None and m.start() - prev.end() <= 3:
            w1, w2 = prev.group(0).lower(), m.group(0).lower()
            yield prev.start(), m.end(), w1 + " " + w2
            if w1.endswith("'s"):
                yield prev.start(), m.end(), "'s " + w2
            if any(ch.isdigit() for ch in w1 + w2):
                yield prev.start(), m.end(), DIGITS.sub("#", w1 + " " + w2)
            if prev2 is not None and prev.start() - prev2.end() <= 3:
                yield prev2.start(), m.end(), prev2.group(0).lower() + " " + w1 + " " + w2
            prev2 = prev
        else:
            prev2 = None
        prev = m
    for m in REF_RE.finditer(text):
        yield m.start(), m.end(), m.group(1).lower() + "#"


def _find_internal_name(text: str) -> Iterator[tuple[int, int]]:
    if not internal_names_enabled():
        return
    for start, end, key in _candidates(text):
        if term_hash(key) in DENYLIST:
            yield start, end


# --------------------------------------------------------------------------- public URLs

# URLs that are public by construction. Numbers and names inside them (a run id, an app
# id, a mirror's path) are not findings for the rules that honour public URLs.
PUBLIC_URL = _c(
    r"https?://(?:"
    r"github\.com/|(?:[\w\-]+\.)?githubusercontent\.com/|"
    r"(?:www\.)?distronode\.(?:com|ca)(?:/|(?=[\s)\]>]|$))|"
    r"apps\.apple\.com/|play\.google\.com/store/|apps\.microsoft\.com/|"
    r"gitlab\.com/distronode-corporation/(?:" + "|".join(sorted(PUBLIC_GITLAB_PROJECTS)) + r")(?![\w\-]|\.\w)"
    r")[^\s)\]>\"'`]*",
    IC,
)

# --------------------------------------------------------------------------- the rules

RULES: tuple[Rule, ...] = (
    Rule("token", "A credential or token shape (GitHub, GitLab, Stripe, AWS, Google, Slack, npm, PyPI, model vendors, New Relic, Sentry, JWTs, bearer tokens, private key blocks, passwords in URLs, assignments or prose).",
         _spans(*TOKEN_PATTERNS, keep=_token_payload_is_real), honours_public_urls=False, for_everyone=True),
    Rule("secret-name-gsm", "A secret store (GSM, Secret Manager, a vault, CI secrets) named next to secret-like names, or a name called a secret outright.",
         _find_secret_name_gsm),
    Rule("secret-name-list", "Three or more distinct secret-like names (KEY, SECRET, TOKEN, PASSWORD, DSN and similar) in one text.",
         _find_secret_name_list),
    Rule("credential-health", "A note on a credential's state: whether it works in production, whether its expiry was checked, whether it was rotated, whether it is still live.",
         _find_credential_health),
    Rule("monitoring-gap", "A note on what production does not monitor or log.",
         _spans(*MONITORING_GAP)),
    Rule("iam-wif", "IAM or workload identity configuration: policy bindings, attribute conditions, identity pools, principals, role ids, service-account emails.",
         _spans(*IAM_WIF)),
    Rule("operator-command", "An operator command against live infrastructure: cloud CLIs (gcloud, aws), kubectl changes, Secret mounts into pods, secret or variable writes.",
         _spans(*OPERATOR_COMMAND)),
    Rule("internal-email", "An address at the company domain other than the public contact address, or a mailbox name written without its domain.",
         _find_internal_email),
    Rule("private-path", "A local machine path (home directories, the user cache, tool configuration) or a path given as the private monorepo's.",
         _find_private_path),
    Rule("ip-address", "An IP address or CIDR range, other than loopback, the documentation ranges, the standard private ranges as such, and the public resolvers.",
         _find_ip),
    Rule("private-gitlab", "A link into the organization's GitLab group other than its public mirrors.",
         _find_private_gitlab),
    Rule("private-reference", "A reference into the private tracker: GitLab issue or merge request numbers, note ids, confidential issues, monorepo commits or branches.",
         _find_private_reference),
    Rule("cloud-account-id", "A cloud or vendor account id: GCP project numbers, AWS account ids and ARNs, ECR registries, account query parameters, Stripe or Twilio account ids.",
         _spans(*CLOUD_ACCOUNT_ID)),
    Rule("console-link", "A link into a vendor console (cloud, New Relic, Cloudflare, store consoles) or a vendor organization's host or ingest id.",
         _spans(*CONSOLE_LINK)),
    Rule("cloud-resource", "A cloud resource id (EC2 instance, security group, VPC and similar).",
         _spans(*CLOUD_RESOURCE)),
    Rule("internal-host", "An internal host name: .internal, .local, .lan, .corp, .svc and cluster-local services.",
         _spans(CLUSTER_LOCAL, INTERNAL_SUFFIX)),
    Rule("internal-name", "A name from the organization's own estate (components, machines, sessions, hosts, accounts), matched by hash against a denylist.",
         _find_internal_name),
)

RULES_BY_ID = {rule.id: rule for rule in RULES}


# At most this many combining marks in a row (UAX #15 "stream-safe" text). CPython 3.12,
# the runner's, reorders a long run of marks in quadratic time inside NFKC.
MAX_MARK_RUN = 30

# Characters that render as nothing (Unicode Default_Ignorable_Code_Point, which is wider
# than category Cf: variation selectors, the combining grapheme joiner, Hangul fillers,
# Mongolian selectors, tag characters), plus the blank braille pattern.
_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
    (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x2800, 0x2800),
    (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
)
_IGNORABLE_STARTS = [a for a, _ in _IGNORABLE_RANGES]


def _ignorable(cp: int) -> bool:
    i = bisect.bisect_right(_IGNORABLE_STARTS, cp) - 1
    return i >= 0 and cp <= _IGNORABLE_RANGES[i][1]


def _strip_format_chars(text: str) -> str:
    """Remove every invisible character (category Cf and the other default-ignorable code
    points), so none can hide a match, and keep at most MAX_MARK_RUN combining marks in a
    row, so NFKC stays linear."""
    if text.isascii():
        return text
    out: list[str] = []
    run = 0
    for ch in text:
        if unicodedata.category(ch) == "Cf" or _ignorable(ord(ch)):
            continue
        run = run + 1 if unicodedata.combining(ch) else 0
        if run <= MAX_MARK_RUN:
            out.append(ch)
    return "".join(out)


# Typographic apostrophes (right single quotation mark, modifier letter apostrophe and
# their kin), as macOS, iOS and word processors type them, read as the ASCII one.
_APOSTROPHES = dict.fromkeys(map(ord, chr(0x2019) + chr(0x2018) + chr(0x02BC) + chr(0x2032) + chr(0xFF07)), "'")


def _normalize(text: str) -> tuple[str, bool]:
    """The scanned form of `text`, and whether it was cut at MAX_SCAN_CHARS."""
    text = _strip_format_chars(text.replace("\r\n", "\n").replace("\r", "\n"))
    folded = unicodedata.normalize("NFKC", text)
    if len(folded) > 2 * len(text) + 16:
        folded = text  # an expansion attack (U+FDFA is 18 characters under NFKC)
    folded = folded.translate(_APOSTROPHES)  # NFKC keeps typographic apostrophes
    return folded[:MAX_SCAN_CHARS], len(folded) > MAX_SCAN_CHARS


def normalize(text: str) -> str:
    """Line ends as LF, invisible characters removed, mark runs capped, NFKC (unless it
    would more than double the text), cut at MAX_SCAN_CHARS. Offsets in findings refer to
    this form."""
    return _normalize(text)[0]


def was_truncated(text: str | None) -> bool:
    """True when `scan` saw only part of `text`: the cut is measured on the normalized
    form, which NFKC can make longer than the text itself."""
    return bool(text) and _normalize(text)[1]


def _inside(span: tuple[int, int], ranges: list[tuple[int, int]], starts: list[int]) -> bool:
    """Whether `span` lies inside one of `ranges` (sorted, not overlapping; `starts` are
    their start offsets). A binary search, so many findings among many URLs stay linear."""
    i = bisect.bisect_right(starts, span[0]) - 1
    return i >= 0 and span[1] <= ranges[i][1]


def scan(text: str | None, *, outside: bool = False) -> list[Finding]:
    """Every finding in `text`, ordered by position. Never includes matched text.

    `outside=True` is for an author outside the organization (no write access, not a
    bot): only the rules marked `for_everyone` apply. An outsider's crash log holds their
    own paths and addresses, which are theirs to share and say nothing of ours."""
    if not text:
        return []
    text = normalize(text)
    public = [(m.start(), m.end()) for m in PUBLIC_URL.finditer(text)]
    starts = [a for a, _ in public]
    findings: list[Finding] = []
    for rule in RULES:
        if outside and not rule.for_everyone:
            continue
        for start, end in rule.finder(text):
            if rule.honours_public_urls and _inside((start, end), public, starts):
                continue
            findings.append(Finding(rule.id, start, end))
    findings.sort(key=lambda f: (f.start, f.rule))
    return findings


def rule_ids(*texts: str | None, outside: bool = False) -> list[str]:
    """The sorted, distinct rule ids that fire on any of `texts`."""
    return sorted({f.rule for text in texts for f in scan(text, outside=outside)})


def is_skipped_author(login: str | None, account_type: str | None, *, comment: bool = True) -> bool:
    """Whether text by this author is skipped. Review bots are skipped for comments only
    (`comment=True`: comments, reviews, review comments); a title, a description or a
    commit by one is checked like anyone's."""
    if account_type != "Bot":
        return False
    return (login or "") in (SKIPPED_BOTS if comment else UPSTREAM_BOTS)


# The author associations of the organization's own people.
INSIDE_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})


def is_outside_author(association: str | None, account_type: str | None) -> bool:
    """An author with no write access who is not a bot. Unknown counts as inside."""
    if account_type == "Bot" or association is None:
        return False
    return association.upper() not in INSIDE_ASSOCIATIONS


def rules_table() -> str:
    lines = ["| Rule | What it covers |", "|---|---|"]
    lines += [f"| `{r.id}` | {r.description} |" for r in RULES]
    return "\n".join(lines)


def _main(argv: list[str]) -> int:
    if argv == ["--list"]:
        print(rules_table())
        return 0
    if argv == ["--self-test"]:
        import unittest

        suite = unittest.defaultTestLoader.discover(str(HERE), pattern="test_*.py", top_level_dir=str(HERE))
        return 0 if unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful() else 1
    if len(argv) == 4 and argv[0] == "--hash-terms" and argv[2] == "--key-file":
        key = _key_bytes(Path(argv[3]).read_text(encoding="utf-8"))
        if len(key) < 16:
            print("The key file must hold at least 16 bytes (32 hex digits).", file=sys.stderr)
            return 2
        print("canary:" + term_hash(CANARY_TERM, key))
        for line in Path(argv[1]).read_text(encoding="utf-8").splitlines():
            term = line.strip()
            if term and not term.startswith("#"):
                print(term_hash(term, key))
        return 0
    if not argv or any(a.startswith("-") and a != "-" for a in argv):
        print(__doc__, file=sys.stderr)
        return 2
    status = 0
    for name in argv:
        data = sys.stdin.read() if name == "-" else Path(name).read_text(encoding="utf-8", errors="replace")
        ids = rule_ids(data)
        print(f"{name}: {', '.join(ids) if ids else 'clean'}")
        status |= bool(ids)
    return status


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
