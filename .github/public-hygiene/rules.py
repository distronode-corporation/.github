#!/usr/bin/env python3
"""Rules for text that must not appear in a public repository's issues and pull requests.

    python3 rules.py --list            # the rules table
    python3 rules.py FILE [FILE...]    # scan files ('-' is stdin); prints rule ids only
    python3 rules.py --self-test       # run test_rules.py

Every public repository in the organization calls the reusable workflow
`.github/workflows/public-hygiene.yml`, which scans pull request, issue, review and
comment text with these rules. The same file is what an author runs on a body before
`gh pr create` or `gh issue create`.

A finding names a rule id and nothing else. Nothing in this module returns, prints or
logs the text that matched: `Finding` holds the rule id and offsets only, and the CLI
prints rule ids. That is the point of the check, since the run log and the bot's comment
are as public as the text they flag.

What is out of scope, on purpose:

- The em and en dash rule of the file-level `check-public-hygiene.py`. It is a style
  rule for files the organization writes, not an exposure rule, and bodies written by
  outside contributors and by bots carry dashes.
- That file's blanket GitLab rule. A pull request may cite an upstream bug on any
  GitLab host (GNOME, freedesktop.org). Only the organization's own GitLab group is
  checked here (`private-gitlab`).
- That file's phone rule (district-linux, district-windows, district-core-rust). The
  apps are diallers, and their pull requests discuss example and malformed numbers as a
  matter of course, which is why district-core-swift's copy leaves it out too.
- Subdomains of the company domain other than the origins. Several are public service
  endpoints the apps use; the origins are not (`internal-host`).

Documented exceptions (the allowlist), each next to the rule it narrows:

- `internal-email`: the public contact address (PUBLIC_ADDRESSES).
- `private-gitlab`: the group's public mirrors and profile (PUBLIC_GITLAB_PROJECTS).
- Every rule but `token`: text inside a public URL (PUBLIC_URL): GitHub, the public
  website, and the App Store, Google Play and Microsoft Store pages, so a store id or a
  run id in a link is not a finding.
- `ip-address`: loopback, the documentation ranges and the public resolvers.
- `token`: test-fixture shapes (one repeated character, the AWS documentation key).
- `private-path`: placeholder home directories and an app's own cache directory.
- `private-path`: the website's `src/` and `contracts/`, which the apps' public trees
  already cite throughout.
- `secret-name-*`: the names every workflow uses, browser-public names, error codes.

Planted examples in test_rules.py are assembled at run time, so that this repository's
own secret scan and dash check do not trip on them.
"""

from __future__ import annotations

import ipaddress
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

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

# Authors whose text is generated from public upstream content (release notes, changelogs)
# or from the public diff, and is skipped. Matched on login AND account type, so a user named like a bot is still
# scanned.
# Code review bots are skipped too: what they quote comes from the pull request's own
# public diff, and their comments cannot be edited by anyone here.
SKIPPED_BOTS = frozenset(
    {
        "dependabot[bot]",
        "github-actions[bot]",
        "renovate[bot]",
        "sentry[bot]",
        "seer-by-sentry[bot]",
        "Copilot",  # the Copilot reviewer's login (account type Bot)
        "copilot-pull-request-reviewer[bot]",
    }
)


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


# --------------------------------------------------------------------------- helpers


def _spans(*patterns: re.Pattern[str], keep: Callable[[re.Match[str]], bool] | None = None):
    def finder(text: str) -> Iterator[tuple[int, int]]:
        for pattern in patterns:
            for m in pattern.finditer(text):
                if keep is None or keep(m):
                    yield m.start(), m.end()

    return finder


def _c(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


IC = re.IGNORECASE

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
    _c(r"(?<![\w-])xox[abposr]-[A-Za-z0-9\-]{10,}"),
    _c(r"hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"),
    _c(r"(?<![\w-])npm_[A-Za-z0-9]{36}(?![\w-])"),
    _c(r"(?<![\w-])pypi-AgE[A-Za-z0-9_\-]{50,}"),
    _c(r"(?<![\w-])sk-ant-[A-Za-z0-9_\-]{20,}"),
    _c(r"(?<![\w-])sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}"),
    _c(r"(?<![\w-])NR(?:AK|AA|II|JS)-[A-Z0-9]{20,}"),
    _c(r"(?<![\w-])SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{30,}"),
    _c(r"(?<![\w-])SK[0-9a-f]{32}(?![\w-])"),
    _c(r"(?<![\w-])KEY[0-9A-F]{32}_[A-Za-z0-9]{16,}"),
    _c(r"(?<![\w-])sntry[su]_[A-Za-z0-9+/=_\-]{20,}"),
    _c(r"(?<![\w-])eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    _c(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
    # A password in a URL's user info.
    _c(r"(?<![\w-])[a-z][a-z0-9+.\-]*://[^\s/:@]+:[^\s/@]{6,}@[\w.\-]+", IC),
    # `password = value` and friends, with a value that is not a placeholder.
    _c(
        # Prefixed names and flags count too: `DB_PASSWORD=`, `CLIENT_SECRET:`, `--password=`.
        r"(?<![\w])(?:-{1,2})?(?:[A-Za-z0-9]+[_\-])*(?:password|passwd|secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_\-+/=.]{12,}",
        IC,
    ),
)


def _token_payload_is_real(m: re.Match[str]) -> bool:
    """Drop the shapes test fixtures use: one repeated character, a short alphabet, or the
    AWS documentation key that ends in EXAMPLE."""
    text = m.group(0)
    if text.upper().endswith("EXAMPLE"):
        return False
    assignment = ASSIGNMENT_VALUE.search(text)
    if assignment:
        # `password: Simulator.app` is prose; a value with no digit is a word, not a secret.
        value = assignment.group(1)
        return bool(re.search(r"\d", value) and re.search(r"[A-Za-z]", value)) and len(set(value)) >= 8
    body = re.sub(r"^[A-Za-z]+[_\-]", "", text)
    return len(set(body)) >= 8


ASSIGNMENT_VALUE = _c(r"[:=]\s*['\"]?([A-Za-z0-9_\-+/=.]{12,})$")


# --------------------------------------------------------------------------- secret names

# An UPPER_SNAKE name with a secret-like word in it. At least one underscore, so a bare
# `TOKEN` or `KEY` in a sentence is not a name.
SECRET_NAME_SNAKE = _c(
    r"(?<![\w-])[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_"
    r"(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?|DSN|PAT|PEM|P8|CERT|SELLER_ID|TENANT_ID|CLIENT_ID)"
    r"(?:_(?:ID|B64|BASE64|JSON|FILE|PATH|V\d+|\d+))?(?![\w-])"
)
# Error codes and states read like secret names (`INVALID_TOKEN`) and are not.
ERROR_CODE_PREFIX = _c(r"(?:INVALID|MISSING|EXPIRED|BAD|NO|WRONG|UNKNOWN|REVOKED|STALE|REFRESH|RESET|ROTATE)_")
# Values meant to be public: a browser bundle's variables and publishable keys.
PUBLIC_NAME = _c(r"(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_).*|.*_(?:PUBLIC|PUBLISHABLE)_KEY(?:_ID)?")
# A kebab-case secret name, the shape Secret Manager names take.
SECRET_NAME_KEBAB = _c(
    r"(?<![\w./-])[a-z][a-z0-9]*(?:-[a-z0-9]+)*-(?:env|key|keys|secret|secrets|token|dsn|password|credentials|pem|p8)(?![\w-])"
)
# Names every workflow uses, which say nothing about the organization.
COMMON_SECRET_NAMES = frozenset(
    {"GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"}
)
SECRET_STORE = _c(r"(?<![\w-])(?:GSM|Secret\s+Manager|secretmanager|gcloud\s+secrets)(?![\w-])")
# The cluster's env Secret, by name.
CLUSTER_ENV_SECRET = _c(r"(?<![\w-])distronode-env(?:-snapshot)?(?![\w-])", IC)


def _secret_names(text: str) -> Iterator[re.Match[str]]:
    for m in SECRET_NAME_SNAKE.finditer(text):
        name = m.group(0)
        if name in COMMON_SECRET_NAMES or ERROR_CODE_PREFIX.match(name) or PUBLIC_NAME.fullmatch(name):
            continue
        yield m


def _paragraphs(text: str) -> Iterator[tuple[int, str]]:
    start = 0
    for m in re.finditer(r"\n[ \t]*\n", text):
        yield start, text[start : m.start()]
        start = m.end()
    yield start, text[start:]


def _find_secret_name_gsm(text: str) -> Iterator[tuple[int, int]]:
    for m in CLUSTER_ENV_SECRET.finditer(text):
        yield m.start(), m.end()
    for offset, para in _paragraphs(text):
        store = SECRET_STORE.search(para)
        if not store:
            continue
        names = list(_secret_names(para)) + list(SECRET_NAME_KEBAB.finditer(para))
        if names:
            yield offset + store.start(), offset + store.end()


def _find_secret_name_list(text: str) -> Iterator[tuple[int, int]]:
    names: dict[str, re.Match[str]] = {}
    for m in _secret_names(text):
        names.setdefault(m.group(0), m)
    if len(names) >= 3:
        first = min(m.start() for m in names.values())
        last = max(m.end() for m in names.values())
        yield first, last


# --------------------------------------------------------------------------- credential health

CREDENTIAL_HEALTH = (
    _c(r"\bnot\s+(?:yet\s+)?(?:been\s+)?(?:verified|tested|confirmed|proven)\s+(?:in|on|against)\s+prod(?:uction)?\b", IC),
    _c(r"\b(?:unverified|untested)\s+in\s+prod(?:uction)?\b", IC),
    _c(r"\bexpir(?:y|ation|es)(?:\s+date)?\s+(?:is\s+|was\s+|has\s+)?(?:not|never)\s+(?:yet\s+)?(?:been\s+)?(?:checked|verified|known|confirmed)\b", IC),
    _c(r"\bexpiry\s+(?:unknown|unchecked)\b", IC),
    _c(r"\bverified\s*[=:]\s*false\b", IC),
)

# Rotation wording, which also describes images and screens, so it counts only with a
# credential word within CREDENTIAL_WINDOW characters either side.
ROTATION = (
    _c(r"\bun-?rotated\b", IC),
    _c(r"\b(?:not|never)\s+(?:yet\s+)?(?:been\s+)?rotated\b", IC),
    _c(r"\brotation\s+(?:is\s+)?(?:overdue|pending|due|outstanding|not\s+done)\b", IC),
)
CREDENTIAL_WORD = _c(r"\b(?:key|keys|secret|secrets|token|tokens|password|passwords|credential|credentials|cert|certificate|pat)\b", IC)
CREDENTIAL_WINDOW = 60


def _find_credential_health(text: str) -> Iterator[tuple[int, int]]:
    for pattern in CREDENTIAL_HEALTH:
        for m in pattern.finditer(text):
            yield m.start(), m.end()
    for pattern in ROTATION:
        for m in pattern.finditer(text):
            window = text[max(0, m.start() - CREDENTIAL_WINDOW) : m.end() + CREDENTIAL_WINDOW]
            if CREDENTIAL_WORD.search(window):
                yield m.start(), m.end()


# --------------------------------------------------------------------------- IAM and WIF

IAM_WIF = (
    _c(r"\bgcloud\s+iam\b", IC),
    _c(r"\b(?:add|remove|set|get)-iam-policy(?:-binding)?\b", IC),
    _c(r"\battribute[._-]?condition\b", IC),
    _c(r"--attribute-mapping\b", IC),
    _c(r"\bworkloadIdentityPools\b"),
    _c(r"--workload-identity-pool\b", IC),
    _c(r"\bprincipal(?:Set)?://", IC),
    _c(r"(?<![\w/-])roles/(?:[a-z][A-Za-z0-9]*\.[A-Za-z0-9.]+|owner|editor|viewer)\b"),
    _c(r"[A-Za-z0-9._\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com\b", IC),
    _c(r"[A-Za-z0-9._\-]+\.svc\.id\.goog\b", IC),
    _c(r"\b(?:iam|sts):[A-Z][A-Za-z]+\b"),
)

# --------------------------------------------------------------------------- operator commands

OPERATOR_COMMAND = (
    _c(r"\bgcloud\s+(?:alpha\s+|beta\s+)?[a-z][a-z\-]+\s+[a-z][a-z\-]+", IC),
    _c(r"\baws\s+(?:iam|sts|ssm|secretsmanager|kms|organizations|ec2|ecr|sso)\s+[a-z][a-z\-]+"),
    _c(r"\bkubectl\s+(?:(?:-n|--namespace|--context)[ =]\S+\s+)*(?:set|patch|apply|edit|create|delete|rollout|scale|annotate|label|replace|exec|cp|drain|cordon)\b", IC),
    _c(r"\benvFrom\b"),
    _c(r"\bgh\s+secret\s+(?:set|delete)\b", IC),
    _c(r"\bglab\s+variable\s+(?:set|update|delete)\b", IC),
    _c(r"\bwrangler\s+secret\s+(?:put|delete|bulk)\b", IC),
)

# --------------------------------------------------------------------------- email

EMAIL = _c(
    r"(?<![\w.%+\-])[A-Za-z0-9_%+\-](?:[A-Za-z0-9._%+\-]*[A-Za-z0-9_%+\-])?"
    r"@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,})(?![\w\-])"
)
# A mailbox name with the @ and no domain (`name@`, then the domain spelt out in words).
# Not before a version operator, so `pkg@^1.2` is not a mailbox.
# Lower case only: mailbox names are written that way, and a CamelCase name before an
# @ is a CI task or an annotation (`PublishPipelineArtifact@`).
BARE_MAILBOX = _c(r"(?<![\w.%+\-@/])[a-z][a-z0-9._%+\-]*[a-z0-9]@(?=$|[\s),.;:!?'\"`\]])", re.M)


def _find_internal_email(text: str) -> Iterator[tuple[int, int]]:
    for m in EMAIL.finditer(text):
        domain = m.group(1).lower()
        if not any(domain == d or domain.endswith("." + d) for d in COMPANY_DOMAINS):
            continue
        if m.group(0).lower() in PUBLIC_ADDRESSES:
            continue
        yield m.start(), m.end()
    for m in BARE_MAILBOX.finditer(text):
        yield m.start(), m.end()


# --------------------------------------------------------------------------- private paths

PRIVATE_PATH = (
    _c(r"(?<![\w.\-])/home/(?!runner/)[a-z_][\w.\-]*/"),
    _c(r"(?<![\w.\-])/Users/(?!runner/|Shared/)[A-Za-z][\w.\-]*/"),
    _c(r"(?<![\w])[A-Za-z]:\\{1,2}Users\\{1,2}(?!runneradmin\\|Public\\|Default\\)[^\\\s]+", IC),
    _c(r"(?:~|\$HOME|\$\{HOME\})/\.(?:cache|claude|ssh|aws|gnupg|kube|docker|netrc|pgpass)\b"),
    _c(r"(?:~|\$HOME|\$\{HOME\})/\.config/(?:mcp|gcloud|gh|glab-cli)\b"),
    # Paths that exist only in the private monorepo, and in it hold deploy, CI or
    # operator material. The website's `src/`, `prisma/` and `contracts/` are left out:
    # the apps mirror that code and those fixtures, and their public trees cite those
    # paths hundreds of times.
    _c(r"(?<![\w./\-])distronode-website/(?!(?:src|contracts)(?![\w.\-])|prisma/schema)[\w.\-]+"),
    _c(r"(?<![\w./\-])(?:distronode-(?:marketing|letterhead|socialposts)|district-voice-agent|telemetry-broadcaster|sean-files|output_cache)/"),
    _c(r"(?<![\w./\-])infra/(?:ci|cloudflare|sentry|scheduler|host|newrelic|alloy|k8s)/"),
    _c(r"(?<![\w./\-])docs/(?:infra_|district_|open_items|project_status|agent_tooling|runbook_|website_readme)[\w.\-/]*"),
    _c(r"(?<![\w./\-])k8s/aws-(?:ca|eu|apac)\b"),
    _c(r"(?<![\w./\-])ci/deploy-origins"),
)


# Home directories that are placeholders in documentation, not someone's machine.
PLACEHOLDER_USER = _c(r"(?:/home/|/Users/|[A-Za-z]:\\{1,2}Users\\{1,2})(?:alice|bob|carol|user|username|you|me|name|example|x+|[<%$]\S*)[/\\]?", IC)


def _find_private_path(text: str) -> Iterator[tuple[int, int]]:
    for pattern in PRIVATE_PATH:
        for m in pattern.finditer(text):
            if PLACEHOLDER_USER.fullmatch(m.group(0).rstrip("`)'\".,;:")):
                continue
            # `~/.cache/district...` is an app's cache directory, documented publicly.
            if text[m.end() : m.end() + 9].lower() == "/district":
                continue
            yield m.start(), m.end()


# --------------------------------------------------------------------------- machine names

MACHINE_NAME = (
    _c(r"\b(?:ThinkPad|iMac|Latitude)(?:'s)?\s+(?:manager|session|worker|box|runner|handoff|agent|clone|checkout|worktree|lane)s?\b"),
    _c(r"\b(?:on|from|to|via|by|in|at)\s+the\s+(?:ThinkPad|iMac|Latitude)\b"),
    _c(r"(?<![\w-])distronode-(?:thinkpad|imac|latitude)(?![\w-])", IC),
    _c(r"(?<![\w-])distronode-com-c\d+(?![\w-])", IC),
)

# --------------------------------------------------------------------------- IP addresses

IPV4 = _c(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(/\d{1,2})?(?![\w]|\.\d)")
IPV6 = _c(r"(?<![\w:])((?:[0-9a-fA-F]{1,4}:){1,7}(?::|(?::[0-9a-fA-F]{1,4}){1,6}|[0-9a-fA-F]{1,4}))(/\d{1,3})?(?![\w:])")
VERSION_CONTEXT = _c(
    r"(?:\bv|\bversion\s*:?\s*|\bver\.?\s*|\brelease\s+|\bbuild\s+|\bmsix\s+|\bpackage\s+|\bpolicy\s+|\bsection\s+|"
    # Version operators only: a bare `@` or `=` is also how a host is written
    # (`user@host`, `HOST=addr`, `--server=addr`).
    r"(?:==|>=|<=|~=|!=|\^|~|\u2192|->)\s*|\bbump(?:s|ed)?\s+)$",
    IC,
)
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


# Addresses every network document uses: the public resolvers and the cloud metadata
# address. They identify nothing of ours.
WELL_KNOWN_ADDRESSES = frozenset(
    {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "169.254.169.254"}
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
        if not cidr:
            # A four-part version number (`3.0.1.0`): written after a version word, or
            # ending in .0, which a host address never does without a prefix length.
            if VERSION_CONTEXT.search(text[max(0, m.start() - 16) : m.start()]):
                continue
            if m.group(1).endswith(".0"):
                continue
            # A build suffix (`26.0.2.1+1`, `1.2.3.4-beta`) makes it a version.
            if re.match(r"[+\-][0-9A-Za-z]", text[m.end() : m.end() + 2]):
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
        if any(addr6 in net for net in DOC_NETS):
            continue
        # Global unicast and unique local only; this keeps `a::b` style code out.
        if not (raw.lower().startswith(("2", "3", "fc", "fd"))):
            continue
        yield m.start(), m.end()


# --------------------------------------------------------------------------- GitLab

GITLAB_GROUP_URL = _c(r"gitlab\.com/distronode-corporation(?:/(?P<project>[A-Za-z0-9_.\-]+))?", IC)


def _find_private_gitlab(text: str) -> Iterator[tuple[int, int]]:
    for m in GITLAB_GROUP_URL.finditer(text):
        project = m.group("project")
        if project is None:
            continue  # the group page lists only public projects to the public
        name = project.lower()
        if name.endswith(".git"):
            name = name[: -len(".git")]
        if name in PUBLIC_GITLAB_PROJECTS:
            continue
        yield m.start(), m.end()


PRIVATE_REFERENCE = (
    _c(r"\bgitlab\s*(?:issue|mr|merge\s+request|work\s+item|epic)?\s*[#!]\s?\d+", IC),
    _c(r"\b(?:MR|merge\s+request)\s*!\d+", IC),
    _c(r"\bnote\s+(?:id\s+)?#?\d{8,}\b", IC),
    _c(r"\bdecisions[\s\-]log\b", IC),
    _c(r"(?<![\w-])distronode-com[#!]\d+"),
    _c(r"(?<![\w-])distronode-corporation/distronode-com(?![\w-])"),
    _c(r"\bmonorepo(?:'s)?\s+(?:commit|sha|branch|main|MR|merge\s+request|pipeline|job)\b", IC),
)

# --------------------------------------------------------------------------- cloud accounts and resources

CLOUD_ACCOUNT_ID = (
    _c(r"\barn:aws[\w\-]*:[\w\-]*:[\w\-]*:\d{12}:"),
    _c(r"\b\d{12}\.dkr\.ecr\."),
    _c(r"(?<![\w/])projects/\d{6,}\b"),
    _c(r"\b(?:aws|gcp|google\s+cloud|new\s+relic|sentry|stripe|cloudflare|twilio|telnyx)\b[^\n]{0,30}?\b(?:account|project|org(?:anization)?)(?:\s+(?:id|number|no\.?))?\s*[:#=]?\s*\d{6,}\b", IC),
    _c(r"\b(?:project|account)\s+(?:id|number|no\.?)\s*[:#=]?\s*\d{6,}\b", IC),
    _c(r"\bproject\b[^\n]{0,40}?\bnumber\b\W{0,3}\d{6,}\b", IC),
    _c(r"(?<![\w.\-/])\d{4}-\d{4}-\d{4}(?![\w\-])"),
    _c(r"\b\d{6,}-compute@developer\.gserviceaccount\.com\b", IC),
    _c(r"\bservice-\d{6,}@"),
    _c(r"(?<![\w-])acct_[A-Za-z0-9]{16}(?![\w-])"),
    _c(r"(?<![\w-])AC[0-9a-f]{32}(?![\w-])"),
    _c(r"(?<![\w/])projects/[a-z][a-z0-9\-]{4,28}[a-z0-9]/(?:secrets|locations|serviceAccounts|keyRings|topics|subscriptions|global|zones|regions|instances|databases)\b"),
)

CLOUD_RESOURCE = (
    _c(r"(?<![\w-])(?:i|sg|subnet|vpc|vol|eni|ami|igw|nat|rtb)-[0-9a-f]{17}(?![\w-])"),
    _c(r"(?<![\w-])distronode-(?:web|origin)-[a-z0-9][a-z0-9\-]*", IC),
)

# --------------------------------------------------------------------------- ported rules

# From check-public-hygiene.py: private-use host suffixes, lower case only (a qualified
# enum case such as `Mode.internal` is not a host), and the origins behind the edge.
#
# Narrower than the file check, because prose quotes code: `self.local`, `config.internal`
# and the `okhttp3.internal` package read as host names. A cluster-local service name is
# always a host; the other suffixes count only in a host's position: after `://` or `@`,
# or before a port or a path.
CLUSTER_LOCAL = _c(r"(?<![\w.\-])(?:[a-z0-9\-]+\.)+svc\.cluster\.local(?![\w\-])")
INTERNAL_SUFFIX = _c(
    r"(?:(?<=://)|(?<=@))(?:[a-z0-9\-]+\.)+(?:internal|local|lan|corp)(?![\w\-]|\.\w)"
    r"|(?<![\w.\-])(?:[a-z0-9\-]+\.)+(?:internal|local|lan|corp)(?=:\d|/)"
)
ORIGIN_HOST = _c(r"(?<![\w.\-])(origin(?:-[a-z0-9]+)*\.distronode\.(?:com|ca))(?![\w\-])", IC)

# --------------------------------------------------------------------------- public URLs

# URLs that are public by construction. Numbers and names inside them (a run id, an app
# id, a mirror's path) are not findings for the rules that honour public URLs.
PUBLIC_URL = _c(
    r"https?://(?:"
    r"github\.com/|(?:[\w\-]+\.)?githubusercontent\.com/|"
    r"(?:www\.)?distronode\.(?:com|ca)(?:/|(?=[\s)\]>]|$))|"
    r"apps\.apple\.com/|play\.google\.com/|apps\.microsoft\.com/|"
    r"gitlab\.com/distronode-corporation/(?:" + "|".join(sorted(PUBLIC_GITLAB_PROJECTS)) + r")(?![\w.\-])"
    r")[^\s)\]>\"'`]*",
    IC,
)

# --------------------------------------------------------------------------- the rules

RULES: tuple[Rule, ...] = (
    Rule("token", "A credential or token shape (GitHub, GitLab, Stripe, AWS, Google, Slack, npm, PyPI, model vendors, New Relic, Sentry, JWTs, private key blocks, passwords in URLs or assignments).",
         _spans(*TOKEN_PATTERNS, keep=_token_payload_is_real), honours_public_urls=False),
    Rule("secret-name-gsm", "A secret store (GSM, Secret Manager) named next to secret-like names, or the cluster's env Secret by name.",
         _find_secret_name_gsm),
    Rule("secret-name-list", "Three or more distinct secret-like names (KEY, SECRET, TOKEN, PASSWORD, DSN and similar) in one text.",
         _find_secret_name_list),
    Rule("credential-health", "A note on a credential's state: whether it works in production, whether its expiry was checked, whether it was rotated.",
         _find_credential_health),
    Rule("iam-wif", "IAM or workload identity configuration: policy bindings, attribute conditions, identity pools, principals, role ids, service-account emails.",
         _spans(*IAM_WIF)),
    Rule("operator-command", "An operator command against live infrastructure: cloud CLIs (gcloud, aws), kubectl changes, Secret mounts into pods, secret or variable writes.",
         _spans(*OPERATOR_COMMAND)),
    Rule("internal-email", "An address at the company domain other than the public contact address, or a mailbox name written without its domain.",
         _find_internal_email),
    Rule("private-path", "A local machine path (home directories, the user cache, tool configuration) or a path that exists only in the private monorepo.",
         _find_private_path),
    Rule("machine-name", "An internal machine or agent-session name.",
         _spans(*MACHINE_NAME)),
    Rule("ip-address", "An IP address or CIDR range, other than loopback and the documentation ranges.",
         _find_ip),
    Rule("private-gitlab", "A link into the organization's GitLab group other than its public mirrors.",
         _find_private_gitlab),
    Rule("private-reference", "A reference into the private tracker: GitLab issue or merge request numbers, note ids, the decision record, monorepo commits or branches.",
         _spans(*PRIVATE_REFERENCE)),
    Rule("cloud-account-id", "A cloud or vendor account id: GCP project numbers, AWS account ids and ARNs, ECR registries, Stripe or Twilio account ids.",
         _spans(*CLOUD_ACCOUNT_ID)),
    Rule("cloud-resource", "A cloud resource id or internal host name (EC2 and VPC ids, origin hosts by machine name).",
         _spans(*CLOUD_RESOURCE)),
    Rule("internal-host", "An internal host name: .internal, .local, .lan, .corp, cluster-local services, and the origins behind the edge.",
         _spans(CLUSTER_LOCAL, INTERNAL_SUFFIX, ORIGIN_HOST)),
)

RULES_BY_ID = {rule.id: rule for rule in RULES}

_INVISIBLE = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)


def normalize(text: str) -> str:
    """NFKC, invisible characters removed, so a pasted zero-width space does not hide a
    match. Offsets in findings refer to this form."""
    return unicodedata.normalize("NFKC", text).translate(_INVISIBLE)


def _inside(span: tuple[int, int], ranges: list[tuple[int, int]]) -> bool:
    return any(a <= span[0] and span[1] <= b for a, b in ranges)


def scan(text: str | None) -> list[Finding]:
    """Every finding in `text`, ordered by position. Never includes matched text."""
    if not text:
        return []
    text = normalize(text)
    public = [(m.start(), m.end()) for m in PUBLIC_URL.finditer(text)]
    findings: list[Finding] = []
    for rule in RULES:
        for start, end in rule.finder(text):
            if rule.honours_public_urls and _inside((start, end), public):
                continue
            findings.append(Finding(rule.id, start, end))
    findings.sort(key=lambda f: (f.start, f.rule))
    return findings


def rule_ids(*texts: str | None) -> list[str]:
    """The sorted, distinct rule ids that fire on any of `texts`."""
    return sorted({f.rule for text in texts for f in scan(text)})


def is_skipped_author(login: str | None, account_type: str | None) -> bool:
    return account_type == "Bot" and (login or "") in SKIPPED_BOTS


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

        here = Path(__file__).resolve().parent
        suite = unittest.defaultTestLoader.discover(str(here), pattern="test_*.py", top_level_dir=str(here))
        return 0 if unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful() else 1
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
