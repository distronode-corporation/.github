# Governance

This file says how the open-source projects of Distronode Corporation are run: who decides,
how a change gets in, who does what, what happens when someone reports a vulnerability, and
what happens if a maintainer is no longer available.
It is the organization's default, so it applies to every repository here that does not have a
GOVERNANCE.md of its own. Where a repository's own CONTRIBUTING.md or SECURITY.md says more,
that file is the detail and this one is the summary.

## The model

Every project in this organization is owned and maintained by Distronode Corporation, a
Canadian company. It is a company-maintained model, not a foundation: there is no elected
committee and no vote. Distronode decides what each project does, and the people who act for
it in that role are the maintainers and code owners described below.

Most decisions are made in public, in the repository: an issue for a problem or a proposal,
a pull request for a change, and the discussion on either. A project's direction, a breaking
change or a new version of a protocol is decided by Distronode and written down in the
repository (its README, CHANGELOG and, where it has them, its roadmap, specification or
decision log), so the reasoning is public with the change.

## Roles

| Role | Who | Responsibilities |
| --- | --- | --- |
| Contributor | Anyone who opens an issue, a discussion or a pull request | Follow the repository's CONTRIBUTING.md and the Code of Conduct. Say why a change is needed, with its tests and docs in the same pull request. |
| Reviewer | Anyone may review a pull request in public. A review counts toward merging only from a code owner. | Read the change against the repository's rules: tests and coverage, style, documentation kept current, and its security model where it has one. Ask for changes in a review thread, so the thread has to be resolved before the merge. |
| Maintainer | Distronode Corporation, through the accounts it gives write access to a repository | Triage issues and pull requests, keep CI green and dependencies current, keep the documentation consistent with the code, and write or merge changes once they are approved. |
| Code owner | The account or team named in the repository's `.github/CODEOWNERS` file | Approve every change to the default branch. The account that pushed a change can never be the one that approves it. |
| Security contact | Distronode Corporation, at **opensource@distronode.com** and through each repository's private vulnerability reporting | Receive vulnerability reports, acknowledge them, coordinate the fix and the advisory, and credit the reporter. See [Vulnerability response](#vulnerability-response). |
| Release manager | A maintainer, for the release in hand | Bump the version in a pull request, tag the release on the default branch, and check that the release workflow built, signed and published what it should. See [Releases](#releases). |

One person or account can hold several roles. The CODEOWNERS file is the public record of who
holds the code owner role in each repository; GitHub ignores an entry there without write
access, so everyone named in it is also a maintainer.

## How a change is accepted

A change reaches a default branch through a pull request. Each repository's ruleset enforces
the same conditions before a pull request can merge:

- an approving review from a code owner, given after the last push (a new push dismisses an
  earlier approval);
- every required CI check passing on the latest commit, which includes the tests and, where
  the repository has them, its linters, coverage floors and supply-chain checks;
- every review thread resolved;
- a squash or rebase merge, with no force push to the default branch and no deleting it.

The only bypass of these rules is held by the approvers, the same people who approve.

What makes a pull request acceptable is in the repository's CONTRIBUTING.md: its coding
style and the tools that enforce it, its test and coverage rules, and how to run what CI runs.
Two rules hold everywhere:

- **New behaviour comes with tests.** A pull request that adds or changes functionality adds
  tests for it to the automated suite, and a bug fix adds a test that fails without the fix.
- **Documentation moves with the code.** A change to behaviour that the README or other docs
  describe changes those docs in the same pull request. Documentation that no longer matches
  the code is a bug, tracked and fixed like any other.

There is no Developer Certificate of Origin sign-off requirement and no contributor licence
agreement. By opening a pull request you agree that your contribution is licensed under the
repository's licence (Apache-2.0 for nearly every project here; the LICENSE file says), as
section 5 of the Apache License describes.

## Becoming a contributor or a reviewer

There is nothing to sign up for. You become a contributor by opening an issue or a pull
request, and a reviewer by reviewing one: thoughtful public reviews are welcome on any pull
request, and a code owner reads them before approving.

Write access, and with it the maintainer and code owner roles, is given by Distronode
Corporation. It goes to people who have shown, over a run of contributions and reviews, that
they know the project's rules and look after its users. If you would like to take on more,
say so in a discussion or at **opensource@distronode.com**.

## Disputes

Most disagreements are settled in the issue or pull request where they come up, by the
evidence: a failing test, a measurement, a line of the specification. If one is not settled
there, ask for a maintainer's decision in the thread, or write to
**opensource@distronode.com**. A code owner makes the decision and gives the reason in
public, and as the owner of the projects, Distronode Corporation has the final say.

Conduct is different: report a breach of the Code of Conduct to **opensource@distronode.com**,
not in the thread. The Code of Conduct (Contributor Covenant) describes how reports are
handled.

Every project here is open source, so a disagreement that cannot be settled never leaves you
stuck: you are free to fork under the licence.

## Vulnerability response

Each repository's SECURITY.md is the authority for its scope, its supported versions and
what counts as a vulnerability there. The process is the same in every repository:

1. **Report privately.** Use GitHub's private vulnerability reporting: the repository's
   **Security** tab, then **Report a vulnerability**. If you cannot use GitHub, email
   **opensource@distronode.com**. Never open a public issue, discussion or pull request for a
   vulnerability.
2. **Acknowledgement** within a few working days.
3. **Assessment** against the repository's SECURITY.md and, where it has one, its security
   model: whether it is in scope, how bad it is, and which versions it affects. You are kept
   informed in the private advisory or by email.
4. **Fix**, developed privately where the report is still undisclosed, with a test that fails
   without it, and released as a new version. Only the latest release is supported, so fixes
   go into a new release rather than being backported, unless a repository's SECURITY.md says
   otherwise.
5. **Disclosure**: a GitHub security advisory for the repository once the fix is released, and
   an entry in the CHANGELOG.

**Credit.** Distronode credits the reporter of every vulnerability it resolves, in the
advisory and in the changelog entry for the fix, unless the reporter asks to stay anonymous.
Tell us in the report how you would like to be named. There is no paid bug bounty.

## Releases

A release is a version tag (such as `v1.2.3`) on the default branch, and the repository's
release workflow builds and publishes it from that tag. The release manager's part is the
version bump pull request, the tag, and checking the result. Release tags are protected by a
ruleset, so a tag cannot be moved or deleted once pushed; a bad release is never re-tagged, it
gets a new patch version. What a release is signed with, and how to verify it, depends on
where it is published (a build provenance attestation checked with `gh attestation verify`,
npm provenance, or the platform's own code signing), and the repository's documentation is
where that is described.

## Continuity

No project here depends on one person's account. The `distronode-corporation` GitHub
organization has three owners: `seandean`, the maintainer who holds the code owner role;
`distronode-com`, the organization's own account; and `distronode-legal`, held by Distronode
Corporation's legal function (legal@distronode.com). An owner can give write access, change a
repository's CODEOWNERS file and rulesets, and run its workflows, so if the maintainer is lost
or unavailable, Distronode Corporation can, within one week, create and close issues, name a
new code owner, accept changes and make a release.

Making a release needs no personal credential. Each repository's release workflow publishes
with what the workflow itself is given, never with someone's own login, and the repository's
documentation has the steps. What each one publishes with:

- **npm packages** (worldinmotion, district-social, mcp-patchbay, mcp-frontdesk): npm trusted
  publishing. npm exchanges the workflow's OIDC token for a one-time publish token, so no npm
  token is stored anywhere. worldinmotion and mcp-patchbay also publish to the MCP Registry,
  signed in with the same OIDC token, and worldinmotion's own GOVERNANCE.md covers its editor
  marketplaces.
- **GitHub releases, signed tags and container images** (bridgewatch, district-linux,
  district-windows, district-core-rust, district-core-swift, district-scheduler, and the files
  and images worldinmotion and mcp-patchbay attach): the workflow's own repository token, and
  keyless Sigstore signing under the workflow's OIDC identity for attestations and signed tags,
  so no signing key is held by a person. bridgewatch's release tags are annotated, not
  signed. district-core-rust and district-core-swift tag from their release workflow and an
  owner then creates the GitHub release by hand.
- **App stores and platform code signing** (district-android, district-ios, district-macos,
  the Microsoft Store submission of district-windows, and the macOS build of bridgewatch): the
  signing keys and store credentials are stored for the release workflow, which reads them
  when it runs, so running it needs no one's own device or login. A submission for review also
  needs the maintainers' approval, given when the workflow is started, and the store then
  reviews it.

## Changing this document

This file lives in
[distronode-corporation/.github](https://github.com/distronode-corporation/.github), and a
change to it is a pull request there, under the same rules as any other change.
