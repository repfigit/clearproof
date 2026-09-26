---
id: UP-EX-007
title: Contributing useful feedback — the reproducible issue path in Clearproof
date: 2026-09-30
publishAfter: 2026-09-30T00:00:00Z
sourceCommit: 5d65115b0907b25be75400bb76f80dedb357f5b7
claimRefs:
  - packages/cli/src/commands/report.ts
  - packages/cli/src/commands/doctor.ts
  - .github/ISSUE_TEMPLATE/bug_report.yml
  - apps/docs/app/docs/report-issues/page.mdx
status: approved
summary: A bug report is only useful if the person reading it can reproduce it. Clearproof's CLI builds a pre-filled GitHub issue link locally — versions, platform, an optional privacy-filtered doctor summary — and nothing is sent until you open the link. This explainer walks that path and its privacy choices.
canonical: /explainers/contributing-useful-feedback
templateVersion: explainer-v1
---

Most feedback loops fail at the same place: the report that reaches a
maintainer is missing the environment it failed in. Clearproof's answer is
narrow and local — a CLI command that assembles a reproducible issue link on
your machine, shows it to you, and sends nothing until you decide to open it.

## `clearproof report` — a link builder, not a sender

The command (`packages/cli/src/commands/report.ts`) does one thing: it prints
or emits a GitHub issue form URL. It has no network code. Three inputs shape
the link, and each one has a privacy decision behind it.

The `--title` option is validated to one line of at most 200 characters before
it reaches the URL — a form field, not free text into a web request. The
`--kind` option selects the bug or feature template; anything else is refused
rather than silently defaulting.

`--json` changes the output from prose to `{ url, environment, security }`,
built for scripts and agents: a program can parse the link, and the `security`
field points at GitHub's private advisory form, so a machine handling a
possible vulnerability has the right channel in hand before it writes anything
public.

## The environment line says what it is

`environment()` returns exactly three lines: the CLI version, the Node version
and the platform architecture. The docstring states the boundary — no
hostname, no user, no paths, no environment variables. A report is useful
because it names the versions involved; it does not need to name your machine.

## `--doctor` — the summary is the point

Artifact problems are hard to describe in prose, so `clearproof doctor` can
save a diagnostic and `report --doctor <file>` can attach a summary of it to a
bug report. The path between them (`doctorSummary` in report.ts, with the
underlying report shape in `packages/cli/src/commands/doctor.ts`) is an
allowlist, and it is easier to describe by what it drops than by what it keeps.

From the doctor result it keeps: `status` (validated to a short lowercase
token), an optional `reason` with the same shape, `proof_profile` only if it is
one of the three named pilot profiles, a 64-hex `manifest_digest` (a digest of
artifact contents, not a path), and two booleans about policy and profile
support. Everything else — including any field with an unexpected shape — is
dropped. The reason this matters: a saved diagnostic can plausibly contain a
filesystem path or an error string copied from stderr, and neither belongs in a
public issue.

The flow preserves the reviewer's position, too: `doctor` inspects pinned
local artifacts without downloading, proving or authorizing, and `report`
documents that nothing is sent until the link is opened. Reproduction stays
with the person who saw the failure.

## Where the link lands

The generated URL opens GitHub's structured bug or feature template — the
forms ask for what happened, what you expected, reproduction steps, the
version or commit, the proof profile and the component. One field is worth
singling out: **Reported by**, which offers "An AI agent, reviewed by a
person" and "An AI agent, unreviewed" alongside human options. The templates
treat agent-reported issues as a first-class case, with review status declared
rather than hidden.

The same path is documented for people and agents on the docs site at
[/docs/report-issues](https://docs.clearproof.world/docs/report-issues),
including the duplicate check (`gh issue list --search`) and the list of
things that never belong in an issue: personal data, private keys, API keys,
`PII_MASTER_KEY`, decrypted envelopes, database URLs, real customer records.

## What this establishes — and what it does not

A pre-filled link is a convenience pipeline for reproducibility, not a
guarantee: the form still has to be filled honestly, and the reproducer still
has to run the failing command. What the source shows is that the project's
default reporting path was built with two properties in mind — the report
carries the versions it needs and nothing identifying, and the sending step
belongs to the reporter. If you have used Clearproof and something did not
work, that path is the way to make the report do its job.

Use `clearproof report --json` (or the plain command) to open the pre-filled
bug or feature form — review the text, attach synthetic-data reproductions
only, and submit from your own GitHub account.
