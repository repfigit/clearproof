# Clearproof adoption roadmap

Clearproof is an open-source project for privacy-preserving crypto transfer
evidence. The first goal is to make the project easy to understand, reproduce and
improve. This roadmap describes development priorities, not release dates or a
claim that every item is already available.

## Explore the current project

Start with the [README](../README.md), [contribution guide](../CONTRIBUTING.md) and
[local pilot acceptance guide](operations/local-pilot-acceptance.md). The current
source supports a bounded development pilot. Public package availability, source
capabilities and production assurance are separate: follow the README's current
installation status rather than assuming a published package contains every source
feature. Development proofs and local tests do not establish independent audit
completion or production readiness. See [security guidance](../SECURITY.md).

## Priorities

| Priority | Useful outcome | Ways to contribute |
| --- | --- | --- |
| Clear explanations | Understand a transfer-evidence workflow and the proof's trust boundaries | Improve terminology, diagrams and source-backed walkthroughs |
| Reproducible onboarding | Run a supported example from documented prerequisites | Test a clean checkout; report failing commands and environment details |
| Reliable distribution | Install compatible packages and identify matching artifact provenance | Review packaging, dependency compatibility and release instructions |
| Portable evidence review | Independently inspect supported exports and recognize incomplete evidence | Exercise synthetic examples, tamper cases and review documentation |
| Project updates | Follow meaningful changes through the website/docs and a planned RSS feed | Build accessible content pages, stable feed entries and accurate source links |
| Useful feedback | Identify repeatable developer and operator needs | Share reproducible issues, example improvements and workflow questions |

The website, documentation and GitHub are the project's public destinations.
An updates/RSS pipeline is planned; a feed is not available merely because it is
listed here. Automation should publish useful, reviewed, source-backed material
and keep links and examples current. Empty schedules are preferable to invented
announcements or duplicate pages.

## Evaluate and contribute

Use synthetic data for public examples and bug reports. Include the source revision,
reproduction commands, expected behavior and observed result. Never attach raw
personal information, decrypted payloads, credentials or private keys. Report
security concerns through [SECURITY.md](../SECURITY.md), not a public issue.

The [evaluation guide](operations/evaluating-clearproof.md) explains how to record
setup outcomes, evidence quality and repeat use without confusing downloads or
stars with successful adoption. The [usage inventory](operations/usage-inventory.md)
documents the API's actual counters and their limitations.

Contributors can start with documentation, examples, packaging and reproducibility
without changing cryptographic commitments or running a production trusted setup.
Changes to circuits, authorization and deployment must follow the repository's
existing review and assurance requirements.

Verification, supported formats and useful local examples should remain freely
usable. Future operational services must be described by their actual availability
and assurance; this roadmap makes no pricing, support or compliance guarantee.

For public material, follow the [publication guidelines](PUBLISHING.md).
