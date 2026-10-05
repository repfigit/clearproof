# October project improvements

Status: active. Scope includes the core repository, clearproof-web, hosted
documentation, all seven open Clearproof Linear issues and all five open GitHub
issues reviewed on October 5. Completion requires verified behavior and tracker
reconciliation, not merely a change of issue status.

| Work | Completion evidence | State |
| --- | --- | --- |
| Website dependencies and maintenance | Patched framework, dependency audit disposition, lint/build/browser/link CI, deployed verification | Done; web #12 merged, production Ready and live checks passed |
| Shared release and publication catalogue | Homepage and docs consume one status/catalogue; future/paused articles not promoted; live links work | Done; production docs/site share 0.7.0 and published catalogue |
| Documentation accuracy and presentation | Reconciled roadmap/agent guidance, proper Markdown, technical sitemap/metadata, maintained web README | Done; #91/web #12 merged and deployed with browser acceptance |
| Two onboarding paths | Small synthetic evidence inspection with tamper case; reproducible complete pilot with preflight/recovery; current SDK example first | Pending |
| Backlog reconciliation | Source/test evidence for every open Linear/GitHub item; delivered work closed and remaining criteria retained | In progress; AIF-119 verified and closed |
| Artifact isolation (GitHub #85) | Explicit test bundles required; incomplete supplied bundles fail; local ambient artifacts ignored | Done; #91 merged and fresh-bundle CI passed; GitHub issue closed |
| Dependency cleanup (GitHub #86) | Unused drivers removed; locked install and relevant Python tests pass; storage guidance accurate | Done; #91 merged, locked install and full remote CI passed; GitHub issue closed |
| Proving execution (GitHub #87) | Correct service scope; durable bounded jobs, privacy-safe input/output, retries/cancellation/concurrency/freshness tests | Pending |
| Native proving benchmark (GitHub #88) | Equivalent current-profile benchmark; measured backend decision; pinned optional backend if justified | Pending |
| Canonical constants (GitHub #89) | Structured profile source, generated runtime constants, drift gate and cross-runtime compatibility tests | In progress; generated code and identical compiled R1CS verified locally |
| Operational preflight and software scale | Scoped authenticated readiness checks, bounded cryptographic execution, paginated persisted inventories and measured limits | Pending |
| Legacy configuration/parity and migration issues | AIF-158/89 hardened with compatibility; AIF-119/100 reconciled; AIF-67/99/65 remaining acceptance explicitly verified | In progress; AIF-158 merged and closed; AIF-119 closed |
| External evaluation and adoption | Evaluation/feedback entry point and sample report; permitted real operator/counterparty evaluation with retained measurements | Pending; external access not yet established |
| Production assurance | Existing F1–F5 start conditions preserved; independently reviewed artifacts, audits and live interoperability cannot be inferred from local tests | External gates remain open |

## Verified tracker reconciliation

- **AIF-119: Done.** Seven-argument router fixtures are already on public main
  at `33be493`. Local complete normal-bytecode Hardhat run: 121 passed, 32
  artifact-gated pending, no constructor errors. Main
  [hardhat-tests](https://github.com/repfigit/clearproof/actions/runs/37377205666/job/111989330905)
  and [real-artifact circuits](https://github.com/repfigit/clearproof/actions/runs/37377205666/job/111989330993)
  are successful. Linear received this evidence, moved to Done and had its
  agent-ready label removed. Other open issues retain their acceptance criteria.

## Execution log

- October 5: rechecked clean worktrees and remote branches; website checkout was
  behind its published explainer-link change and was updated on an isolated branch.
  Registry confirms stable Next.js 16.3.8 and React 19.3.0. Implementation started
  with website dependency remediation and a shared public project catalogue.

Customer/provider access, independent assurance and production approvals require
actual external evidence; local tests cannot establish those prerequisites.

- October 5: website [PR #12](https://github.com/repfigit/clearproof-web/pull/12)
  contains dependency remediation, a request-time shared catalogue client,
  publication filtering, explicit synthetic-demo labels, robots/sitemap, CI and
  maintenance documentation. Local lint/typecheck/build, 18 unit checks and eight
  desktop/mobile/Firefox/WebKit browser checks pass. Production npm audit: zero
  advisories; five development-only braces/ESLint entries remain unpatched.
  Both site deployments and the live link check are still pending.
- October 5: core documentation uses the shared status source, renders proper
  CommonMark/GFM without HTML, inventories every technical page in its sitemap,
  and checks static page-specific metadata for drift. Documentation: 115 unit
  tests at 100% measured app coverage; content: 25 tests at 100%. PostCSS is pinned
  to patched 8.5.29, with a successful production docs build. Core production
  audit still reports five high build-chain and 15 low comparison-tool entries;
  no claim of a fully clean dependency tree is made. Documentation browser acceptance: 80 checks passed in the full run; the four
  root-page canonical assertions were corrected and passed on a focused rerun.
  Hosted deployment and full remote CI verification remain required before
  closing this work.

- October 5: core maintenance [PR #91](https://github.com/repfigit/clearproof/pull/91)
  links GitHub #85/#86 and the shared documentation catalogue consumed by web
  PR #12. Main's stale AIF-119 constructor issue is closed with execution/CI
  evidence. Removed agent-ready from all eleven other completed Clearproof
  issues, preserving their other labels and completion state.
- October 5: AIF-158 implementation requires stable HKDF salt at API startup and
  direct legacy derivation, with an explicit local-demo-only opt-in. Configured
  UTF-8 salts preserve existing derivation; retained legacy ciphertext migration
  is documented and tested. Focused encryption/startup checks: 51 passed, 100%
  changed-module coverage. Full Python suite: 2,442 passed, 274 optional/service
  skips, zero HKDF salt warnings under a warning-as-error gate. Remote real-service
  CI and merging remain required before the issue is closed.

- October 5: #91 merged as `8a7c428` after every required check and automated
  approval succeeded. Fresh development setup, actual legacy/pilot proofs,
  PostgreSQL acceptance, normal-bytecode E2E and aggregate coverage gates passed
  in run [37381888518](https://github.com/repfigit/clearproof/actions/runs/37381888518).
  GitHub #85 and #86 are closed. Production docs deployment
  `dpl_F2bYk9Nt2apWV7gmZjB5eznYjG21` is Ready; its public catalogue reports
  0.7.0 / pilot-transfer-v3 and eight currently published explainers, excluding
  the October 7/12 articles.
- October 5: AIF-158 is In Review under [PR #92](https://github.com/repfigit/clearproof/pull/92).
  Clearproof's Linear project is now In Progress. A concurrent PR #90 duplicates
  the now-merged #86 dependency cleanup; its additional supervisor-driver
  correction is preserved here before reconciling that duplicate.

- October 5: website #12 merged as `f277842` after exact-head CI and approval.
  Production deployment `dpl_2VxB6B8kU6qVVvVXeMfLpDTUAo2v` is Ready at
  clearproof.world and www.clearproof.world. Live verification passed all 13
  linked documentation pages, robots/sitemap and release status. Final source
  checks: 22 unit tests and eight browser checks. Core #92 merged as `b689aea`
  after full CI run [37383711024](https://github.com/repfigit/clearproof/actions/runs/37383711024),
  including PostgreSQL, actual proofs and aggregate coverage. AIF-158 is Done
  with retained-ciphertext compatibility evidence. Duplicate #90 was closed as
  superseded; its extra supervisor-driver correction is preserved in #92.

- October 5: GitHub #89 implementation generates constants and public declarations
  from `specs/pilot-signals-v3.json` for Python, TypeScript, Solidity, Circom,
  source-package metadata and specification tables. A read-only CI drift check
  rejects stale outputs; malformed and ambiguous schema input is rejected before
  writing. Previous source, generated repository source and packaged source all
  compile to the identical R1CS SHA256
  `4248cc7b67e7ead5a4ac7a4425acd0debffaee9642d540846be58daeae551aa8`.
  Checks: full Python 2,529 passed / 274 optional skips; generator/cross-layer
  focused suite 95 passed with 100% generator branch coverage; SDK 222 passed
  at 100% coverage; normal-bytecode contracts 121 passed / 32 artifact-gated
  pending; source package six passed, including packed include resolution.
  Remote actual-proof/coverage CI, review and merge remain required before
  GitHub #89 closes. No compiled keys or artifacts are committed.

- October 5: [PR #93](https://github.com/repfigit/clearproof/pull/93) contains the
  canonical profile implementation. Initial CI exposed generator formatting and
  an escaped SPDX header being interpreted as an invalid license expression.
  The renderer now emits repository-formatted Python and a literal valid SPDX
  header. Full Ruff lint/format, REUSE and 95 focused tests at 100% generator
  coverage pass locally; updated full remote CI remains required.
