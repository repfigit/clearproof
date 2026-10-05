# October project improvements

Status: active. Scope includes the core repository, clearproof-web, hosted
documentation, all seven open Clearproof Linear issues and all five open GitHub
issues reviewed on October 5. Completion requires verified behavior and tracker
reconciliation, not merely a change of issue status.

| Work | Completion evidence | State |
| --- | --- | --- |
| Website dependencies and maintenance | Patched framework, dependency audit disposition, lint/build/browser/link CI, deployed verification | In progress |
| Shared release and publication catalogue | Homepage and docs consume one status/catalogue; future/paused articles not promoted; live links work | In progress |
| Documentation accuracy and presentation | Reconciled roadmap/agent guidance, proper Markdown, technical sitemap/metadata, maintained web README | Pending |
| Two onboarding paths | Small synthetic evidence inspection with tamper case; reproducible complete pilot with preflight/recovery; current SDK example first | Pending |
| Backlog reconciliation | Source/test evidence for every open Linear/GitHub item; delivered work closed and remaining criteria retained | In progress; AIF-119 verified and closed |
| Artifact isolation (GitHub #85) | Explicit test bundles required; incomplete supplied bundles fail; local ambient artifacts ignored | Implemented; explicit absent/empty/incomplete checks pass; fresh-bundle CI pending |
| Dependency cleanup (GitHub #86) | Unused drivers removed; locked install and relevant Python tests pass; storage guidance accurate | Implemented; locked all-extras install and 2,040 Python unit tests pass; PR pending |
| Proving execution (GitHub #87) | Correct service scope; durable bounded jobs, privacy-safe input/output, retries/cancellation/concurrency/freshness tests | Pending |
| Native proving benchmark (GitHub #88) | Equivalent current-profile benchmark; measured backend decision; pinned optional backend if justified | Pending |
| Canonical constants (GitHub #89) | Structured profile source, generated runtime constants, drift gate and cross-runtime compatibility tests | Pending |
| Operational preflight and software scale | Scoped authenticated readiness checks, bounded cryptographic execution, paginated persisted inventories and measured limits | Pending |
| Legacy configuration/parity and migration issues | AIF-158/89 hardened with compatibility; AIF-119/100 reconciled; AIF-67/99/65 remaining acceptance explicitly verified | Pending |
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

No customer outreach, customer data access, production proving-key approval or
fund movement is authorized by this plan. Customer/provider permission and
independent assurance require actual external evidence.

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
