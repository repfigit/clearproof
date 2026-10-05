# Branch Protection — main

Enabled: 2026-07-27 (AIF-72). Updated: 2026-10-05 (added `lint` and `python-aggregate-coverage`).

This file mirrors the live GitHub settings. Check them with:

```bash
gh api repos/repfigit/clearproof/branches/main/protection
```

## Required status checks (not strict — branches need not be up to date)

- `python-tests`
- `typescript-build`
- `hardhat-tests`
- `protobuf-freshness`
- `license-compliance`
- `circuits` — real-proof circuit build, full Python suite with coverage
- `circuit-lint`
- `lint` — ruff check + format
- `python-aggregate-coverage` — combined database/mirror/operational coverage, 100% gate

## Other rules

- Enforce admins: **no**
- Force pushes: **no**
- Branch deletions: **no**
