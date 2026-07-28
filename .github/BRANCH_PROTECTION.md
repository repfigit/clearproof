# Branch Protection — main

Enabled: 2026-07-27 (AIF-72)

## Required status checks (strict — branches must be up to date)

- `python-tests`
- `typescript-build`
- `hardhat-tests`
- `protobuf-freshness`
- `license-compliance`

## Other rules

- Enforce admins: **yes**
- Force pushes: **no**
- Branch deletions: **no**
