# Hardhat 3.x Migration Guide

## Current State (Post-Migration Audit)

- **Installed**: hardhat `2.28.6`
- **Vulnerabilities**: ~38 total (23 low, 8 moderate, 7 high)
- **Root causes**: Transitive dependencies of hardhat 2.x (`mocha`, `tmp`, `undici`)

## Vulnerability Breakdown

| Package | Severity | Issue | Fix |
|---------|----------|-------|-----|
| `undici` <=6.23.0 | **High** (5 advisories) | Unbounded decompression, request smuggling, CRLF injection | Hardhat 3.x updates undici |
| `tmp` <=0.2.3 | **High** | Arbitrary file write via symlink | Hardhat 3.x updates tmp |
| `mocha` | Moderate | Various chain issues | Hardhat 3.x updates mocha |
| `glob` (multiple) | Low | Deprecated, known vulns | Hardhat 3.x updates glob |
| `uuid` <=10 | Low | Deprecated | Update uuid |

## Migration Complexity: HIGH

**Hardhat 3.x is not a drop-in upgrade for this project.** The `@nomicfoundation/hardhat-chai-matchers` package has a compatibility cliff:

- `hh2` tag: requires `@nomicfoundation/hardhat-ethers@^3.1.0` which requires hardhat 3.x internals
- `^2.1.x`: also requires `@nomicfoundation/hardhat-ethers@^3.1.0`

There is **no working combination** of hardhat-chai-matchers + hardhat-ethers that works with hardhat 2.x in this workspace.

## Migration Steps

### 1. Migrate all @nomicfoundation packages to hardhat 3 compatible versions

```bash
cd packages/contracts
npm install --save-dev \
  hardhat@^3.0 \
  "@nomicfoundation/hardhat-chai-matchers@hh2" \
  "@nomicfoundation/hardhat-ethers@^3.1.0" \
  "@nomicfoundation/hardhat-network-helpers@^1.0.0" \
  "@nomicfoundation/hardhat-verify@^2.0.0" \
  "@nomicfoundation/hardhat-viem@^2.0.0" \
  "@nomicfoundation/hardhat-ignition@^0.13.0" \
  "@nomicfoundation/hardhat-ignition-ethers@^0.13.0" \
  --legacy-peer-deps
```

### 2. Add `"type": "module"` to package.json

Hardhat 3.x requires ESM:

```json
{ "type": "module" }
```

### 3. Migrate hardhat.config.ts

Hardhat 3.x has breaking changes in:
- Task signatures and parameter names
- Network configuration format
- Plugin registration syntax
- TypeScript compilation settings

### 4. Verify

```bash
npx hardhat compile
npx hardhat test
```

### 5. Post-migration audit

```bash
npm audit
```

Expected: <5 remaining vulnerabilities.

## Risk Assessment

- **Risk**: High — requires full dependency migration, config changes, test updates
- **Current mitigation**: Accept known vulnerabilities as acceptable risk for now
- **Recommendation**: Schedule migration during a dedicated tech debt sprint

## Post-Migration TODO

- [ ] Run full test suite
- [ ] Update hardhat.config.ts for HH3 syntax
- [ ] Update deploy scripts if needed
- [ ] Re-audit and document remaining vulns
- [ ] Update this doc with actual post-migration vulnerability count
