# Security Policy

## Reporting a Vulnerability

We take the security of ZK Travel Rule seriously. If you discover a security vulnerability, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

### Contact

Email: **security@clearproof.dev**

Please include:

- A description of the vulnerability
- Steps to reproduce the issue
- The potential impact
- Any suggested fixes (if applicable)

### Response Timeline

- **Acknowledgment**: Within 48 hours of your report
- **Initial assessment**: Within 5 business days
- **Resolution target**: Dependent on severity, but we aim for fixes within 30 days for critical issues

## Scope

The following areas are in scope for security reports:

- **ZK circuits** (`circuits/`): Soundness issues, constraint under-specification, proof forgery vectors
- **Encryption and key management**: Weaknesses in data encryption, key derivation, or secret handling
- **Protocol bridges**: Vulnerabilities in cross-chain message passing or verification logic
- **Smart contracts** (`packages/contracts/`): Reentrancy, access control, verification bypass, domain binding bypass, or proof replay issues in ComplianceRegistry, VASPRegistry, or SanctionsOracle
- **Sanctions oracle** (`SanctionsOracle.sol`): Issues that could allow stale or manipulated sanctions roots
- **Proof SDK** (`packages/proof/`): Issues that could allow invalid proofs to be accepted
- **Proof expiration**: Bypass of on-chain `proof_expires_at` enforcement

## Out of Scope

The following are out of scope:

- Third-party dependencies (report these to the upstream maintainer)
- Test infrastructure and CI/CD configuration
- Social engineering attacks
- Denial of service attacks against test or development environments
- Issues in forks or unofficial distributions

## Bug Bounty

A formal bug bounty program is **coming soon**. In the meantime, we will credit all valid reporters in our security advisories and release notes (unless you prefer to remain anonymous).

## Disclosure Policy

- We follow coordinated disclosure. Please give us reasonable time to address vulnerabilities before public disclosure.
- We will credit reporters in our security advisories unless anonymity is requested.
- We will not take legal action against researchers who follow this policy.
