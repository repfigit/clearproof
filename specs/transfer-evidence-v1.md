# Canonical transfer and evidence records v1

Status: CP-004 foundation in development. These types are not yet wired to the legacy proof API or circuit. A record digest does not prove credential issuance, authenticate a holder, establish quote truth or authorize a transfer. CP-005–CP-009 must connect storage, trust authorities and the actual proof statement before the pilot profile is enabled.

## Records and authority

`Transfer` contains private transfer facts: tenant and transfer IDs, a 32-byte nonce, exact originator/beneficiary wallets and VASP/self-hosted roles, asset identity/catalog digest, quantity, valuation, jurisdiction, policy digest and validity interval. Serialized transfers belong inside encrypted envelopes, not logs, public proof signals or plaintext storage. The nonce should be cryptographically random in the eventual issuance API; deterministic nonces in fixtures are synthetic only.

`VerificationContext` contains verifier-supplied expectations: tenant/transfer/policy references, deployment chain/address, artifact/proof-profile references, sanctions/issuer/issuance/revocation snapshot digests, evaluation time and permitted transfer age. `check_transfer` rejects mismatched tenant, digest, policy or chain, future/expired transfers and stale transfers. Snapshot digests and artifact IDs still require authenticated lookup; the model does not make a caller-provided context trusted.

`EvidenceReceipt` carries minimized opaque references and independently named results for cryptography, policy, exchange, settlement and authorization consumption. A valid proof does not set policy to allow or settlement to confirmed. A receipt must identify an evaluated proof, and cannot label authorization consumed without valid-proof/allow results. Actual consumption and signatures will be enforced at the transactional service boundary. No receipt signature is implemented by these models.

Generated schema exports and synthetic vectors live in `specs/fixtures/*-v1.schema.json` and `specs/fixtures/transfer-v1.json`. Python tests check schema-export drift. JSON Schema describes field shape; relational and catalog checks remain mandatory.

## Assets, quantities and valuation

The initial profile accepts canonical lowercase ERC-20 asset types: `eip155:<chain-id>/erc20:<contract-address>`. Chain IDs are positive unsigned 64-bit values; zero contract addresses are rejected. This is a constrained [CAIP-19 asset-type profile](https://standards.chainagnostic.org/CAIPs/caip-19), not a symbol resolver. Native assets and other namespaces are currently unsupported.

`AssetRegistry` is an immutable operator-supplied catalog of 1–256 unique asset identities with decimals from 0 to 18. Catalog commitments sort entries by asset identity. Identical symbols on different chains or contracts remain different assets. `parse_transfer(data, registry)` is the application entry point: it validates both the record and membership in the expected catalog. Constructing `Transfer` alone validates shape and internal consistency, not catalog authority.

Amounts use unsigned 128-bit canonical decimal strings in base units. Human decimal conversion is explicit through the catalog, rejects numeric/float inputs, exponent notation, signs, grouping, whitespace and excess precision, and never rounds token quantity. Leading zeroes are forbidden except the zero before a fractional amount. Zero-value transfers are rejected.

Valuation specifies a reduced positive rational number of **USD cents per base unit**, observed/expiry timestamps, source ID and source-evidence digest. The transfer binds its complete valuation record. USD cents must exactly equal `floor(amount_base_units * numerator / denominator)` and be positive. This is an explicit rounding convention, not an assertion of regulatory applicability. The quote must cover the entire transfer validity interval. There is no automatic stablecoin peg and no current live price provider. Source authenticity and approved valuation policy remain trust-layer requirements.

## Canonical encoding and commitments

Python `canonical_bytes` and Node `canonicalBytes` operate on a deliberately restricted data profile rather than implementing arbitrary [RFC 8785 JCS](https://www.rfc-editor.org/info/rfc8785/): printable ASCII strings, safe integral values, booleans, null, dense arrays and ordinary objects. Python requires integer-typed numeric values; Node rejects unsafe/nonintegral values and negative zero. Monetary quantities are strings in both implementations. Values must already satisfy their record schema; the Node encoder is not a business-rule or schema validator.

Object keys are sorted lexically, including numeric-looking keys. JSON has no insignificant whitespace; quotes and backslashes use JSON escaping. Limits are eight nesting levels, 256 array items, 64 object members, 128 characters per key, 4096 characters per string and 64 KiB serialized bytes. Validation has a separate 65536-unit work budget: eight units per value plus string length and key length plus three. This bounds work before serialization allocation. Invalid values, Unicode, control characters, unsupported objects and oversized inputs fail.

Commitment bytes are:

```
SHA-256(ASCII(domain) || 0x00 || canonical_json_bytes)
```

Domains are `clearproof/transfer/v1`, `clearproof/verification-context/v1`, `clearproof/evidence-receipt/v1` and `clearproof/asset-registry/v1`. Results are lowercase 64-character hex strings. No hash is silently reduced into the SNARK scalar field. The circuit-facing projection and its binding to private transfer facts must be specified and tested in CP-006/CP-007; hashing JSON alone does not solve that binding.

Unknown fields and unsupported schema versions fail. Records are frozen and normal model string/repr output identifies only the record type. Explicit serialization still exposes private facts and must stay within the encrypted-envelope boundary. Validation error formatting hides input values; applications must also avoid logging raw request bodies or structured validation inputs.
