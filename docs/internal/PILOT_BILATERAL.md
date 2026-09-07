# Local bilateral counterparty scenarios

`TRPBridge.build_pilot_request` and `LocalBilateralCounterparty` implement the
explicitly selected `clearproof-local-bilateral-v1` profile. They run entirely
in-process with independently configured transfer/context, signing authorities,
recipient authority and private keys. This is a local acceptance fixture, not a
TRP-conformant wire implementation or live counterparty integration.

## Protocol review and compatibility boundary

The OpenVASP [core specification](https://gitlab.com/OpenVASP/travel-rule-protocol/-/raw/master/core/specification.md),
reviewed September 6, 2026, identifies version 3.2.1 and describes mTLS,
version/extension headers, inquiry and callback semantics, IVMS101 information,
and exact transfer amount/asset fields. It explicitly provides unsupported-extension
responses. An extension-shaped JSON body therefore does not establish remote
acceptance or conformance. The legacy `build_trp_request` documentation now records
its missing person data and ambiguous symbol mapping instead of promising silent
extension compatibility. Its legacy serialization behavior is retained.

The new local profile uses Clearproof's private transfer-information schema in the
authorized HPKE envelope. It does not rename that schema IVMS101 or send empty
person arrays as a substitute for mandatory information. Live TRP transport,
certificate policy, wire-schema translation and remote acceptance require separate
conformance and customer-gate evidence.

## Receiver checks

A request contains a version, exact receipt ID/body, minimized authorization
request, encrypted recipient envelope, signed originator decision and signed
information approval. Canonical validation bounds the entire message. No raw
person information is included in reports or outside the encrypted envelope.

Before any supported-profile business disposition, the receiver checks:

- Exact tenant, transfer, context, receipt identity, profile and current validity.
- The decision signature against independently configured originator authority.
- The authorized-proof identity and exact receipt/envelope commitments.
- Current recipient authority and availability of the exact private key, with no encryption fallback.
- HPKE binding and decryption, mandatory transfer-information semantics, exact asset/base units and both participants.
- The authorized information-signature digest and source signature over the actual decrypted bytes.

This receiver relies on the authenticated originator decision for originator-side
proof/policy approval. It does not independently run Groth16 pairing, refresh
sanctions sources, inspect the originator database or make a new authorization.
The joined PostgreSQL test supplies a receipt created by the actual real-proof
current authorization flow. Source signatures authenticate scoped claims, not their
external truth or jurisdiction-specific legal sufficiency.

## Deterministic local behaviors

After valid message checks, the configured simulator returns accepted, rejected
or information-requested. A timeout behavior returns pending before an independently
configured deadline and timeout at that deadline while the receipt remains valid.
An unsupported profile produces unsupported-version rather than acceptance.

The key-rotation scenario retains old and new keys during overlap so the original
authorized envelope remains readable. After retiring the old authority/key, that
same envelope rejects; it is never silently decrypted with another key or resealed
under an unchanged receipt. Repeated identical requests at the same clock and
behavior produce identical request references and results.

Results identify `source_authenticity=local-simulator`, development assurance,
`authorization=not-created` and `execution=not-requested`. They are trusted only
as local simulator results, not signed remote responses. Persistent exchange-event
ingestion, timeline/report integration and the user-facing scenario command remain
required M5 work. No network communication, storage writes or funds movement occur
inside this simulator.

## Validation

The real PostgreSQL authorization gate exercises accept, reject, request-information,
pending/timeout, key overlap/retirement and unsupported-version. It rejects missing
or substituted envelope/authorization/decision/information records, expired receipts
and unavailable keys, verifies deterministic retry and checks minimized output.
The surrounding gate still checks unchanged stored-record counts and exactly one
consumption. `scripts/test_pilot_mirror.py` includes this path with the real development
proof, encrypted information and EVM mirror/recovery checks.
