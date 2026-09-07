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
as local simulator results, not signed remote responses. The CLI disposition command is described below. Complete clean-environment
pilot packaging remains required M5 work. No network communication, storage writes or funds movement occur
inside this simulator.

## Validation

The real PostgreSQL authorization gate exercises accept, reject, request-information,
pending/timeout, key overlap/retirement and unsupported-version. It rejects missing
or substituted envelope/authorization/decision/information records, expired receipts
and unavailable keys, verifies deterministic retry and checks minimized output.
The surrounding gate still checks unchanged stored-record counts and exactly one
consumption. `scripts/test_pilot_mirror.py` includes this path with the real development
proof, encrypted information and EVM mirror/recovery checks.

## Durable local delivery and investigation

`LocalExchangeService` loads the retained authorization receipt and proof under the
authenticated tenant, invokes the configured local receiver, and commits minimized
response evidence, the counterparty event/index and its idempotency result in one
database transaction. Source authority restricts actor, tenant, deployment and event
dimension. Delivery requires event-ingestion and evidence-decryption permissions,
including retries. The receiver configuration and business behavior belong to the
local service, not an incoming remote response.

A delivery ID binds its receipt, source sequence, declared observation time,
context and configured behavior. Exact retries return the retained historical
result; altered requests conflict. A retry after key retirement is therefore a
historical read, not a fresh acceptance under the retired key. New deliveries still
require receiver validation. Observation time is a simulator-declared clock, kept
separate from ingestion time; it is not an authenticated remote timestamp.

The joined database test delivers acceptance before an earlier information request,
checks simultaneous retries, reconnects, and reconstructs the same investigation.
Duplicate and reordered internal custody-simulator events join that timeline.
Custody completion without an independent finality observation remains a finding.
Pending and unsupported-version counterparty states also produce actionable
findings. These are local fixtures, not live Fireblocks deliveries or settlement
proof. The independent Fireblocks adapter retains its existing ingestion boundary.

## Run a local disposition from the CLI

Build the source CLI with `npm run build --workspace=@clearproof/cli` and use a
Python environment with this checkout installed. The command takes three separate
inputs:

- `--request`: the JSON object returned by `TRPBridge.build_pilot_request(record, receipt)` from an authorized retained record. It includes encrypted information, not plaintext person fields.
- `--trust`: independently configured recipient expectations. The exact schema is `CounterpartyConfiguration` in `src/protocol/bridges/pilot_bilateral_cli.py`: `schema_version=clearproof-local-counterparty-configuration-v1`, the expected `transfer` and `context`, and nonempty arrays of public `decisions`, `information` and `recipients` authorities. Do not take these authorities from the request you are checking.
- stdin: a JSON object `{"keys":{"<recipient-key-id>":"<64-hex-private-key>"}}`. Keep recipient private keys out of command arguments and public configuration files.

For a protected local synthetic key file supplied by the operator:

```bash
node packages/cli/dist/index.js counterparty \
  --python .venv/bin/python \
  --request /absolute/local/bilateral-request.json \
  --trust /absolute/local/counterparty-trust.json \
  --observed-at "$SIMULATION_EPOCH" \
  --behavior accept < /absolute/private/recipient-keys.json
```

`--observed-at` is an explicit simulation clock inside the receipt's validity
window. Repeat with `--behavior reject` or `--behavior request-information` to
exercise those dispositions. For `--behavior timeout --deadline EPOCH`, an
observation before the deadline yields pending; at the deadline it yields timeout.
The deadline must fall strictly inside the authorization window. An unsupported
request profile yields unsupported-version. To exercise key rotation, configure
both old and new authorities/keys during overlap, then remove the old authority
and key: the original envelope must reject after retirement.

Exit 0 means the simulator produced a disposition, including rejection or timeout;
it does not mean the transfer is authorized or settled. Invalid messages, trust or
keys exit 2 with a minimized error. Request/trust files must be bounded regular
files; duplicate JSON keys and unsupported configuration fields reject. The
command does not persist events or communicate with a remote counterparty.
`LocalExchangeService` provides the separate durable ingestion path described above.

The PostgreSQL/EVM acceptance runner invokes the built CLI against its actual
real-proof authorization and encrypted envelope. It exercises the three business
dispositions, pending/timeout, unsupported version, key overlap/retirement, expiry,
missing keys and malformed input, with private-key and input-value redaction
checks. This is executable scenario coverage; a fresh-checkout setup that retains
all demo reports and evidence exports remains part of CP-017.

To retain the scenario results alongside policy, investigation and encrypted
historical evidence outputs, use the [local acceptance command](../operations/local-pilot-acceptance.md).
