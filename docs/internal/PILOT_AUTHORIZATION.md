# Atomic local authorization

`ProofAuthorizationService.authorize` consumes one local pilot authorization after
current proof inspection and a policy `ALLOW`. It requires `proof:consume`,
`proof:generate`, `proof:inspect`, `policy:read` and `evidence:decrypt`. The generate
permission authorizes encrypted proof/receipt retention; the consume permission
does not imply it. Tenant and actor come from the authenticated principal.

Transfer/context, artifact and runtime pins, current root and policy configuration,
valuation trust and external fact authority are server inputs. The service does
not accept a caller's claimed policy outcome or expected public signal vector.
It shares inspection's transaction-aware evaluation path, including current
activation, enrollment/revocation, root head and signed fact checks, and performs
real pairing. `DENY`, `REVIEW`, `INDETERMINATE`, invalid pairing and invalid trust
cannot consume or create authorization records.

Authorization also requires a [trusted recipient envelope](PILOT_RECIPIENT_ENVELOPE.md).
The supplied bytes must first satisfy the [bound information profile](PILOT_TRANSFER_INFORMATION.md).
An independently trusted [information approval](PILOT_INFORMATION_APPROVAL.md)
must cover the exact bytes and credential before the current inspection proceeds.
A server-configured [decision signer](PILOT_DECISION_ATTESTATION.md) is also required.
After ALLOW it seals those validated bytes to a currently approved beneficiary VASP
key. Encryption failure rejects the operation before any consumption commits.

The existing tenant transaction serializes inspection and writes with supported
policy/root/revocation writers. After `ALLOW`, it retains:

- An immutable encrypted proof record containing exact original proof bytes as
  base64, their SHA-256 digest, public signals, transfer/context, credential and
  fact references, the policy evaluation, recipient-encrypted payload and signed decision attestation.
- An immutable encrypted `clearproof-local-authorization-v1` receipt binding the
  proof record, tenant/actor, transfer/context/policy, artifact/profile, nullifier,
  authorization time, proof expiry and exact randomized envelope digest. Its
  execution state is `not-requested`.
- A unique tenant/nullifier consumption linked to that proof record, plus the
  existing actor-bound encrypted idempotency result.
- An [evidence manifest and configuration capture](PILOT_AUTHORIZATION_EVIDENCE.md)
  that pins the exact retained revisions and verifier inputs used for the decision.

All writes commit or roll back together. Different keys cannot consume the same
authorization twice. An exact same-key retry returns the original receipt,
including after restart or expiry; this is historical recovery, not a fresh
authorization. Changing request content or actor with the same key rejects.
Fact reference order is normalized before the request digest. Read-only inspection
remains available after consumption and never performs another spend.

The real PostgreSQL test generates an additional synthetic policy-bound proof
using the independently inspected development artifact set. It checks successful
`ALLOW`, missing/negative facts, invalid pairing, missing permissions, rollback
after consumption was inserted, competing request keys, concurrent exact retries,
changed-request rejection, reconnect/expired retry, exact proof-byte retention,
and one consumption with the expected proof/receipt/idempotency records plus
evidence manifest and configuration chunks.

This service records a local policy authorization. The API and source clients
below expose that operation; recipient delivery, payment execution, contract
acceptance parity and reproducible clean-environment onboarding remain open.
Encrypted export and offline historical inspection are separate operations with
independently configured evidence authorities. Development keys and synthetic
policy/attestation sources provide no production assurance or legal certification.

### Explicit authorization API and source clients

`POST /pilot/proof/authorize` accepts private JSON up to 16 KiB:
`target_id`, `credential_id`, `proof_json` (a JSON string), exactly eight
`public_signals`, up to 64 distinct `fact_ids`, and an `idempotency_key`.
The five permissions listed above are independently required. Tenant and actor
come from signed authentication claims. Unknown fields, duplicate JSON keys,
query selectors and request-supplied clocks, PII, recipient keys or trust reject.
Observation routes do not call this endpoint or inherit its write permissions.

The operator explicitly provisions
`app.state.pilot_authorization_targets[(tenant_id, target_id)]` with an
`AuthorizationTarget`. This contains the current statement/verifier/fact trust,
independent information trust, decision signer, approved recipient inventory/key,
and `SealedAuthorizationInformation`. Seal the latter with the storage keyring,
tenant and target name using its `seal` method; it holds only authenticated
ciphertext, including bounded base64 chunks of the exact information bytes and
its source-signed approval. Tenant and target name are authenticated encryption
metadata. Do not put plaintext inputs in server configuration, logs or files.
The transient decrypted bytes are validated and re-encrypted for the beneficiary
inside the authorization service. Input sealing establishes no source authority;
the service still verifies the independent signature for new consumption.

The response has profile `clearproof-authorization-response-v1`, scope
`recorded-local-authorization`, assurance `development-unapproved`, and `receipt`.
A successful response can be either a newly committed authorization or the
original same-key receipt. It does not claim a fresh decision, counterparty
acceptance, envelope delivery or execution. An unchanged request can recover its
original receipt after database reconnect and expiry while the corresponding
operator input and decryption key remain available. Removing those configured
inputs prevents this endpoint from constructing the original retry; retained
historical evidence remains subject to the separate export/review permissions.

Conflicting requests or consumed nullifiers return 409; current trust/input or
non-ALLOW rejection returns 422; unavailable configuration/storage returns 503;
unknown scoped targets/enrollments return 404. Missing/insufficient authentication
returns 401/403. Errors are generic and exclude submitted private values.

The source SDK exposes `authorizeCurrentProof(origin, token, requestBytes)`.
The built CLI exposes `authorize-current --api-url <origin>`, with the exact request
on stdin and `CLEARPROOF_API_TOKEN` in the environment. This is an explicit write
operation. Exit 0 means a structurally validated receipt was returned; exit 2 means
no usable response was obtained. The SDK checks the exact profile, canonical receipt
ID, ALLOW/non-execution claims, and request nullifier/expiry binding. It trusts the
selected API for the underlying current checks; it is not an independent proof or
historical signature verifier.

A timeout, connection failure or client response-validation error can occur after
the server commits. Preserve the exact request and idempotency key and retry that
pair; never infer rollback from exit 2 or automatically generate a replacement key.
These clients perform no automatic retry, recipient transmission, payment or
on-chain write. Public npm 0.3.0 does not include these source commands.
