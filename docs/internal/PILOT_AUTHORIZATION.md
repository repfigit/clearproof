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
After ALLOW it seals those validated bytes to a currently approved beneficiary VASP
key. Encryption failure rejects the operation before any consumption commits.

The existing tenant transaction serializes inspection and writes with supported
policy/root/revocation writers. After `ALLOW`, it retains:

- An immutable encrypted proof record containing exact original proof bytes as
  base64, their SHA-256 digest, public signals, transfer/context, credential and
  fact references, the policy evaluation and recipient-encrypted payload.
- An immutable encrypted `clearproof-local-authorization-v1` receipt binding the
  proof record, tenant/actor, transfer/context/policy, artifact/profile, nullifier,
  authorization time, proof expiry and exact randomized envelope digest. Its
  execution state is `not-requested`.
- A unique tenant/nullifier consumption linked to that proof record, plus the
  existing actor-bound encrypted idempotency result.

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
and one consumption with exactly three additional encrypted records.

This service records a local policy authorization. It has no public API endpoint,
recipient envelope delivery, payment execution or on-chain consumption adapter.
It does not establish agreement with SDK/contract acceptance or supply portable
historical evidence. Those integrations remain required pilot work. Development
keys and synthetic policy/attestation sources provide no production assurance or
legal certification.
