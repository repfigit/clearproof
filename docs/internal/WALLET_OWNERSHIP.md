# Wallet ownership extension (EOA, staged circuit)

This source feature implements PR #11 / AIF-67 without changing legacy credentials,
the pilot credential commitment, existing proof formats or deployed verifiers.
It verifies control of an EOA signing key at challenge completion. It does not
establish legal ownership, complete regulatory compliance, or settlement authority.

## Flow

1. Enroll the exact credential through `POST /pilot/credential/enroll`, using
   its existing wallet-signed consent. This remains the existing pilot flow.
2. Call `POST /wallet/ownership/challenge` with `{ "credential_id": "<64 hex>" }`.
   The server loads the authenticated tenant's enrolled credential and verifies
   the caller's issuer scope. Wallet and VASP identity come from that credential;
   callers cannot select a different identity in the request.
3. Check the returned challenge against the enrollment context retained by the
   wallet/client. Sign its exact `message` using EIP-191 `personal_sign`.
4. Submit `{ "nonce": "<64 hex>", "signature": "0x<130 lowercase hex>" }` to
   `POST /wallet/ownership/verify`. A successful response includes `attestation_id`,
   `issued_at`, `expires_at` and `wallet_ownership_verified: true`.
5. Call `POST /wallet/ownership/credential` with `{ "attestation_id": "<64 hex>" }`
   to issue the optional versioned extension. Its response explicitly reports
   `proof_support: "staged-witness-only"`.
6. Inspect current eligibility with `GET /wallet/ownership/attestations/{id}`;
   revoke with `POST /wallet/ownership/revoke` and the same attestation identifier.

All calls require the existing authenticated tenant principal, `evidence:decrypt`
and the relevant issuer grant. Challenge/verify/status/extension use
`credential:issue`; revocation uses `credential:revoke`. There is no implicit
administrator override. PostgreSQL, encryption keys, `PILOT_CHAIN_ID` and
`PILOT_REGISTRY_ADDRESS` must be configured; unavailable storage fails closed.

## Signing helper

The unreleased source SDK exports `walletOwnershipSigningMessage`:

```typescript
import { walletOwnershipSigningMessage } from '@clearproof/proof';

// response is from the authenticated challenge endpoint. expectedEnrollment
// and the tenant/deployment context were retained independently during enrollment.
const message = walletOwnershipSigningMessage(response.challenge, {
  tenantId,
  actorId,
  credential: expectedEnrollment.credential,
  chainId,
  registryAddress,
});
const signature = await signer.signMessage(message); // EIP-191 signer supplied by the wallet
```

Never populate the expected context by copying fields from an untrusted challenge.
The helper returns text; it never receives a private key or submits a transaction.
Its message matches the Python server byte for byte through a shared test vector.
Only canonical 65-byte, low-s signatures with recovery values 27/28 are supported.
Contract wallets/EIP-1271 are not supported by this profile.

## Lifetime, replay and retention

A challenge expires exactly 300 seconds after creation; equality with expiry is
expired. Its signed content binds the wallet's full credential, issuer, tenant,
actor, chain, registry, timestamp and random 256-bit nonce. A verified attestation
expires exactly 86400 seconds after verification. This additional evidence has a
separate lifetime from the original enrollment consent.

Verification and nonce consumption share one PostgreSQL transaction and tenant
lock. Exactly one concurrent verification can succeed. A retry receives 409;
use the nonce as the attestation identifier to inspect an uncertain successful
response. Failed signatures do not consume the challenge. New challenges are
limited to one per actor/credential/five-minute time bucket and 256 per tenant
per UTC day; the daily limit returns 429. Limits survive restarts and are checked
atomically. Challenge/attestation records are retained encrypted for evidence;
expiry does not delete them. These limits bound daily growth, not total retention.

Status and extension issuance recheck the retained wallet signature, authenticated
context, attestation expiry/revocation and parent credential eligibility/revocation.
An extension retry cannot use a previously successful result to bypass current
revocation. Revocation is scoped and idempotent. Historical commitments remain
immutable; they are not rewritten when evidence changes. A previously returned
`wallet_ownership_verified: true` is a historical response, not perpetual validity.

## Versioned commitment and circuit boundary

`clearproof-wallet-credential-v1` commits six ordered field elements:

| Index | Field |
|---|---|
| 0 | Extension domain tag `111` |
| 1 | Existing pilot credential commitment |
| 2 | Domain-separated attestation SHA-256 digest reduced into the BN254 scalar field |
| 3 | Attestation issuance timestamp |
| 4 | Minimum of attestation expiry and parent credential expiry |
| 5 | `wallet_ownership_verified` as 0 or 1 |

The extension commitment is Poseidon(6). The original legacy Poseidon(5) and
pilot credential encodings are unchanged. The isolated
`circuits/wallet_ownership_credential.circom` constrains the flag to 1, the domain,
expected credential/attestation commitments and the evaluation interval with
53-bit time range checks. The public signals are, in order:
`extension_commitment`, `expected_credential_commitment`,
`expected_attestation_digest`, `evaluated_at`. It has no public outputs.

This is a **staged circuit**, tested with real R1CS/witness generation. No new
trusted setup or proving key is generated, no verifier is deployed, and neither
legacy nor pilot proving endpoints accept this extension as an authorization
profile. A future verifier must independently authenticate the expected
commitments and current eligibility, as well as verify the composed proof.
Supplying self-selected public commitments does not prove authentic issuance.
The circuit checks the recorded attestation statement; it does not verify the
EIP-191 signature itself. Revocation is a current-state service check.

## Verification

```bash
uv run pytest tests/unit/test_wallet_ownership.py -q
DATABASE_URL=<isolated-test-postgres> uv run pytest tests/integration/test_wallet_ownership.py -q
npm test --workspace=@clearproof/proof -- --run test/wallet-ownership.test.ts
```

The witness tests require Circom and Node. CI installs the pinned compiler and
runs them in `pilot-credential-witness`; PostgreSQL tests run in `proof-storage`.
Existing legacy and pilot real-proof checks remain required independently.
