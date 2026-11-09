---
id: UP-EX-013
title: Wallet authority is not wallet ownership — the trust boundaries in Clearproof's wallet verification
date: 2026-11-09
publishAfter: 2026-11-09T00:00:00Z
sourceCommit: 796b1597cbd90f93152ddcd7cc776367f99b4716
claimRefs:
  - docs/internal/WALLET_OWNERSHIP.md
  - packages/proof/src/wallet-ownership.ts
  - src/chain/wallet_account.py
  - src/services/wallet_evidence_export.py
  - circuits/wallet_ownership_credential.circom
  - tests/vectors/wallet-ownership/challenge-v2.json
status: approved
summary: A signature proves that a key signed a message at a moment. It does not prove who owns the wallet, who controls it today, or who is allowed to settle a transfer. Clearproof's wallet ownership extension (merged November 2026) is built around that gap: a bound SIWE challenge, separate handling for EOAs and smart accounts, explicit EIP-7702 delegation checks, a supervisor-readable evidence export, and a staged circuit that has no verifier. This explainer walks where the trust boundaries actually sit.
canonical: /explainers/wallet-authority-trust-boundaries
templateVersion: explainer-v1
---

When a Travel Rule workflow needs to tie a wallet to a person or an entity, the
tempting shortcut is to ask the wallet for a signature and treat a valid
signature as proof of ownership. The wallet ownership extension that landed in
[PR #127](https://github.com/repfigit/clearproof/pull/127) in November 2026
takes the opposite starting point: a signature establishes that the signing key
controlled the wallet *at that moment*, and everything else — who benefits from
the wallet, whether control still holds, whether that amount of authority is
even the right question — has to come from somewhere else, and be labeled as
coming from there. The [reference documentation](https://github.com/repfigit/clearproof/blob/main/docs/internal/WALLET_OWNERSHIP.md)
says it in the first paragraph: this verifies control of an EOA signing key at
challenge completion. It does not establish legal ownership, complete
regulatory compliance, or settlement authority.

The rest of this explainer walks the boundaries that follow from that framing.

## The challenge is the record, not a formality

Enrollment happens first, through the existing pilot credential flow with its
wallet-signed consent. Only then can the authenticated tenant request a
wallet-ownership challenge — and the caller cannot pick an identity: the wallet
and VASP identity come from the enrolled credential the tenant already holds.

With `PILOT_SIWE_DOMAIN` configured, the challenge is a
`clearproof-wallet-challenge-v2` record whose message is a deterministic
[EIP-4361](https://eips.ethereum.org/EIPS/eip-4361) SIWE message. That choice
is doing real work: the signed text itself becomes a supervisor-readable
record, because the SIWE fields (domain, nonce, chain ID, issued-at,
expiration-time, resources) say what was signed, when, and in what context.
The subject address is rendered with its EIP-55 checksum inside the message;
protocol records keep lowercase hex.

The signed content binds the wallet's full credential, issuer, tenant, actor,
chain, registry, timestamp and a random 256-bit nonce. Nothing in it is
reused from another context, and the challenge expires exactly 300 seconds
after creation (`CHALLENGE_TTL = 300` in
[`src/protocol/wallet_ownership.py`](https://github.com/repfigit/clearproof/blob/main/src/protocol/wallet_ownership.py)).
Message preparation on the client tolerates 30 seconds of clock skew in either
direction; server verification enforces the exact five-minute interval with no
tolerance.

Two boundary rules keep the client honest:

- The expected context (tenant, actor, credential, chain, registry) must be
  retained independently from enrollment — never copied from an untrusted
  challenge. The `walletOwnershipSigningMessage` helper in
  [`@clearproof/proof`](https://github.com/repfigit/clearproof/blob/main/packages/proof/src/wallet-ownership.ts)
  returns the exact bytes to sign and accepts the expected context as input;
  it never receives a private key and never submits a transaction.
- The Python server and the TypeScript helper must agree byte for byte, which
  is pinned by shared test vectors
  ([`challenge-v2.json`](https://github.com/repfigit/clearproof/blob/main/tests/vectors/wallet-ownership/challenge-v2.json)
  among them) rather than by convention.

## EOAs, smart accounts, and delegation are different paths

The EOA path is deliberately narrow: only canonical 65-byte, low-s signatures
with recovery values 27/28 are accepted. malleable encodings are rejected
instead of normalized, because an attestation should record one signature, not
a class of interchangeable ones.

Contract wallets — and EOAs that delegate through
[EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) — are verified through
ERC-1271 `isValidSignature` over the EIP-191 prehash of the SIWE message, or
ERC-6492 for counterfactual (not-yet-deployed) accounts. The attestation
records which method was used: `eoa`, `erc-1271` or `erc-6492`. Non-EOA
attestations are not re-verified with `ecrecover` on later reads; the standing
code/delegation re-check is the deliberate cheap check instead.

The EIP-7702 delegation check is the part most systems skip, and it changes
the outcome rather than decorating it. When `WALLET_OWNERSHIP_RPC_URL` is
configured, verification records the delegation status of the subject wallet
at verification time via `eth_getCode`, with strict `0xef0100` indicator
parsing in [`src/chain/wallet_account.py`](https://github.com/repfigit/clearproof/blob/main/src/chain/wallet_account.py):
code that starts with the indicator but does not match the exact form is
*malformed*, not delegated — and a malformed indicator does not silently pass
as either a plain EOA or a valid delegate. A delegated wallet keeps its
evidence but eligibility (status and extension issuance) pauses with a review
flag until the delegation is resolved. Status and extension evaluations
re-check delegation at most once per
`WALLET_OWNERSHIP_DELEGATION_RECHECK_SECONDS` (default 3600), and a dedicated
`POST /wallet/ownership/delegation-check` endpoint forces an immediate check
for external schedulers.

If no RPC is configured, the check is recorded as not performed. That last
part is a design position, not an omission: the attestation explicitly states
what was verified and what was not, instead of degrading to a binary
"verified/failed" that hides the difference.

## One transaction, one winner

Replay protection is structural. Verification and nonce consumption share a
single PostgreSQL transaction with a tenant lock, so exactly one concurrent
verification can succeed; a retry receives a 409 and can use the nonce as the
attestation identifier to inspect an uncertain-but-successful earlier attempt.
A failed signature does not consume the challenge.

Creation is rate-limited — one challenge per actor/credential/five-minute
bucket and 256 per tenant per UTC day, enforced atomically, surviving
restarts. These bounds limit daily growth, not retention: challenge and
attestation records are retained encrypted for evidence, and expiry does not
delete them.

A verified attestation expires exactly 86,400 seconds after verification
(`ATTESTATION_TTL = 86400`) — a lifetime deliberately separate from the
original enrollment consent. Status and extension issuance recheck the
retained signature, the authenticated context, expiry/revocation and the
parent credential's current eligibility on every evaluation, so an extension
retry cannot ride in on a previously successful result. A previously returned
`wallet_ownership_verified: true` is a historical response, not perpetual
validity; revocation is a current-state service check.

## The export, and its honest label

`GET /wallet/ownership/evidence/{attestation_id}` returns a supervisor-readable
export: the subject address, the verification method mapped to the verification
methods in the [EBA Travel Rule Guidelines (EBA/GL/2024/11)](https://www.eba.europa.eu/regulation-and-policy/single-rulebook/3102-travel-rule-guidelines)
section 4.8.4 paragraph 83 — the ¶83(d) message-signing limb for EOA
signatures, the ¶83(e) "other suitable technical means" catch-all for
ERC-1271/6492 — the exact signed message, signature, timestamps, delegation
status with the full re-check history, and credential linkage.

The mapping to ¶83(e) is Clearproof's interpretation, and
[`wallet_evidence_export.py`](https://github.com/repfigit/clearproof/blob/main/src/services/wallet_evidence_export.py)
flags it as such in the export rather than presenting a regulator's conclusion.
The export is evidence of a verification event, not a legal opinion.

## The staged circuit says no on purpose

The extension also carries a versioned commitment —
`clearproof-wallet-credential-v1`, a Poseidon(6) over six ordered field
elements — and an isolated circuit,
[`wallet_ownership_credential.circom`](https://github.com/repfigit/clearproof/blob/main/circuits/wallet_ownership_credential.circom),
tested with real R1CS/witness generation. It is a staged circuit, and the
boundaries around it are the point:

- No new trusted setup or proving key is generated and no verifier is
  deployed for it.
- Neither the legacy nor the pilot proving endpoints accept the extension as
  an authorization profile.
- The legacy Poseidon preimage is unchanged — the existing pilot commitment
  and proof formats carry no wallet-ownership field.
- The circuit constrains the recorded attestation statement (the flag, the
  domain, expected commitments, the evaluation interval). It does not verify
  the EIP-191 signature itself, and supplying self-selected public commitments
  does not prove authentic issuance. A future verifier must independently
  authenticate the expected commitments and current eligibility.

Revocation of a wallet-ownership attestation is a current-state service check,
which is exactly why it lives outside the circuit: a proof can attest to what
was recorded, not to what is still true.

## The takeaway

"Signed by this wallet" is a fact about one moment. Ownership, ongoing
control, delegation state, regulatory meaning and settlement authority are all
separate facts with separate lifetimes, and each one needs its own named
check. The wallet ownership extension is a worked example of drawing those
lines explicitly — and of stating in every artifact, from the challenge record
to the evidence export, which line a given check actually crossed.
