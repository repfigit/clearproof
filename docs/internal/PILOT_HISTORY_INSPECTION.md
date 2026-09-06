# Offline historical decision inspection

`inspect_history_bundle` reviews a decrypted export against an independently
configured `PilotPairingVerifier`, expected tenant and receipt ID, and reviewer
time. It performs no database reads, network calls, writes or authorization
consumption. Bundled keys, policies and certificates cannot approve themselves.

The historical outcome describes support for the **recorded local policy
decision under the configured trust authorities**. It does not certify legal
compliance, source-document truth, global screening coverage, delivery, settlement
or production readiness. The beneficiary's private information is not decrypted
by inspection. The signed operator receipt binds its approved information signature
and recipient envelope; this is not independent ciphertext-to-plaintext validation.

## Checks and independent inputs

1. Integrity checks cover expected receipt and evidence-manifest identities,
   tenant/transfer/context, original proof bytes and public signals, exact record
   revisions/hashes, captured configuration, policy report and recipient envelope
   binding. Artifact and runtime pins come from the reviewer.
2. `statement_trust` reconstructs the v2 circuit statement using captured wallet
   consent, exact credential, catalog, valuation, three signed roots and independently
   approved historical root/policy selection. Real Groth16 pairing must agree.
3. `fact_trust` authenticates exact captured external facts and replays the entire
   policy report, including reasons and matched rules. Replay uses the captured
   status observation conditionally until its authority is separately verified.
4. `decision_trust` verifies the [operator decision signature](PILOT_DECISION_ATTESTATION.md)
   over the receipt, evidence digest and context.
5. `status_trust` independently delegates [historical status authority](PILOT_HISTORY_STATUS.md)
   for the credential's issuer and pilot registry. Current status is never used to
   replace a past observation.
6. `timing_trust` verifies the [RFC 3161 timestamp](PILOT_HISTORY_TIMING.md), including
   exact TSA leaf/root/policy, accuracy and decision-window bounds. It authenticates
   existence of the signed record within that interval, not its exact decision time.
7. `information_trust` authenticates the [retained information-source approval](PILOT_INFORMATION_APPROVAL.md)
   without payload decryption or underlying-document validation.

Validity is checked at the claimed historical decision time. Known compromise is
checked at reviewer time for root, valuation, fact, information, decision, status
and timestamp authorities. A self-asserted pre-compromise signing time does not
bypass it. Root/valuation/fact stores reject a key if any configured entry records
a known compromise, so a second scope entry cannot override the finding. Removed
keys also remain unavailable; ordinary expiry permits previously valid evidence.
These are independently configured trust decisions, not live compromise discovery.

## Outcomes

- `supported`: integrity, pairing, statement reconstruction, policy reproduction,
  decision, status, timing and information authentication all succeed. The report
  has no unresolved reason codes. This supports the scoped recorded claim under
  the supplied authorities and still cannot authorize replay.
- `contradicted`: linked evidence or cryptographic checks contradict the artifact's
  claim. Examples include changed evidence, failed pairing, a mismatched replayed
  policy report, or an invalid decision/information signature. This is not a new
  regulatory policy `DENY` decision.
- `indeterminate`: necessary evidence, runtime or independently approved trust is
  missing, compromised or insufficient. Removing any required trust layer prevents
  support. Successful pairing alone is insufficient.

Reports separate `integrity_valid`, `cryptographic_valid`, `statement_valid`,
`policy_reproduced`, `decision_authenticated`, `status_authenticated`,
`timing_authenticated`, `information_authenticated` and the timestamp's accuracy
interval. A check not run remains unset. Proof expiry at reviewer time does not
prevent historical review; operator and reviewer clocks remain distinct.

The real-proof PostgreSQL test reviews an expired synthetic record after later
policy activation and revocation. It covers all outcomes, missing trust layers,
changed manifest/root/key/policy/envelope/signals, missing records, invalid source
signatures and later key compromise. A fresh Python process reconstructs every
trust store from separate reviewer configuration, decrypts and verifies the
bundle with database access closed and Python socket connections disabled, and
returns `supported` without printing private evidence.

The public `verify-history` CLI, user-facing trust configuration and the complete
clean-environment pilot remain required. This stage does not complete CP-015 or
M0–M5, and synthetic keys/authorities do not satisfy production assurance gates.
