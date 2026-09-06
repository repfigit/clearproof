# Scoped external policy-fact attestations

`src.policy.fact_approval` authenticates claims about applicability resolution,
counterparty trust, required information completeness and counterparty
acknowledgment. The signer is independently configured for a tenant, chain,
registry, source IDs, predicates, validity interval, maximum fact lifetime and
maximum observation age. Ed25519 signatures use a distinct application purpose
and bind the exact transfer and verification-context digests, predicate, boolean
value, evidence digest, observation/expiry times and signing time.

Authority configuration cannot be derived from an incoming attestation. Retaining
a signature does not establish the claim's truth, legal sufficiency, the source
document's availability or independent trusted timing. Those remain operational
and historical-verification requirements. A context digest also binds its policy,
artifact and deployment; an attestation cannot silently migrate to another context.

Verification accepts up to 64 attestations and 256 configured authorities. Exact
retries deduplicate; different attestations for a single predicate reject even if
both signers are trusted. Arrival order never chooses a winner. False values stay
false, and missing facts stay missing. The output is minimized `PolicyFacts`, not
an authorization, approval or claim of complete evidence.

Attestors cannot supply credential validity, sanctions clearance, valuation
authentication or proof validity. Those predicates must come from the appropriate
current verification workflow. Tests feed externally attested facts into the
existing evaluator and require INDETERMINATE while those derived facts are absent.

The module is not yet wired to durable fact retention, policy activation or
atomic authorization. It performs no network calls or storage writes. Future
services must preserve signed source evidence in tenant-authorized encrypted
storage, apply independent current trust, and combine derived facts only after
their corresponding checks succeed. Evidence digests alone are not retention.
