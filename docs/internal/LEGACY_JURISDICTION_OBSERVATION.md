# Legacy jurisdiction observation

The legacy 16-signal verifier can report whether its claimed jurisdiction matches
an independently selected registry record for the caller-requested VASP DID.
This is an observation, not proof that the VASP is the credential issuer, subject
or legally applicable jurisdiction. It does not change the legacy acceptance set
and is separate from the current v2 pilot's authenticated facts.

The API uses only an operator-provisioned `app.state.chain_reader`. Missing reader,
failed/timed-out lookup, inactive/unregistered VASP or malformed jurisdiction
produces `jurisdiction_matches_vasp: null` and `jurisdiction_observation: unverified`.
A match/mismatch returns true/false with its explicit observation string. The
five-second lookup bound does not turn missing data into success. Registry reads
use deployment-instance-scoped cache entries and immutable tuple results.

The SDK's optional expected-jurisdiction parameter is caller configuration.
Omitting it returns null. The Solidity registry emits `JurisdictionCodeMismatch`
for a differing code; expected code zero denotes an unparseable registered code.
That observation does not revert an otherwise acceptable legacy proof. Event
absence is not evidence of independent source truth. No new public signal,
proving-key layout, compiler mode or current-pilot authorization behavior changes.

Focused tests isolate observational behavior with mocked pairing; the separate
real legacy/pilot artifact suites retain responsibility for cryptographic checks.
