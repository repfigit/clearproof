# ADR 0007: Scoped valuation approvals

Status: implemented for composed witness construction; current authorization
integration and live source ingestion remain open.

The transfer already binds an exact reduced rational quote in USD cents per
asset base unit. Its numerator, denominator, source identity, evidence digest,
observation/expiry times and full valuation digest participate in the private
projection. Arithmetic correctness alone cannot authenticate those inputs.

`ValuationApproval` signs the complete valuation, tenant, asset catalog digest,
signing timestamp and key ID under `clearproof/valuation-approval/v1`. Key IDs
use a separate `clearproof/valuation-key/v1` domain. Ed25519 signatures are
verified outside the circuit; they are not claimed to be ZK-verified.

Operator configuration pins each public key to a tenant, catalog digest, exact
chain-qualified assets, exact source IDs and a key validity interval. It also
sets maximum quote lifetime and observation age. Verification checks the exact
transfer valuation and trusted catalog, the independent caller tenant, signing
time, expiry, key interval, source/asset scope and signature. The entire quote
interval must lie inside the key's approval interval. Freshly signing an old
observation cannot reset its age. Cross-chain same-symbol assets remain distinct.

`compliance_witness` now requires a signed valuation approval and a configured
`ValuationTrustStore`. It validates them at the context's claimed evaluation
time before encoding the projection. This permits deterministic historical
fixtures; it is not a substitute for checking current time. The application
verifier must repeat quote validation using its authenticated tenant and actual
clock, check the rest of the current state, and derive the expected projection
from those authenticated inputs. A prover can bypass a witness encoder, so the
encoder check by itself is not an authorization security boundary.

The signing authority must validate the source evidence and correct asset/base
unit interpretation before signing. A source evidence hash does not establish
that the source data was true or even available; durable authenticated evidence
retention remains part of the later export workflow. The authority's pricing
truthfulness is an explicit trust assumption. No stablecoin peg is inferred.
This approves a scoped quote within configured bounds, not necessarily the latest
quote, a business policy, legal compliance or settlement.

Rotation supports overlapping configured keys. Removing a key from the current
trust store stops accepting its approvals; historical verification will require
retained, authenticated historical trust configuration and timing evidence.
No remote key discovery, implicit trust bootstrap or live provider integration
is introduced. Synthetic tests generate local signing keys and do not establish
that any live quote provider or external feed has been integrated.

Validation includes real Ed25519 signatures, coherent forged transfer/quote
values still rejected by the old signature, tenant/catalog/asset/source scope,
expiry/age boundaries, key overlap/removal and cross-purpose signature rejection.
The composed circuit and its eight-signal ABI are unchanged.
