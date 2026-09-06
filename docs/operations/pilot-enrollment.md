# Pilot wallet enrollment

`POST /pilot/credential/enroll` records wallet-authorized enrollment in encrypted
PostgreSQL tenant storage. Its response is `awaiting-root-publication`, not an
active credential or proof authorization. The legacy `/credential` routes remain
on the legacy registry and cannot read these records.

Configure `DATABASE_URL`, `PII_MASTER_KEY`, `PILOT_CHAIN_ID` and
`PILOT_REGISTRY_ADDRESS`. The latter two select the operator-controlled audience,
not caller-selected defaults. Chain IDs in this enrollment JSON profile are
positive safe integers (at most 2^53−1); the registry is a lowercase nonzero EVM
address. A missing database or encryption/audience configuration fails closed.

The authentication provider must sign tenant and opaque actor claims and grant
`credential:issue` plus the exact canonical issuer DID in `issuer_dids`. Merely
having a wallet, API key or tenant admin role does not grant issuer authority.
Development API keys need the explicit operator scopes documented in
`pilot-tenant-authorization.md`.

The request has three fields: `consent`, `signature` and `idempotency_key`.
`consent` is `EnrollmentConsent` from `src/protocol/enrollment.py`: the complete
`PilotCredential`, chain ID, registry address and consent expiry. The wallet signs
EIP-191 personal_sign bytes consisting of `Clearproof credential enrollment v1`,
a newline and the exact bounded canonical JSON representation of the consent.
`EnrollmentConsent.signing_message()` constructs the corresponding eth-account
message. Wallet UI should show the enrollment purpose and all agreed terms.

This version accepts EOA signatures only, in lowercase `0x`-prefixed 65-byte form,
with v=27/28 and low-s. Contract wallet/EIP-1271 enrollment is not supported.
The credential nonce must be freshly generated with 256 bits of cryptographic
randomness. The holder generates and retains its own nonzero canonical scalar
secret and supplies only the holder commitment. Never send that secret to this
endpoint. The issuer's signed authentication grants issuance scope; consent does
not prove that the issuer performed KYC or screening correctly.

Consent can last at most ten minutes from the credential's issued-at time. The
service checks signature, role, tenant, audience and time before every mutation
or idempotent retry. Expired consent cannot start or retry issuance. Matching
retries within validity return the original result; a different request/actor
under the same idempotency key, or the same credential under another key,
conflicts. The encrypted record retains consent, wallet signature, accepted actor,
acceptance time and credential commitment. The response exposes only an opaque
credential ID and pending status.

Next activation gates are the registrar-authenticated issuance and issuer roots,
revocation, composed transfer proving and verification. Neither this endpoint nor
the legacy proof route establishes those gates. Tests use real ES256 API tokens,
EOA enrollment signatures and PostgreSQL, with app reconstruction and database
pool reconnection; a full operating-system process recovery test remains open.
