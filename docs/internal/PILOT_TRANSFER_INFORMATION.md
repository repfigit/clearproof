# Pilot transfer information profile

Authorization accepts UTF-8 JSON using the explicit
`clearproof-transfer-information-v1` schema. The payload includes exact
transfer/context digests, asset identity, base-unit amount, and originator and
beneficiary information. Each party contains the exact `Participant` from the
transfer plus a tagged natural-person or legal-person identity. Names and postal
address lines must be bounded, nonblank text without control characters. Legal
persons also require a two-letter registration-country field. Country fields
currently check uppercase two-letter syntax, not an independently maintained
country registry.

Both parties' wallet, kind and VASP DID, and the asset/amount/context fields must
match the authenticated transfer exactly. Unknown fields, unsupported schema/person
types, absent required fields, duplicate JSON keys and malformed JSON reject.
Unicode names are preserved. This local profile deliberately requires a postal
address for both party types; this is a pilot input contract, not a statement of
every jurisdiction's requirements or a full representation of possible identities.

The validator parses at most 32 KiB in memory and returns no personal fields. It
raises a generic error without retaining a Pydantic exception containing customer
input. The service encrypts the exact original bytes, preserving UTF-8 encoding
and whitespace. It does not save a plaintext model or log names/addresses. Changed
bytes under the same idempotency key conflict; there is no silent rewriting of
customer information.

The existing [IVMS101.2023 reference](https://raw.githubusercontent.com/TransactionAuthorizationProtocol/ivms101/main/specs/ivms101-2023.md)
describes a data model with constraints and distinguishes that scope from other
layers of a transfer system. The repository's existing IVMS101 wrappers are not
full validators. This new profile is explicitly a Clearproof internal schema;
its field names and tagged identity objects must not be advertised as an IVMS101
wire message. A complete, versioned IVMS101 mapping and bilateral interoperability
remain required work.

Structural validation does not establish identity truth. Authorization additionally
requires an [exact-payload source approval](PILOT_INFORMATION_APPROVAL.md), binding
the name/address bytes and credential reference to a scoped trusted signer. The
external business attestation about completeness remains a separate check. Actual
source-document review/retention, jurisdiction-specific requirements, sender
authentication, delivery and acknowledgment remain open.

Focused tests cover natural/legal persons, Unicode, exact maximum-size bytes,
private representations/errors, field and party substitution, missing/ambiguous
identities, malformed/duplicate JSON and invalid text. The real PostgreSQL/proof
authorization scenario rejects opaque/empty/mismatched information without writes,
retains the validated information only in the recipient envelope, decrypts after
reconnect, and rejects a changed valid name with the original retry key.
