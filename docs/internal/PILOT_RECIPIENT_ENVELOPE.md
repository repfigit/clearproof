# Trusted recipient envelope

Pilot authorization requires 1–32768 bytes of [validated transfer information](PILOT_TRANSFER_INFORMATION.md)
and an independently configured
`RecipientTrustStore`. Each immutable authority pins an X25519 public key to one
tenant, chain, registry address, beneficiary VASP DID and validity interval. The
requested key ID must resolve in that inventory and match the actual transfer.
Unknown, expired, future, wrong-scope and unusable low-order keys fail. The pilot
profile currently supports VASP beneficiaries; self-hosted recipient key authority
requires a separately specified profile.

Operators supply this inventory through authenticated server configuration. It is
not a caller-supplied public key, a discovery response automatically promoted to
trust, or an independent certification of the VASP. Rotation can overlap approved
keys; removing a key prevents new envelopes without deleting retained ciphertext.
Recipients may retain old private keys for historical decryption.

`clearproof-pilot-envelope-v1` wraps the existing HPKE v2 suite. Associated data is
a domain-separated digest of tenant, exact transfer/context/proof digests,
recipient DID/key ID and sealing time. Ciphertext uses bounded 2048-character
base64 chunks so it fits the existing canonical encrypted-record format. The
legacy HPKE format and its protocol bridge serialization are unchanged.
HPKE decoding requires the canonical padded base64url encoding emitted by the
encoder. Ignored characters, whitespace, extra padding and nonzero unused pad
bits reject, even when a permissive decoder would recover identical bytes.

`open_pilot_envelope` requires independently expected binding metadata. It checks
the complete binding, key fingerprint derived from the recipient private key,
HPKE header and associated data before decryption. Copying expected metadata from
the received envelope does not establish transfer authenticity. Base-mode HPKE
does not authenticate the sender or validate the plaintext's business semantics.

The authorization service seals only after successful current proof inspection
and policy ALLOW, then retains the recipient envelope inside the encrypted proof
record. Receipt and proof identity bind the randomized envelope digest. Plaintext
is not retained or logged; its fingerprint is used only inside the encrypted
idempotency request digest, not in externally visible identifiers. Changed payloads
or recipient keys with the same retry key conflict. Exact historical retries
recover the original ciphertext and receipt even after key expiry.

Recipient authority or encryption failure aborts authorization. A subsequent
storage/consumption failure rolls back the envelope, proof, receipt and consumption
together. There is no shared-key or plaintext fallback. Live delivery,
acknowledgment, complete IVMS101 mapping and remote bilateral interoperability
remain separate integration gates. The local counterparty simulator checks
independently trusted information and decision signatures before accepting its
decrypted payload; it does not establish live interoperability. The signed business fact about information
completeness does not establish the truth of the validated personal fields.

Tests use real X25519/HPKE and synthetic bytes. They cover scoped authority,
validity and rotation overlap, wrong keys, altered metadata/associated data,
valid-base64 ciphertext corruption, noncanonical encoding, maximum payload size, encryption failure,
changed-payload retries and recipient decryption after database reconnect.
