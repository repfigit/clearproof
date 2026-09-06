# Encrypted evidence export

`EvidenceExportService` requires both `evidence:export` and `evidence:decrypt`.
An `EvidenceRecipient` supplied by authenticated server configuration approves a
reviewer ID and X25519 key for one tenant and a bounded validity interval. This
reviewer is independent of the transfer beneficiary. A caller's arbitrary public
key must not be promoted into that server configuration.

Export selects one authorization receipt and checks its identity, proof/capture
scope and capture-manifest digest. It resolves every evidence reference at its
recorded revision and checks the recorded canonical hash. It reconstructs captured
configuration bytes from their exact chunks, checking both size and SHA-256.
Missing or changed records/chunks reject the export; current roots or policies
are never substituted for the captured versions.

The `clearproof-history-bundle-v1` plaintext contains receipt, retained proof and
recipient envelope, capture manifest, pinned source records and exact base64
configuration bytes. It is bounded to 8 MiB and built only in memory. The service
returns a `clearproof-encrypted-history-v1` HPKE wrapper; tenant, receipt, reviewer,
reviewer key fingerprint and export time are bound as associated data. Neither
plaintext evidence files nor consumption records are created by export. Repeating
export generates fresh encryption and performs no authorization.

`open_evidence_bundle` decrypts offline with a reviewer private key and independently
expected binding metadata. It rejects wrong keys, changed associated data,
ciphertext tampering, wrong bundle scope and oversized input. The helper returns
private evidence to its authorized caller; it does not print or persist it.

Decryption is not historical verification. A separate
[offline inspector](PILOT_HISTORY_INSPECTION.md) checks linked integrity and real
pairing against reviewer-supplied pins, while retaining an indeterminate historical
outcome when authority evidence is missing. The exported proof includes a signed decision attestation; independent reviewer
trust is required to authenticate it. HPKE base mode does not authenticate the
exporter.
Captured/local clocks and local revocation absence remain explicitly labeled.
Complete historical authority and authenticated timing/status evidence,
supported/contradicted/indeterminate reporting and the public `verify-history`
command remain required CP-015 work.

The real-proof/PostgreSQL test exports after later policy activation and revocation,
then confirms the bundle still contains the original activation revision and
captured bytes. It covers missing export permission, recipient scope/expiry,
wrong keys/binding, corrupted ciphertext, missing chunks and unchanged record and
consumption counts. A fresh Python process decrypts the encrypted artifact after
the database closes, with socket connections disabled, and reports only the
receipt ID and evidence count.

When a verified [timestamp record](PILOT_HISTORY_TIMING.md) has been attached,
export includes it alongside the immutable receipt/proof. Attachment is separate
from original capture and cannot change the decision. Offline review supplies its
own TSA trust; neither export inclusion nor decryption approves a certificate.
