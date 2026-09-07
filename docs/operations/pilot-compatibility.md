# Pilot compatibility matrix

The source manifests identify software version 0.4.0. Software versions, discovery
versions, proof profiles and envelope versions are separate identifiers. The API
reports the installed Python distribution version; an uninstalled source import
reports `unknown`. Neither a version string nor matching signal count establishes
artifact approval. This matrix describes the source implementation, not an npm
release, public repository availability or a deployed chain.

## Protocol and data compatibility

| Surface | Current local pilot | Earlier/other material | Selection and migration rule |
| --- | --- | --- | --- |
| Discovery | Profile `0.4.0`, typed X25519 HPKE key and supported suite | `0.2.0`/`0.3.0` documents are unsupported; legacy `publicKey` is informational | Upgrade both endpoints explicitly. Never reinterpret an old key or downgrade encryption after discovery failure. See the [discovery spec](../../specs/well-known-clearproof.md). |
| Legacy proof demo | Separate legacy circuit and 16-signal vector, with matching locally generated keys | Does not select the current pilot authorization profile | Use legacy artifact paths only for the legacy demo/parity tests. A successful legacy pairing is not current pilot authorization. |
| Current proof statement | `pilot-transfer-v2`, eight ordered signals and credential-bound projection | `pilot-transfer-v1` also has eight signals but different first-signal meaning and keys | Choose by independently pinned manifest/profile, never signal count. Current artifact/context checks reject v1; read-only pairing can inspect pinned v1 material. See [v2 statement](../../specs/pilot-transfer-v2.md). |
| Artifact manifest | `clearproof-artifact-manifest-v1`; explicit v2 profile and exact file/runtime pins | Missing profile defaults to historical pilot v1; unsupported fields/layouts reject | Do not edit labels to promote artifacts. All supported manifests remain `development-unapproved`; production mode rejects them. |
| Transfer and context | `clearproof-transfer-v1`, `clearproof-verification-context-v1` | Unknown schema combinations reject | Preserve canonical asset identity, base units, participants, tenant, chain/registry, policy, clocks and artifact digest. See [transfer evidence](../../specs/transfer-evidence-v1.md). |
| Pilot recipient envelope | `clearproof-pilot-envelope-v1`, wrapping recipient HPKE with exact transfer/context/proof binding | The legacy hybrid payload's shared-key AES-GCM mode is a different interface | HPKE envelope version is not proof-profile version. Use the separately configured recipient authority/key and signed information approval; no fallback or resealing under an unchanged receipt. |
| Local authorization | `clearproof-local-authorization-v1`, retained proof/evidence and PostgreSQL consumption | Observation results and generic evidence receipts are different records | Only the current authorization service can create the consumed receipt. Contract mirroring records that receipt and does not independently consume another transfer. |
| Observation | Newly created `clearproof-proof-observation-v2` includes evaluation timing | Retained v1 observations remain readable without invented latency | Decoders route explicitly. Exact retry returns its original version/time; a new evaluation uses a new idempotency key. Cohort report v2 keeps missing measurements explicit. |
| Investigation | Event/investigation/queue v1 profiles; optional scoped `provider_links` | Older v1 reports may omit navigation links | Current CLI handles omitted links. Navigation is operator configuration, not a new event commitment or provider signature. |
| Bilateral exchange | Explicit `clearproof-local-bilateral-v1` in-process profile | Unsupported request profile yields unsupported-version | This is not TRP wire conformance. Live transport, certificates and message translation require separate acceptance evidence. |
| Historical evidence | `clearproof-encrypted-history-v1` containing `clearproof-history-bundle-v1`; reviewer configuration v1 | Missing authority/status/timing evidence can make review indeterminate | Preserve exact encrypted bytes and independently selected bindings/keys/artifacts. Successful decryption alone does not verify history or authorize replay. |
| Persistent schema | Ordered migrations through 19 in the current source | Legacy rows have distinct ownership/representation constraints | Startup serializes migrations. Do not point an older writer at a newer schema or infer ownership of unscoped rows. Use the rollback procedure below. |

## Runtime and deployment boundary

The [clean-checkout guide](local-pilot-acceptance.md) records tested host versions
and lockfile installation commands. `test_pilot_local.py` explicitly requires
PostgreSQL 18 and creates a private Unix-socket cluster. Node and Python clients
must use their own installed, matching source dependencies. Circom 2.2.2 is pinned
in CI; generated proving keys are not byte-reproducible or approved ceremony keys.

The current registry fixture deploys a verifier matched to the selected development
verification key before generating its bound proof. Existing deployed addresses,
including old testnet contracts, must not be assumed to support this profile.
Pin chain, registry/runtime, source checkpoints, policies and manifest separately.

## Upgrade and rollback sequence

1. Record the source revision, lockfiles, database schema versions, artifact/runtime pins, scoped policies and authority configuration under controlled access.
2. Stop old writers and take a protected database backup. Keep the required old storage and recipient keys separately; copying ciphertext without its authorized keys is not a usable backup.
3. Install from the lockfiles and inspect the selected artifacts with the [doctor](../internal/PILOT_ARTIFACT_DOCTOR.md). Confirm current v2 context support and the separate development-assurance result.
4. Start the compatible application and let its transactional migration runner finish. Investigate rejection; never delete malformed evidence to force migration success.
5. Run the [local acceptance command](local-pilot-acceptance.md), then authenticated read-only checks under the operator's configured tenant/trust before enabling a new pilot workflow.
6. Before a migration commits, failure rolls back its transaction. After commit, use a compatible build or restore the pre-upgrade backup into a separate controlled database after accounting for intervening writes. Do not reset nullifiers, broadcast attempts or event identities to make an old application work.

The detailed [proof-storage upgrade](proof-storage-upgrade.md),
[tenant storage](pilot-tenant-storage.md), [enrollment](pilot-enrollment.md) and
[publication recovery](../internal/PILOT_PUBLICATION_JOURNAL.md) guides govern
their respective boundaries. There is no automatic downgrade migration, fee/nonce
replacement, production artifact promotion or live-provider compatibility claim.
