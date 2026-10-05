# Legacy envelope salt configuration

The API requires `HKDF_SALT` before entering serving state. This applies even
when the preferred information envelope is HPKE: the legacy AES-GCM derivation
path remains available. Direct callers of `src.sar.encryption.derive_key` enforce
the same requirement. Missing, empty and whitespace-only values fail closed.

For a new deployment, provision a unique random salt, such as the value produced
by `openssl rand -hex 32`, in the operator's protected configuration. Store it
alongside the legacy encryption master key and retain it for as long as those
ciphertexts must remain readable. Do not regenerate it on process restart.
The salt string is encoded as UTF-8, including hex-looking values; it is not
hex-decoded. Configured values retain their historical byte representation.

## Upgrade an existing deployment

Before upgrading, identify the exact salt that encrypted each retained legacy
envelope. A changed salt derives a different key: changing the environment
variable alone does not rotate or migrate retained ciphertext.

- If `HKDF_SALT` was already configured, preserve its exact value and encoding.
- If it was unset or empty, older code used the literal `zk-travel-rule-v1`.
  Explicitly configure `HKDF_SALT=zk-travel-rule-v1` to retain access to those
  envelopes. This documents the existing derivation; it does not improve its
  deployment separation. Moving to a unique salt requires an operator-managed
  migration with the original keys/salt retained until verified re-encryption
  and retention requirements are satisfied. No automatic migration is provided.
- Never delete the old salt/key or overwrite the original envelope before the
  replacement is verified. Inspect using synthetic fixtures before touching
  retained records. Never place plaintext exports or secret configuration in
  logs, public issues or source control.

Pilot `RecordCipher` storage and HPKE envelopes have their own derivation and
recipient-key boundaries. This change does not alter their cryptographic formats
or silently re-encrypt stored data.

## Disposable tests and demos

Exactly `ALLOW_INSECURE_HKDF_SALT=1` explicitly enables the historical default
when no usable salt is set. Other values do not opt in. Do not configure this
switch in production. A configured salt takes precedence over the switch.
Repository tests set a synthetic `HKDF_SALT`; they do not implicitly opt in based
on pytest detection or an authentication mode.
