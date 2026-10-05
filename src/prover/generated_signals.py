"""Generated: specs/pilot-signals-v3.json; SHA256 4932f8bc2948340926aeb23c7ed202bb47615ba9c570c2731daea64366206948."""

PROFILE = "pilot-transfer-v3"
PUBLIC_SIGNALS = (
    "projection_commitment",
    "authorized_issuer_root",
    "sanctions_root",
    "authorization_nullifier",
    "evaluated_at",
    "proof_expires_at",
    "domain_chain_id",
    "domain_registry",
)
PILOT_PUBLIC_SIGNAL_COUNT = 8
PROJECTION_FIELD_COUNT = 48
PROJECTION_COMMITMENT_INDEX = 0
AUTHORIZED_ISSUER_ROOT_INDEX = 1
SANCTIONS_ROOT_INDEX = 2
AUTHORIZATION_NULLIFIER_INDEX = 3
EVALUATED_AT_INDEX = 4
PROOF_EXPIRES_AT_INDEX = 5
DOMAIN_CHAIN_ID_INDEX = 6
DOMAIN_REGISTRY_INDEX = 7
ISSUANCE_TREE_DEPTH = 32
ISSUER_TREE_DEPTH = 20
SANCTIONS_TREE_DEPTH = 20
HOLDER_DOMAIN_TAG = 101
CREDENTIAL_DOMAIN_TAG = 102
ISSUER_LEAF_DOMAIN_TAG = 103
PROJECTION_DOMAIN_TAG = 201
AUTHORIZATION_SCOPE_DOMAIN_TAG = 202
AUTHORIZATION_NULLIFIER_DOMAIN_TAG = 203
BOUND_PROJECTION_DOMAIN_TAG = 204
SANCTIONS_LEAF_DOMAIN_TAG = 301
PROOF_LIFETIME_SECONDS = 300
MAX_TRANSFER_AGE_SECONDS = 86400
MAX_ASSET_DECIMALS = 18
FIELD_NAMES = (
    "transfer_digest_hi",
    "transfer_digest_lo",
    "context_digest_hi",
    "context_digest_lo",
    "tenant_hi",
    "tenant_lo",
    "transfer_id_hi",
    "transfer_id_lo",
    "nonce_hi",
    "nonce_lo",
    "originator_wallet",
    "beneficiary_wallet",
    "asset_chain",
    "asset_contract",
    "asset_decimals",
    "amount_base_units",
    "valuation_numerator",
    "valuation_denominator",
    "usd_cents",
    "valuation_observed_at",
    "valuation_expires_at",
    "transfer_created_at",
    "transfer_expires_at",
    "evaluated_at",
    "max_transfer_age",
    "jurisdiction",
    "deployment_chain",
    "deployment_address",
    "policy_digest_hi",
    "policy_digest_lo",
    "catalog_digest_hi",
    "catalog_digest_lo",
    "threshold_2",
    "threshold_3",
    "threshold_4",
    "private_tier",
    "originator_did_hi",
    "originator_did_lo",
    "originator_is_vasp",
    "beneficiary_did_hi",
    "beneficiary_did_lo",
    "beneficiary_is_vasp",
    "valuation_source_hi",
    "valuation_source_lo",
    "valuation_evidence_hi",
    "valuation_evidence_lo",
    "valuation_digest_hi",
    "valuation_digest_lo",
)
PROJECTION_FIELD_WIDTHS = (
    128,
    128,
    128,
    128,
    128,
    128,
    128,
    128,
    128,
    128,
    160,
    160,
    64,
    160,
    5,
    128,
    128,
    128,
    128,
    53,
    53,
    53,
    53,
    53,
    17,
    16,
    64,
    160,
    128,
    128,
    128,
    128,
    128,
    128,
    128,
    3,
    128,
    128,
    1,
    128,
    128,
    1,
    128,
    128,
    128,
    128,
    128,
    128,
)
