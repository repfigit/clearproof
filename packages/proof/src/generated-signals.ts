// Generated: specs/pilot-signals-v3.json; SHA256 4932f8bc2948340926aeb23c7ed202bb47615ba9c570c2731daea64366206948.
export const PROFILE = 'pilot-transfer-v3' as const;
export const PUBLIC_SIGNALS = [
  'projection_commitment',
  'authorized_issuer_root',
  'sanctions_root',
  'authorization_nullifier',
  'evaluated_at',
  'proof_expires_at',
  'domain_chain_id',
  'domain_registry',
] as const;
export const PILOT_SIGNAL_INDICES = {
  projection_commitment: 0,
  authorized_issuer_root: 1,
  sanctions_root: 2,
  authorization_nullifier: 3,
  evaluated_at: 4,
  proof_expires_at: 5,
  domain_chain_id: 6,
  domain_registry: 7,
} as const;
export const PILOT_PUBLIC_SIGNAL_COUNT = 8;
export const PROJECTION_FIELD_COUNT = 48;
export const PROJECTION_COMMITMENT_INDEX = 0;
export const AUTHORIZED_ISSUER_ROOT_INDEX = 1;
export const SANCTIONS_ROOT_INDEX = 2;
export const AUTHORIZATION_NULLIFIER_INDEX = 3;
export const EVALUATED_AT_INDEX = 4;
export const PROOF_EXPIRES_AT_INDEX = 5;
export const DOMAIN_CHAIN_ID_INDEX = 6;
export const DOMAIN_REGISTRY_INDEX = 7;
export const ISSUANCE_TREE_DEPTH = 32;
export const ISSUER_TREE_DEPTH = 20;
export const SANCTIONS_TREE_DEPTH = 20;
export const HOLDER_DOMAIN_TAG = 101;
export const CREDENTIAL_DOMAIN_TAG = 102;
export const ISSUER_LEAF_DOMAIN_TAG = 103;
export const PROJECTION_DOMAIN_TAG = 201;
export const AUTHORIZATION_SCOPE_DOMAIN_TAG = 202;
export const AUTHORIZATION_NULLIFIER_DOMAIN_TAG = 203;
export const BOUND_PROJECTION_DOMAIN_TAG = 204;
export const SANCTIONS_LEAF_DOMAIN_TAG = 301;
export const PROOF_LIFETIME_SECONDS = 300;
export const MAX_TRANSFER_AGE_SECONDS = 86400;
export const MAX_ASSET_DECIMALS = 18;
