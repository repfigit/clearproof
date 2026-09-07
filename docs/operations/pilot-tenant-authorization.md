# Pilot tenant authorization boundary

Status: CP-005 foundation. `TenantPrincipalDependency` and its tests exist, but the legacy credential/proof routes do not yet use it. Durable tenant stores, membership administration and issuance/proving integration remain open. Do not infer tenant isolation for the old routes from these tests.

The pilot dependency first invokes the configured authentication verifier. For signed JWTs it then requires opaque `tenant_id` and `actor_id` claims plus an explicit `roles` list. These must come from the configured trusted token issuer. Headers, query parameters and request bodies cannot select a tenant. Invalid/missing scopes return HTTP 403; invalid signatures return HTTP 401.

Roles are explicit: credential issuance/revocation, proof generation/inspection/consumption, evidence reading/decryption, event ingestion, policy reading/approval and tenant administration. No wildcard is accepted. `tenant:admin` does not implicitly grant decryption or proof consumption. Issuance and revocation additionally require the exact issuer DID in `issuer_dids`; active issuer/root authority must still be checked by the service. An authorized role is not proof of KYC facts, licensing or holder consent.

For the local static API-key mode, the operator must set `API_KEY_TENANT_ID`, `API_KEY_ACTOR_ID` and comma-separated `API_KEY_ROLES`. `API_KEY_ISSUER_DIDS` declares optional exact DID scopes. One static key maps to one tenant. The implementation has no default tenant or permissive role fallback. SIWE sessions currently lack tenant-membership claims and therefore cannot satisfy this dependency; a durable membership resolver must be added before enabling that path.

Real ES256 token tests check tenant binding, wrong signing keys, missing claims and spoofed headers/query parameters. Role tests cover cross-issuer attempts and missing consumption/decryption/revocation grants. They do not yet test database isolation.

Existing credential-route logs now include only opaque record IDs. They no longer include subject wallets, issuer/jurisdiction details or caller-provided revocation reasons. API integration tests capture these logs to prevent regression.
