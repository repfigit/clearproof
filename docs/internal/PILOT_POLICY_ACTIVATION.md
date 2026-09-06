# Reviewed policy activation

`PolicyActivationService` separates review from current selection. `policy:approve`
retains reviewed versions and expected cases; the separate `policy:activate` role
selects a retained, currently effective version. Neither role implies the other,
and both storage operations require evidence decryption. `policy:read` reads the
current selection. Tenant scope comes from the authenticated principal.

Additive migration 14 introduces encrypted `policy-activation` revisions keyed by
tenant/deployment/jurisdiction scope. Each activation records its selected policy,
server actor/time, sequential revision and preceding activation digest. The caller
must supply the expected revision (null only for initial activation). A tenant
transaction prevents competing selections from both succeeding. A repeated
idempotency key returns its original receipt without creating another selection;
that receipt is historical and does not assert the policy is still current.

Current reads validate the retained head and policy approval, check exact scope
and effective validity, and fail if absent or expired. Historical revisions remain
available through authorized encrypted storage. Activating a previously reviewed
version is an explicit rollback selection with a new activation revision; it does
not delete intervening history or revive an expired policy.

This is an authenticated local service, not a signed external policy authority or
proof of source truth. Current inspection still uses configured policy pins; wiring
this service's active head into the same verification/consumption transaction
remains open. No API activation endpoint, authorization consumption, legal approval
or historical timing attestation is implied.

PostgreSQL tests cover activation before review, review without activation,
idempotent retry, competing selections with one winner, retained predecessor
binding, explicit rollback, reconnect, expired selection, foreign tenant and
missing activation role. Activation never consumes a transfer authorization.
