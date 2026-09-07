# Historical pilot registry status

Authorization captures a versioned credential status observation inside its
receipt-bound evidence manifest. It identifies the credential, issuer, registry
scope and observation time. The registry ID binds the tenant and chain/contract
audience; the observation is made while the authorization transaction holds the
same tenant lock used by supported revocation writers. Its exact content is
covered by the retained decision signature through the evidence digest.

`HistoryStatusTrust` is separate reviewer configuration. Each authority explicitly
delegates one decision key as status authority for an issuer and registry, with
tenant/deployment scope, validity and compromise constraints. Trusting a decision
signer alone does not delegate credential status authority. A caller must approve
this registry as authoritative for the pilot credential's revocations; this is
not inferred from a key, signed payload, absent row or current registry state.

After bundle integrity and independent statement reconstruction, offline review
checks the captured credential/issuer/registry, exact decision/observation/capture
time agreement, receipt-to-manifest digest and real decision signature. It applies
status authority validity and compromise rules independently. Successful review
sets `status_authenticated`; missing delegation or evidence leaves the result
indeterminate. Older observations without the versioned registry/issuer fields
cannot satisfy this check.

This authenticates an authoritative registry's point-in-time observation for the
configured pilot scope. It does not establish global revocation history, cover an
external issuer's unconnected status service, or make a current absence into past
status. A later recorded revocation does not replace the captured observation.
Known signer compromise at review time remains indeterminate even if the claimed
observation predates it. Independent [timing verification](PILOT_HISTORY_TIMING.md) is separately
required, and successful status authentication alone cannot produce a `supported`
outcome or authorize replay.

The real-proof PostgreSQL scenario exports after an actual later revocation and
policy change, verifies the original scoped observation with independent trust,
and rejects wrong issuer/registry/tenant, compromised signer, changed time/status/
credential and missing signature. It confirms that the combined statement,
policy, decision and status checks still leave independent timing unresolved.
