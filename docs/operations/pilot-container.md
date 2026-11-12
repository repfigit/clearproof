# Run the local pilot acceptance in a container

This is the shortest path from a clean machine to the complete current-profile
pilot. It packages the host prerequisites of the
[local acceptance guide](local-pilot-acceptance.md) (Node 24, Python 3.12,
PostgreSQL 18 and Circom 2.2.2) in one image and runs the same commands as the
README's source-checkout path.

**Development only.** The run generates unapproved development proving keys, uses
synthetic data and counterparties, publishes no network port and makes no
shared-network transaction. It is not a deployment of the API and it is not
evidence of production readiness, an audit or customer adoption.

## Run

Docker with the Compose plugin is the only host requirement.

```bash
docker compose -f compose.pilot.yaml up --build
```

The container then:

1. downloads the pinned `2^17` powers-of-tau file and checks its SHA-256 (the
   same file and digest as CI);
2. compiles both circuit profiles and generates development keys;
3. runs the pilot preflight, then the full acceptance with an owned PostgreSQL
   18 cluster on a private Unix socket and a loopback EVM.

The first run downloads the powers-of-tau file and compiles the circuits, so it
takes noticeably longer than later runs, which reuse both from the `pilot-data`
volume. An interrupted circuit build is set aside as
`development-artifacts.incomplete.<time>` and rebuilt; it is never reused.

## Read the results

Each run writes a new directory `runs/<UTC time>/` in the volume. Copy out only
the synthetic reports and inventory:

```bash
docker compose -f compose.pilot.yaml run --rm --entrypoint bash pilot -c 'ls /data/runs'
docker compose -f compose.pilot.yaml cp pilot:/data/runs/<UTC time>/pilot/reports ./pilot-reports
docker compose -f compose.pilot.yaml cp pilot:/data/runs/<UTC time>/pilot/run.json ./pilot-run.json
```

`reports/` and `run.json` are described in the
[local acceptance guide](local-pilot-acceptance.md). The run directory also holds
PostgreSQL data and logs, and `pilot/private/` holds the synthetic export
recipient key. Do not publish those.

## Reset

```bash
docker compose -f compose.pilot.yaml down --volumes
```

This removes the powers-of-tau file, the development keys and every retained run.

## Limits

- The image is built from the checkout you run it in. It does not pull published
  npm packages and does not prove that those packages reproduce this run.
- A passing run establishes local synthetic acceptance on development keys. The
  follow-on gates in the README (external credentials, re-screening, trusted
  distribution, a live pilot and production authorization) are unchanged.
- There is no long-running API service in this file. Serving the API needs
  operator-owned keys, tenant and trust configuration; see
  [tenant storage](pilot-tenant-storage.md), [tenant authorization](pilot-tenant-authorization.md)
  and the `PILOT_*_FACTORY` settings in `.env.example`.
