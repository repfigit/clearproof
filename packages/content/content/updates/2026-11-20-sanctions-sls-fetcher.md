---
id: UP-2026-007
title: Sanctions tree fetchers repaired — SLS consolidated XML and circuit-matched legacy depth
date: 2026-11-20
publishAfter: 2026-11-20T21:00:00Z
sourceCommit: 46ebfe3bb305a2f592419946b89201ffb71833c3
claimRefs:
  - scripts/build_sanctions_tree.py
  - scripts/build_pilot_sanctions_tree.py
  - .github/workflows/sanctions-update.yml
  - Makefile
status: approved
summary: OFAC's retired consolidated CSV is replaced by the Sanctions List Service CONS_ADVANCED.XML fetcher, and the legacy sanctions tree is now built at the depth the legacy circuit actually pins (20, not the auto-sized 8).
---

Two fixes landed this week in the sanctions data pipeline that feeds the
Merkle root behind proof checks.

## The retired consolidated CSV endpoint

OFAC has moved consolidated-list distribution to the Sanctions List Service.
The old `cons_advanced.csv` download no longer exists — the repository's fix
records it returning 404 since 2026-11-13 — so the tree builder now fetches
the SLS `CONS_ADVANCED.XML` document instead. The SLS download endpoint
redirects to a signed S3 URL serving the XML, and the new fetcher parses it
the same way the SDN XML fetcher does: crypto program keywords plus a
raw-hex token sweep over the whole document. Addresses are raw hex only; no
ENS or other name resolution is performed.

As of the 2026-11-04 issue the consolidated file contains no digital-currency
feature types, so it contributes zero addresses today. The fetcher is kept
for source-set completeness and picks up any future consolidated crypto
entries automatically. The pilot tree builder now uses the same XML fetcher.

## Building the legacy tree at the depth the circuit pins

The daily sanctions-update workflow and the `build-sanctions-tree` make
target built the legacy tree at auto depth — 8, given today's leaf count —
while the legacy 16-signal circuit pins `ComplianceProof(20, 10)`. Witness
paths from a depth-8 artifact do not match the circuit's fixed 20-element
path inputs, so real proof generation on the legacy profile could not use
the committed artifact. Both call sites now pass the documented `--depth 20`,
and `extend_depth()` extends the naturally sized tree to the target. The
pilot tree is unaffected — it derives at fixed depth 20 by key-sorted order.

The workflow and Makefile sources are readable in full in the repository at
[.github/workflows/sanctions-update.yml](https://github.com/repfigit/clearproof/blob/main/.github/workflows/sanctions-update.yml)
and the [Makefile](https://github.com/repfigit/clearproof/blob/main/Makefile).

Unchanged from the earlier
[sanctions-schedule update](https://docs.clearproof.world/updates/2026-09-21-sanctions-schedule):
a rebuilt tree still never relays itself. The on-chain relay stays a
deliberate operator step on every deployed chain.
