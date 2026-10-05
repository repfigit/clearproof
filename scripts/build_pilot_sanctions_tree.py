#!/usr/bin/env python3
"""Build the pilot-transfer-v3 raw-address sanctions tree (``PilotSanctionsTree``).

The legacy ``build_sanctions_tree.py`` feeds only the 16-signal ``SanctionsOracle``
path. This script derives the pilot tree (depth 20, key-sorted raw EVM addresses
between the ``0`` and ``2^160`` sentinels) from the same normalized feed output,
reusing that script's fetchers and ``normalize_address``. ENS names are never
resolved: only raw hex addresses become leaves.

Inputs (choose one):
    default            ``artifacts/sanctions_tree.json`` written by build_sanctions_tree.py
    --input PATH       another legacy tree artifact (uses its ``sorted_addresses``)
    --fetch            fetch OFAC/EU feeds directly with the legacy fetchers
    --fetch --offline  only the legacy hardcoded OFAC addresses (development)

Output: ``artifacts/pilot_sanctions_tree.json`` with the root, source digest and the
full sorted address list, so an auditor can rebuild the tree and check ordering:

    uv run python scripts/build_pilot_sanctions_tree.py --verify

Building never publishes. Publishing the root as a ``Kind.Sanctions`` checkpoint is
a separate, human-confirmed step: ``scripts/publish_pilot_sanctions_head.py``.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

import httpx

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts import build_sanctions_tree as legacy  # noqa: E402
from src.registry.pilot_sanctions import PilotSanctionsTree  # noqa: E402

# Increment on any change to input selection, normalization or artifact layout.
BUILD_SCRIPT_VERSION = "1.0.0"
DEFAULT_INPUT = legacy.OUTPUT_PATH
DEFAULT_OUTPUT = os.path.join(legacy.ARTIFACTS_DIR, "pilot_sanctions_tree.json")


def canonical_addresses(raw: list[str]) -> list[str]:
    """Normalize with the legacy rules, dedupe and reject anything not a nonzero raw address."""
    if type(raw) is not list or any(type(address) is not str for address in raw):
        raise ValueError("Expected a list of address strings")
    normalized = sorted({legacy.normalize_address(address) for address in raw})
    for address in normalized:
        # Raises for non-hex or zero addresses; the pilot tree has no name resolution path.
        PilotSanctionsTree.address_key(address)
    return normalized


def load_legacy_artifact(path: str) -> tuple[list[str], dict[str, Any]]:
    with open(path, "rb") as handle:
        raw = handle.read()
    data = json.loads(raw)
    addresses = data.get("sorted_addresses") if type(data) is dict else None
    if type(addresses) is not list:
        raise ValueError("Legacy sanctions artifact has no sorted_addresses list")
    manifest = data.get("source_manifest") or {}
    if manifest.get("normalization_spec", {}).get("ens_resolution", "never") != "never":
        raise ValueError("Legacy sanctions artifact was not built from raw addresses only")
    return addresses, {
        "kind": "legacy-sanctions-tree",
        "path": os.path.relpath(path, legacy.PROJECT_ROOT),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "legacy_root": data.get("root"),
        "legacy_build_script_version": manifest.get("build_script_version"),
        "fetch_timestamp": manifest.get("fetch_timestamp"),
        "sources": manifest.get("sources"),
    }


async def fetch_addresses(offline: bool) -> tuple[list[str], dict[str, Any]]:
    addresses = list(legacy.KNOWN_OFAC_ADDRESSES)
    sources: dict[str, Any] = {"hardcoded_ofac": {"addresses_found": len(addresses)}}
    if not offline:
        async with httpx.AsyncClient(
            headers={"User-Agent": "clearproof-sanctions-fetcher/1.0"}, follow_redirects=True
        ) as client:
            for name, fetcher in (
                ("ofac_sdn_xml", legacy.fetch_ofac_sdn_xml),
                ("ofac_consolidated_csv", legacy.fetch_ofac_consolidated_csv),
                ("eu_sanctions_xml", legacy.fetch_eu_sanctions_xml),
            ):
                found, metadata = await fetcher(client)
                addresses.extend(found)
                sources[name] = metadata
    return addresses, {
        "kind": "offline" if offline else "live-feeds",
        "fetch_timestamp": datetime.now(timezone.utc).isoformat(),
        "sources": sources,
    }


def build_artifact(raw: list[str], provenance: dict[str, Any]) -> dict[str, Any]:
    tree = PilotSanctionsTree(canonical_addresses(raw))
    return {
        **tree.artifact(),
        "proof_profile": "pilot-transfer-v3",
        "ens_resolution": "never",
        "build": {
            "script_version": BUILD_SCRIPT_VERSION,
            "script_sha256": legacy.sha256_file(os.path.abspath(__file__)),
            "built_at": datetime.now(timezone.utc).isoformat(),
        },
        "input": provenance,
    }


def verify_artifact(path: str) -> PilotSanctionsTree:
    with open(path) as handle:
        return PilotSanctionsTree.from_artifact(json.load(handle))


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the pilot raw-address sanctions tree")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Legacy sanctions tree artifact to derive from")
    parser.add_argument("--fetch", action="store_true", help="Fetch feeds directly with the legacy fetchers")
    parser.add_argument("--offline", action="store_true", help="With --fetch: hardcoded addresses only")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Pilot artifact path to write or verify")
    parser.add_argument("--verify", action="store_true", help="Rebuild the output artifact and check it")
    args = parser.parse_args(argv)
    if args.offline and not args.fetch:
        parser.error("--offline requires --fetch")
    if args.verify:
        try:
            tree = verify_artifact(args.output)
        except (OSError, ValueError) as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1
        print(f"OK: {len(tree.addresses)} addresses, sorted, root {tree.root}")
        return 0
    if args.fetch:
        raw, provenance = await fetch_addresses(args.offline)
    else:
        raw, provenance = load_legacy_artifact(args.input)
    artifact = build_artifact(raw, provenance)
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w") as handle:
        json.dump(artifact, handle, indent=2)
        handle.write("\n")
    print(f"Wrote {args.output}")
    print(f"  Root:      {artifact['root']}")
    print(f"  Addresses: {artifact['address_count']} (depth {artifact['depth']})")
    print("Next: publish a signed sanctions-root approval with scripts/publish_pilot_sanctions_head.py")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
