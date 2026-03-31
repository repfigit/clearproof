#!/usr/bin/env python3
"""
Fetch OFAC SDN and EU sanctions lists, extract crypto addresses,
and build a sorted Poseidon Merkle tree.

Outputs: artifacts/sanctions_tree.json

Usage:
    python scripts/build_sanctions_tree.py
    python scripts/build_sanctions_tree.py --offline   # skip HTTP fetches

NOTE: All subprocess calls use asyncio.create_subprocess_exec (argument-list
form, no shell) to prevent command injection.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Project root / Poseidon helper
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
POSEIDON_SCRIPT = os.path.join(PROJECT_ROOT, "scripts", "poseidon_hash.js")
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, "artifacts")
OUTPUT_PATH = os.path.join(ARTIFACTS_DIR, "sanctions_tree.json")

# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------

OFAC_SDN_XML_URL = "https://www.treasury.gov/ofac/downloads/sdn.xml"
OFAC_CONS_CSV_URL = "https://www.treasury.gov/ofac/downloads/consolidated/cons_advanced.csv"
EU_SANCTIONS_URL = (
    "https://webgate.ec.europa.eu/fsd/fsf/public/files/xmlFullSanctionsList_1_1/content"
)

HTTP_TIMEOUT = 60  # seconds

# ---------------------------------------------------------------------------
# Known OFAC-sanctioned crypto addresses (hardcoded fallback)
# ---------------------------------------------------------------------------

KNOWN_OFAC_ADDRESSES: list[str] = [
    "0x8589427373D6D84E98730D7795D8f6f8731FDA16",  # Tornado Cash
    "0x722122dF12D4e14e13Ac3b6895a86e84145b6967",  # Tornado Cash
    "0xDD4c48C0B24039969fC16D1cdF626eaB821d3384",  # Tornado Cash
    "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b",  # Tornado Cash
    "0xd96f2B1c14Db8458374d9Aca76E26c3D18364307",  # Tornado Cash
    "0x4736dCf1b7A3d580672CcE6E7c65cd5cc9cFBfA9",  # Tornado Cash
    "0xD4B88Df4D29F5CedD6857912842cff3b20C8Cfa3",  # Tornado Cash
    "0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF",  # Tornado Cash
    "0xA160cdAB225685dA1d56aa342Ad8841c3b53f291",  # Tornado Cash
    "0xFD8610d20aA15b7B2E3Be39B396a1bC3516c7144",  # Tornado Cash
    "0xF60dD140cFf0706bAE9Cd734Ac3683696B445d00",  # Tornado Cash
    "0x179f48C78f57A3A78f0608cC9197B8972921d1D2",  # Blender.io
    "0xb541fc07bC7619fD4062A54d96268525cBC6FfEF",  # Blender.io
    "0x7F367cC41522cE07553e823bf3be79A889debe1B",  # Lazarus Group
    "0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b",  # Lazarus Group
    "0x7F19720A857F834696350e8484600F000000000",  # Garantex
]

# Patterns that signal a crypto wallet address in XML/CSV text
_ETH_ADDRESS_PREFIX = "0x"

# Digital-currency program names OFAC uses
_CRYPTO_PROGRAM_KEYWORDS = frozenset({
    "digital currency address",
    "digital currency",
    "virtual currency",
    "xbt",
    "eth",
    "usdt",
    "cryptocurrency",
})


# ---------------------------------------------------------------------------
# Poseidon hash via subprocess (safe argument-list form)
# ---------------------------------------------------------------------------

async def poseidon_hash(inputs: list[int | str]) -> str:
    """Call the Node.js Poseidon helper and return the hash as a decimal string."""
    proc = await asyncio.create_subprocess_exec(
        "node", POSEIDON_SCRIPT,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    payload = json.dumps([str(v) for v in inputs]).encode()
    stdout, stderr = await asyncio.wait_for(proc.communicate(input=payload), timeout=30)
    if proc.returncode != 0:
        raise RuntimeError(f"Poseidon hash failed: {stderr.decode().strip()}")
    return stdout.decode().strip()


def address_to_int(address: str) -> int:
    """Convert a hex wallet address to an integer."""
    clean = address.lower().removeprefix("0x")
    return int(clean, 16)


# ---------------------------------------------------------------------------
# Fetchers
# ---------------------------------------------------------------------------

def _looks_like_eth_address(text: str) -> bool:
    """Return True if *text* looks like a 0x-prefixed Ethereum address."""
    text = text.strip()
    if not text.lower().startswith(_ETH_ADDRESS_PREFIX):
        return False
    hex_part = text[2:]
    if len(hex_part) < 38 or len(hex_part) > 42:
        # Allow slightly short addresses (some lists truncate)
        return False
    try:
        int(hex_part, 16)
        return True
    except ValueError:
        return False


def _extract_eth_addresses_from_text(text: str) -> list[str]:
    """Scan arbitrary text for Ethereum-style hex addresses."""
    results: list[str] = []
    for token in text.replace(",", " ").replace(";", " ").split():
        token = token.strip("\"'()[]{}<>")
        if _looks_like_eth_address(token):
            results.append(token)
    return results


async def fetch_ofac_sdn_xml(client: httpx.AsyncClient) -> tuple[list[str], dict[str, Any]]:
    """
    Fetch and parse the OFAC SDN XML list.

    Returns (addresses, metadata).
    """
    addresses: list[str] = []
    meta: dict[str, Any] = {"source": OFAC_SDN_XML_URL, "fetched": False, "error": None}

    try:
        print(f"  Fetching OFAC SDN XML from {OFAC_SDN_XML_URL} ...")
        resp = await client.get(OFAC_SDN_XML_URL, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        meta["fetched"] = True
        meta["status_code"] = resp.status_code
        meta["content_length"] = len(resp.content)

        root = ET.fromstring(resp.content)
        # OFAC SDN XML namespace
        ns = ""
        # Try to detect namespace from root tag
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        # Walk all elements looking for digital-currency address features
        for elem in root.iter():
            tag_local = elem.tag.replace(ns, "") if ns else elem.tag

            # Look for <feature> elements with featureType containing crypto keywords
            if tag_local.lower() in ("feature", "id"):
                text_content = ET.tostring(elem, encoding="unicode", method="text")
                if text_content:
                    text_lower = text_content.lower()
                    is_crypto = any(kw in text_lower for kw in _CRYPTO_PROGRAM_KEYWORDS)
                    if is_crypto:
                        found = _extract_eth_addresses_from_text(text_content)
                        addresses.extend(found)

            # Also check raw text of any element for ETH addresses near crypto keywords
            if elem.text and _ETH_ADDRESS_PREFIX in (elem.text or ""):
                found = _extract_eth_addresses_from_text(elem.text)
                addresses.extend(found)

        # Also do a broad scan of the entire XML text for any ETH addresses
        raw_text = resp.text
        for token in raw_text.split():
            token = token.strip("\"'<>")
            if _looks_like_eth_address(token):
                addresses.append(token)

        meta["addresses_found"] = len(set(addresses))
        print(f"    Found {meta['addresses_found']} addresses in OFAC SDN XML")

    except Exception as exc:
        meta["error"] = str(exc)
        print(f"    OFAC SDN XML fetch failed: {exc}")

    return addresses, meta


async def fetch_ofac_consolidated_csv(client: httpx.AsyncClient) -> tuple[list[str], dict[str, Any]]:
    """
    Fetch and parse the OFAC consolidated (non-SDN) CSV for crypto addresses.

    Returns (addresses, metadata).
    """
    addresses: list[str] = []
    meta: dict[str, Any] = {"source": OFAC_CONS_CSV_URL, "fetched": False, "error": None}

    try:
        print(f"  Fetching OFAC consolidated CSV from {OFAC_CONS_CSV_URL} ...")
        resp = await client.get(OFAC_CONS_CSV_URL, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        meta["fetched"] = True
        meta["status_code"] = resp.status_code
        meta["content_length"] = len(resp.content)

        # Scan each line for ETH addresses
        for line in resp.text.splitlines():
            line_lower = line.lower()
            if "digital currency" in line_lower or "0x" in line_lower:
                found = _extract_eth_addresses_from_text(line)
                addresses.extend(found)

        meta["addresses_found"] = len(set(addresses))
        print(f"    Found {meta['addresses_found']} addresses in OFAC consolidated CSV")

    except Exception as exc:
        meta["error"] = str(exc)
        print(f"    OFAC consolidated CSV fetch failed: {exc}")

    return addresses, meta


async def fetch_eu_sanctions_xml(client: httpx.AsyncClient) -> tuple[list[str], dict[str, Any]]:
    """
    Fetch and parse the EU consolidated sanctions list.

    Returns (addresses, metadata).
    """
    addresses: list[str] = []
    meta: dict[str, Any] = {"source": EU_SANCTIONS_URL, "fetched": False, "error": None}

    try:
        print(f"  Fetching EU sanctions XML from {EU_SANCTIONS_URL} ...")
        resp = await client.get(EU_SANCTIONS_URL, timeout=HTTP_TIMEOUT, follow_redirects=True)
        resp.raise_for_status()
        meta["fetched"] = True
        meta["status_code"] = resp.status_code
        meta["content_length"] = len(resp.content)

        # Broad scan for ETH addresses in the XML text
        for token in resp.text.split():
            token = token.strip("\"'<>")
            if _looks_like_eth_address(token):
                addresses.append(token)

        meta["addresses_found"] = len(set(addresses))
        print(f"    Found {meta['addresses_found']} addresses in EU sanctions XML")

    except Exception as exc:
        meta["error"] = str(exc)
        print(f"    EU sanctions XML fetch failed: {exc}")

    return addresses, meta


# ---------------------------------------------------------------------------
# Merkle tree builder
# ---------------------------------------------------------------------------

async def build_merkle_tree(addresses: list[str]) -> dict[str, Any]:
    """
    Build a sorted Poseidon Merkle tree from a deduplicated list of hex addresses.

    Returns the tree metadata dict ready for JSON serialization.
    """
    # Deduplicate (case-insensitive) and normalize
    seen: set[str] = set()
    unique: list[str] = []
    for addr in addresses:
        key = addr.lower()
        if key not in seen:
            seen.add(key)
            unique.append(addr)

    print(f"\nBuilding Merkle tree from {len(unique)} unique addresses ...")

    # Hash each address through Poseidon
    hashed: list[tuple[int, str]] = []  # (hash_int, original_address)
    for i, addr in enumerate(unique):
        h = await poseidon_hash([address_to_int(addr)])
        hashed.append((int(h), addr))
        if (i + 1) % 10 == 0 or (i + 1) == len(unique):
            print(f"  Hashed {i + 1}/{len(unique)} addresses")

    # Sort by hash value
    hashed.sort(key=lambda x: x[0])
    sorted_hashes = [h for h, _ in hashed]
    sorted_addresses = [a for _, a in hashed]

    if not sorted_hashes:
        return {
            "root": "0",
            "sorted_leaves": [],
            "sorted_addresses": [],
            "depth": 0,
            "leaf_count": 0,
            "padded_size": 0,
        }

    # Determine depth
    n = len(sorted_hashes)
    depth = max(1, math.ceil(math.log2(n))) if n > 1 else 1
    padded_size = 2 ** depth

    # Build leaf layer
    leaf_strs = [str(h) for h in sorted_hashes] + ["0"] * (padded_size - n)

    # Build tree bottom-up
    current = leaf_strs
    for level in range(depth):
        next_level: list[str] = []
        for i in range(0, len(current), 2):
            h = await poseidon_hash([int(current[i]), int(current[i + 1])])
            next_level.append(h)
        current = next_level
        print(f"  Built tree level {level + 1}/{depth}")

    root = current[0]
    print(f"  Root hash: {root}")

    return {
        "root": root,
        "sorted_leaves": [str(h) for h in sorted_hashes],
        "sorted_addresses": sorted_addresses,
        "depth": depth,
        "leaf_count": n,
        "padded_size": padded_size,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main(offline: bool = False) -> None:
    print("=" * 60)
    print("OFAC / EU Sanctions List Fetcher & Merkle Tree Builder")
    print("=" * 60)

    timestamp = datetime.now(timezone.utc).isoformat()
    all_addresses: list[str] = []
    source_meta: dict[str, Any] = {}
    counts: dict[str, int] = {}

    # Always include hardcoded known addresses
    all_addresses.extend(KNOWN_OFAC_ADDRESSES)
    counts["hardcoded_ofac"] = len(KNOWN_OFAC_ADDRESSES)
    print(f"\n[1/4] Loaded {len(KNOWN_OFAC_ADDRESSES)} hardcoded OFAC addresses")

    if not offline:
        async with httpx.AsyncClient(
            headers={"User-Agent": "clearproof-sanctions-fetcher/1.0"},
            follow_redirects=True,
        ) as client:
            # Fetch OFAC SDN XML
            print("\n[2/4] Fetching OFAC SDN XML ...")
            sdn_addrs, sdn_meta = await fetch_ofac_sdn_xml(client)
            all_addresses.extend(sdn_addrs)
            source_meta["ofac_sdn_xml"] = sdn_meta
            counts["ofac_sdn_xml"] = len(set(sdn_addrs))

            # Fetch OFAC consolidated CSV
            print("\n[3/4] Fetching OFAC consolidated CSV ...")
            csv_addrs, csv_meta = await fetch_ofac_consolidated_csv(client)
            all_addresses.extend(csv_addrs)
            source_meta["ofac_consolidated_csv"] = csv_meta
            counts["ofac_consolidated_csv"] = len(set(csv_addrs))

            # Fetch EU sanctions
            print("\n[4/4] Fetching EU sanctions XML ...")
            eu_addrs, eu_meta = await fetch_eu_sanctions_xml(client)
            all_addresses.extend(eu_addrs)
            source_meta["eu_sanctions_xml"] = eu_meta
            counts["eu_sanctions_xml"] = len(set(eu_addrs))
    else:
        print("\n[2-4/4] Skipped HTTP fetches (--offline mode)")
        source_meta["mode"] = "offline"

    # Deduplicate
    seen: set[str] = set()
    deduped: list[str] = []
    for addr in all_addresses:
        key = addr.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(addr)

    print(f"\nTotal unique addresses: {len(deduped)}")

    # Build the Merkle tree
    tree_data = await build_merkle_tree(deduped)

    # Assemble output
    output = {
        "root": tree_data["root"],
        "sorted_leaves": tree_data["sorted_leaves"],
        "sorted_addresses": tree_data["sorted_addresses"],
        "depth": tree_data["depth"],
        "leaf_count": tree_data["leaf_count"],
        "padded_size": tree_data["padded_size"],
        "source_metadata": {
            "fetch_timestamp": timestamp,
            "sources": source_meta,
            "address_counts_per_source": counts,
            "total_unique_addresses": len(deduped),
        },
    }

    # Write output
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nWrote sanctions tree to {OUTPUT_PATH}")
    print(f"  Root:  {tree_data['root']}")
    print(f"  Depth: {tree_data['depth']}")
    print(f"  Leaves: {tree_data['leaf_count']}")
    print("Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build sanctions Merkle tree")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip HTTP fetches; use only hardcoded addresses",
    )
    args = parser.parse_args()
    asyncio.run(main(offline=args.offline))
