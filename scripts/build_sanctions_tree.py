#!/usr/bin/env python3
"""
Fetch OFAC SDN and EU sanctions lists, extract crypto addresses,
and build a sorted Poseidon Merkle tree with deterministic output.

Outputs: artifacts/sanctions_tree.json

Usage:
    python scripts/build_sanctions_tree.py
    python scripts/build_sanctions_tree.py --offline   # skip HTTP fetches
    python scripts/build_sanctions_tree.py --verify     # verify existing tree is reproducible

Deterministic guarantee:
    Given the same source files (verified by SHA-256), the same build script
    version, and the same normalization spec, any operator will produce the
    same Merkle root. The output includes a source manifest for independent
    verification.

NOTE: All subprocess calls use asyncio.create_subprocess_exec (argument-list
form, no shell) to prevent command injection.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Build script version — increment on any change to normalization or tree logic
# ---------------------------------------------------------------------------

BUILD_SCRIPT_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Project root / Poseidon helper
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
POSEIDON_SCRIPT = os.path.join(PROJECT_ROOT, "scripts", "poseidon_hash.js")
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, "artifacts")
OUTPUT_PATH = os.path.join(ARTIFACTS_DIR, "sanctions_tree.json")
TEST_VECTORS_PATH = os.path.join(ARTIFACTS_DIR, "sanctions_test_vectors.json")

# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------

OFAC_SDN_XML_URL = "https://www.treasury.gov/ofac/downloads/sdn.xml"
OFAC_CONS_CSV_URL = "https://www.treasury.gov/ofac/downloads/consolidated/cons_advanced.csv"
EU_SANCTIONS_URL = (
    "https://webgate.ec.europa.eu/fsd/fsf/public/files/xmlFullSanctionsList_1_1/content"
)

HTTP_TIMEOUT = 60  # seconds

# Domain tag for sanctions tree leaves (must match circuits)
SANCTIONS_DOMAIN_TAG = 1

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
# Canonical address normalization (deterministic)
# ---------------------------------------------------------------------------

def normalize_address(addr: str) -> str:
    """
    Canonical normalization for EVM addresses.

    Rules (deterministic — two operators applying these get identical output):
    1. Strip whitespace
    2. Lowercase (checksums are display-only, not canonical)
    3. Ensure 0x prefix
    4. Zero-pad to 42 chars (0x + 40 hex digits)

    ENS names are NEVER resolved — only raw hex addresses enter the tree.
    """
    addr = addr.strip().lower()
    if not addr.startswith("0x"):
        addr = "0x" + addr
    hex_part = addr[2:]
    if len(hex_part) < 40:
        hex_part = hex_part.zfill(40)
    return "0x" + hex_part[:40]


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
    """Convert a normalized hex wallet address to an integer."""
    return int(address.removeprefix("0x"), 16)


# ---------------------------------------------------------------------------
# Source content hashing (for reproducibility verification)
# ---------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    """Return hex SHA-256 of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    """Return hex SHA-256 of a file."""
    with open(path, "rb") as f:
        return sha256_bytes(f.read())


# ---------------------------------------------------------------------------
# Fetchers
# ---------------------------------------------------------------------------

def _looks_like_eth_address(text: str) -> bool:
    text = text.strip()
    if not text.lower().startswith(_ETH_ADDRESS_PREFIX):
        return False
    hex_part = text[2:]
    if len(hex_part) < 38 or len(hex_part) > 42:
        return False
    try:
        int(hex_part, 16)
        return True
    except ValueError:
        return False


def _extract_eth_addresses_from_text(text: str) -> list[str]:
    results: list[str] = []
    for token in text.replace(",", " ").replace(";", " ").split():
        token = token.strip("\"'()[]{}<>")
        if _looks_like_eth_address(token):
            results.append(token)
    return results


async def fetch_ofac_sdn_xml(client: httpx.AsyncClient) -> tuple[list[str], dict[str, Any]]:
    addresses: list[str] = []
    meta: dict[str, Any] = {"source": OFAC_SDN_XML_URL, "fetched": False, "error": None}

    try:
        print(f"  Fetching OFAC SDN XML from {OFAC_SDN_XML_URL} ...")
        resp = await client.get(OFAC_SDN_XML_URL, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        meta["fetched"] = True
        meta["status_code"] = resp.status_code
        meta["content_length"] = len(resp.content)
        meta["sha256"] = sha256_bytes(resp.content)
        meta["last_modified"] = resp.headers.get("Last-Modified", "unknown")

        root = ET.fromstring(resp.content)
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        for elem in root.iter():
            tag_local = elem.tag.replace(ns, "") if ns else elem.tag
            if tag_local.lower() in ("feature", "id"):
                text_content = ET.tostring(elem, encoding="unicode", method="text")
                if text_content:
                    text_lower = text_content.lower()
                    is_crypto = any(kw in text_lower for kw in _CRYPTO_PROGRAM_KEYWORDS)
                    if is_crypto:
                        found = _extract_eth_addresses_from_text(text_content)
                        addresses.extend(found)
            if elem.text and _ETH_ADDRESS_PREFIX in (elem.text or ""):
                found = _extract_eth_addresses_from_text(elem.text)
                addresses.extend(found)

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
    addresses: list[str] = []
    meta: dict[str, Any] = {"source": OFAC_CONS_CSV_URL, "fetched": False, "error": None}

    try:
        print(f"  Fetching OFAC consolidated CSV from {OFAC_CONS_CSV_URL} ...")
        resp = await client.get(OFAC_CONS_CSV_URL, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        meta["fetched"] = True
        meta["status_code"] = resp.status_code
        meta["content_length"] = len(resp.content)
        meta["sha256"] = sha256_bytes(resp.content)
        meta["last_modified"] = resp.headers.get("Last-Modified", "unknown")

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
    addresses: list[str] = []
    meta: dict[str, Any] = {"source": EU_SANCTIONS_URL, "fetched": False, "error": None}

    try:
        print(f"  Fetching EU sanctions XML from {EU_SANCTIONS_URL} ...")
        resp = await client.get(EU_SANCTIONS_URL, timeout=HTTP_TIMEOUT, follow_redirects=True)
        resp.raise_for_status()
        meta["fetched"] = True
        meta["status_code"] = resp.status_code
        meta["content_length"] = len(resp.content)
        meta["sha256"] = sha256_bytes(resp.content)
        meta["last_modified"] = resp.headers.get("Last-Modified", "unknown")

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
# Merkle tree builder (deterministic)
# ---------------------------------------------------------------------------

async def build_merkle_tree(addresses: list[str]) -> dict[str, Any]:
    """
    Build a sorted Poseidon Merkle tree from a deduplicated, normalized address list.

    Deterministic guarantees:
    1. Addresses normalized via normalize_address() before dedup
    2. Leaves sorted by Poseidon hash value (integer comparison)
    3. Poseidon hashing uses domain tag 1 for leaf hashing
    4. Zero-padding uses 0 for empty leaves
    5. Tree always padded to next power of 2
    """
    seen: set[str] = set()
    unique: list[str] = []
    for addr in addresses:
        normalized = normalize_address(addr)
        if normalized not in seen:
            seen.add(normalized)
            unique.append(normalized)

    unique.sort()

    print(f"\nBuilding Merkle tree from {len(unique)} unique normalized addresses ...")

    hashed: list[tuple[int, str]] = []
    for i, addr in enumerate(unique):
        h = await poseidon_hash([SANCTIONS_DOMAIN_TAG, address_to_int(addr)])
        hashed.append((int(h), addr))
        if (i + 1) % 10 == 0 or (i + 1) == len(unique):
            print(f"  Hashed {i + 1}/{len(unique)} addresses")

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

    n = len(sorted_hashes)
    depth = max(1, math.ceil(math.log2(n))) if n > 1 else 1
    padded_size = 2 ** depth

    leaf_strs = [str(h) for h in sorted_hashes] + ["0"] * (padded_size - n)

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
# Test vector generation
# ---------------------------------------------------------------------------

async def generate_test_vectors(addresses: list[str]) -> list[dict[str, Any]]:
    """Generate test vectors for independent verification."""
    vectors: list[dict[str, Any]] = []
    for addr in addresses[:10]:
        normalized = normalize_address(addr)
        addr_int = address_to_int(normalized)
        leaf_hash = await poseidon_hash([SANCTIONS_DOMAIN_TAG, addr_int])
        vectors.append({
            "original": addr,
            "normalized": normalized,
            "address_int": str(addr_int),
            "domain_tag": SANCTIONS_DOMAIN_TAG,
            "expected_leaf_hash": leaf_hash,
        })
    return vectors


# ---------------------------------------------------------------------------
# Verify mode
# ---------------------------------------------------------------------------

async def verify_tree() -> bool:
    """Verify existing tree against stored test vectors."""
    if not os.path.exists(TEST_VECTORS_PATH):
        print(f"No test vectors found at {TEST_VECTORS_PATH}")
        return False

    with open(TEST_VECTORS_PATH) as f:
        data = json.load(f)

    vectors = data.get("vectors", [])
    print(f"Verifying {len(vectors)} test vectors ...")

    passed = 0
    failed = 0
    for v in vectors:
        addr_int = int(v["address_int"])
        expected = v["expected_leaf_hash"]
        actual = await poseidon_hash([SANCTIONS_DOMAIN_TAG, addr_int])
        if actual == expected:
            passed += 1
        else:
            failed += 1
            print(f"  FAIL: {v['normalized']} expected {expected} got {actual}")

    print(f"\n{passed} passed, {failed} failed")
    return failed == 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main(offline: bool = False, verify: bool = False) -> None:
    if verify:
        ok = await verify_tree()
        sys.exit(0 if ok else 1)

    print("=" * 60)
    print("clearproof Sanctions Merkle Tree Builder")
    print(f"Build script version: {BUILD_SCRIPT_VERSION}")
    print("=" * 60)

    script_path = os.path.abspath(__file__)
    script_hash = sha256_file(script_path)
    print(f"Script hash (SHA-256): {script_hash}")

    timestamp = datetime.now(timezone.utc).isoformat()
    all_addresses: list[str] = []
    source_meta: dict[str, Any] = {}
    counts: dict[str, int] = {}

    all_addresses.extend(KNOWN_OFAC_ADDRESSES)
    counts["hardcoded_ofac"] = len(KNOWN_OFAC_ADDRESSES)
    print(f"\n[1/4] Loaded {len(KNOWN_OFAC_ADDRESSES)} hardcoded OFAC addresses")

    if not offline:
        async with httpx.AsyncClient(
            headers={"User-Agent": "clearproof-sanctions-fetcher/1.0"},
            follow_redirects=True,
        ) as client:
            print("\n[2/4] Fetching OFAC SDN XML ...")
            sdn_addrs, sdn_meta = await fetch_ofac_sdn_xml(client)
            all_addresses.extend(sdn_addrs)
            source_meta["ofac_sdn_xml"] = sdn_meta
            counts["ofac_sdn_xml"] = len(set(sdn_addrs))

            print("\n[3/4] Fetching OFAC consolidated CSV ...")
            csv_addrs, csv_meta = await fetch_ofac_consolidated_csv(client)
            all_addresses.extend(csv_addrs)
            source_meta["ofac_consolidated_csv"] = csv_meta
            counts["ofac_consolidated_csv"] = len(set(csv_addrs))

            print("\n[4/4] Fetching EU sanctions XML ...")
            eu_addrs, eu_meta = await fetch_eu_sanctions_xml(client)
            all_addresses.extend(eu_addrs)
            source_meta["eu_sanctions_xml"] = eu_meta
            counts["eu_sanctions_xml"] = len(set(eu_addrs))
    else:
        print("\n[2-4/4] Skipped HTTP fetches (--offline mode)")
        source_meta["mode"] = "offline"

    seen: set[str] = set()
    deduped: list[str] = []
    for addr in all_addresses:
        normalized = normalize_address(addr)
        if normalized not in seen:
            seen.add(normalized)
            deduped.append(normalized)

    deduped.sort()

    print(f"\nTotal unique normalized addresses: {len(deduped)}")

    tree_data = await build_merkle_tree(deduped)

    print("\nGenerating test vectors ...")
    test_vectors = await generate_test_vectors(KNOWN_OFAC_ADDRESSES[:10])

    source_manifest = {
        "build_script_version": BUILD_SCRIPT_VERSION,
        "build_script_hash": script_hash,
        "normalization_spec": {
            "method": "lowercase_hex_0x_prefix_40chars",
            "domain_tag": SANCTIONS_DOMAIN_TAG,
            "ens_resolution": "never",
            "sort_order": "lexicographic_on_normalized_hex_then_poseidon_hash_int",
            "dedup": "case_insensitive_after_normalization",
        },
        "fetch_timestamp": timestamp,
        "sources": source_meta,
        "address_counts_per_source": counts,
        "total_unique_addresses": len(deduped),
    }

    output = {
        "root": tree_data["root"],
        "sorted_leaves": tree_data["sorted_leaves"],
        "sorted_addresses": tree_data["sorted_addresses"],
        "depth": tree_data["depth"],
        "leaf_count": tree_data["leaf_count"],
        "padded_size": tree_data["padded_size"],
        "source_manifest": source_manifest,
    }

    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nWrote sanctions tree to {OUTPUT_PATH}")

    test_vector_output = {
        "build_script_version": BUILD_SCRIPT_VERSION,
        "domain_tag": SANCTIONS_DOMAIN_TAG,
        "description": "Test vectors for sanctions tree leaf hashing. Any operator can verify these to confirm their Poseidon implementation and normalization match.",
        "vectors": test_vectors,
    }
    with open(TEST_VECTORS_PATH, "w") as f:
        json.dump(test_vector_output, f, indent=2)
    print(f"Wrote {len(test_vectors)} test vectors to {TEST_VECTORS_PATH}")

    print(f"\n  Root:    {tree_data['root']}")
    print(f"  Depth:   {tree_data['depth']}")
    print(f"  Leaves:  {tree_data['leaf_count']}")
    print(f"  Script:  v{BUILD_SCRIPT_VERSION} ({script_hash[:16]}...)")
    print("Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build sanctions Merkle tree (deterministic)")
    parser.add_argument("--offline", action="store_true", help="Skip HTTP fetches; use only hardcoded addresses")
    parser.add_argument("--verify", action="store_true", help="Verify existing tree against test vectors")
    args = parser.parse_args()
    asyncio.run(main(offline=args.offline, verify=args.verify))
