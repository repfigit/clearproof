# SPDX-License-Identifier: Apache-2.0
"""Complete source paging, exact scope, missing pages, ordering and bounds."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.protocol.canonical import canonical_bytes, record_digest
from src.services.issuance_source import (
    MAX_ISSUANCE_ENTRIES,
    PAGE_DOMAIN,
    IssuanceEntry,
    IssuanceSourceScope,
    PagedIssuanceSource,
    issuance_source_domain,
    load_issuance_entries,
    pack_issuance_source,
)

SCOPE = dict(
    tenant_id="tenant-a",
    issuer_did="did:web:issuer.example",
    chain_id=31337,
    registry_address="0x" + "1" * 40,
    evaluated_at=120,
    depth=32,
)


def entries(count):
    return tuple((f"{i:064x}", str(i + 1)) for i in range(1, count + 1))


@pytest.mark.parametrize("count", [0, 1, 256, 257, 384, MAX_ISSUANCE_ENTRIES])
async def test_complete_source_roundtrip_uses_bounded_canonical_pages(count):
    source, pages = pack_issuance_source(SCOPE, entries(count))
    stored = {record_digest(PAGE_DOMAIN, page): page for page in pages}
    tx = SimpleNamespace(get=AsyncMock(side_effect=lambda kind, digest: stored.get(digest)))
    assert await load_issuance_entries(tx, source) == list(entries(count))
    assert len(canonical_bytes(source)) <= 65536
    assert all(len(canonical_bytes(page)) <= 65536 for page in pages)
    if count <= 256:
        assert pages == () and source == {
            **SCOPE,
            "entries": [dict(credential_id=k, commitment=v) for k, v in entries(count)],
        }
        assert issuance_source_domain(source) == "clearproof/issuance-source/v1"
        tx.get.assert_not_called()
    else:
        assert issuance_source_domain(source) == "clearproof/issuance-source/v2"
        assert source["entry_count"] == count and "entries" not in source
        assert tx.get.await_count == len(pages)


@pytest.mark.parametrize(
    "value", ["0", "01", "-1", "99999999999999999999999999999999999999999999999999999999999999999999999999999"]
)
def test_noncanonical_or_zero_leaf_rejected(value):
    with pytest.raises(ValueError):
        IssuanceEntry(credential_id="ab" * 32, commitment=value)


@pytest.mark.parametrize(
    "change",
    [
        dict(registry_address="0x" + "0" * 40),
        dict(issuer_did="did:web:ISSUER.example"),
        dict(issuer_did="issuer.example"),
    ],
)
def test_source_scope_requires_canonical_issuer_and_nonzero_registry(change):
    with pytest.raises(ValueError):
        IssuanceSourceScope(**{**SCOPE, **change})


@pytest.mark.parametrize("count,depth", [(MAX_ISSUANCE_ENTRIES + 1, 32), (3, 1)])
def test_pack_capacity_fails_before_any_source_is_returned(count, depth):
    with pytest.raises(ValueError, match="capacity"):
        pack_issuance_source({**SCOPE, "depth": depth}, entries(count))


@pytest.mark.parametrize("damage", ["count", "duplicate", "depth", "schema"])
def test_manifest_rejects_incomplete_duplicates_small_tree_and_unknown_version(damage):
    source, _ = pack_issuance_source(SCOPE, entries(257))
    if damage == "count":
        source["entry_count"] = 385
    elif damage == "duplicate":
        source["page_digests"][1] = source["page_digests"][0]
    elif damage == "depth":
        source["depth"] = 8
    else:
        source["schema_version"] = "clearproof-issuance-source-v99"
    with pytest.raises(ValueError):
        PagedIssuanceSource.model_validate_json(canonical_bytes(source))


@pytest.mark.parametrize("damage", ["missing", "digest", "position", "scope", "length", "order"])
async def test_paged_reader_rejects_missing_tampered_rescoped_and_reordered_data(damage):
    source, pages = pack_issuance_source(SCOPE, entries(257))
    pages = deepcopy(pages)
    if damage == "position":
        pages[1]["page_index"] = 0
    elif damage == "scope":
        pages[1]["tenant_id"] = "tenant-b"
    elif damage == "length":
        pages[1]["entries"].pop()
    elif damage == "order":
        pages[1]["entries"].reverse()
    if damage in ("position", "scope", "length", "order"):
        source["page_digests"][1] = record_digest(PAGE_DOMAIN, pages[1])
    stored = {digest: page for digest, page in zip(source["page_digests"], pages, strict=True)}
    if damage == "missing":
        stored.pop(source["page_digests"][1])
    elif damage == "digest":
        stored[source["page_digests"][1]]["entries"][0]["commitment"] = "12345"
    tx = SimpleNamespace(get=AsyncMock(side_effect=lambda kind, digest: stored.get(digest)))
    with pytest.raises(ValueError):
        await load_issuance_entries(tx, source)


@pytest.mark.parametrize("value", [None, entries(1), [dict(credential_id=k, commitment=v) for k, v in entries(257)]])
async def test_legacy_reader_enforces_the_original_source_bound(value):
    with pytest.raises(ValueError, match="format bound"):
        await load_issuance_entries(None, {**SCOPE, "entries": value})


@pytest.mark.parametrize("count,domain", [(1, "clearproof/issuance-source/v1"), (257, "clearproof/issuance-source/v2")])
def test_candidate_digest_binds_the_selected_complete_source_format(count, domain):
    from src.services.issuance_tree import IssuanceTree

    source, pages = pack_issuance_source(SCOPE, entries(count))
    candidate = IssuanceTree(None, source, pages)
    assert candidate.source_digest == record_digest(domain, source)
