# SPDX-License-Identifier: Apache-2.0
"""Complete source paging, exact scope, missing pages, ordering and bounds."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from src.protocol.canonical import canonical_bytes, record_digest
from src.services.issuance_source import (
    ISSUANCE_SOURCE_PAGE_SIZE,
    MAX_MANIFEST_PAGES,
    PAGE_DOMAIN,
    PAGE_GROUP_DOMAIN,
    GroupedIssuanceSource,
    IssuanceEntry,
    IssuanceSourcePageGroup,
    IssuanceSourceScope,
    PagedIssuanceSource,
    issuance_page_domain,
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


@pytest.mark.parametrize("count", [0, 1, 256, 257, 384, 1024, 1280])
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


@pytest.mark.parametrize("count,depth", [(17, 4), (3, 1)])
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


async def test_grouped_v3_source_roundtrip_and_tamper_rejection():
    from src.protocol.root_snapshot import RootTrustError

    count = MAX_MANIFEST_PAGES * ISSUANCE_SOURCE_PAGE_SIZE + 1
    source, pages_and_groups = pack_issuance_source(SCOPE, entries(count))
    assert source["schema_version"] == "clearproof-issuance-source-v3"
    assert issuance_source_domain(source) == "clearproof/issuance-source/v3"
    assert len(canonical_bytes(source)) <= 65536
    stored = {record_digest(issuance_page_domain(item), item): item for item in pages_and_groups}
    assert any(issuance_page_domain(item) == PAGE_GROUP_DOMAIN for item in pages_and_groups)
    assert any(issuance_page_domain(item) == PAGE_DOMAIN for item in pages_and_groups)
    tx = SimpleNamespace(get=AsyncMock(side_effect=lambda kind, digest: stored.get(digest)))
    loaded = await load_issuance_entries(tx, source)
    assert len(loaded) == count
    assert loaded[0] == entries(1)[0]
    assert loaded[-1] == (f"{count:064x}", str(count + 1))

    # Reject duplicate pages inside a group.
    with pytest.raises(ValueError, match="Duplicate source page in group"):
        IssuanceSourcePageGroup(**SCOPE, group_index=0, page_digests=("aa" * 32, "aa" * 32))

    # Reject wrong group count, duplicate group digests, or depth overflow in manifest.
    bad_count = deepcopy(source)
    bad_count["entry_count"] = count + MAX_MANIFEST_PAGES * ISSUANCE_SOURCE_PAGE_SIZE
    with pytest.raises(ValueError, match="group count differs"):
        GroupedIssuanceSource.model_validate_json(canonical_bytes(bad_count))

    bad_dup = deepcopy(source)
    bad_dup["page_group_digests"][1] = bad_dup["page_group_digests"][0]
    with pytest.raises(ValueError, match="Duplicate source page group"):
        GroupedIssuanceSource.model_validate_json(canonical_bytes(bad_dup))

    bad_depth = deepcopy(source)
    bad_depth["depth"] = 14
    with pytest.raises(ValueError, match="tree capacity exceeded"):
        GroupedIssuanceSource.model_validate_json(canonical_bytes(bad_depth))

    # Missing group fails closed.
    missing_stored = dict(stored)
    missing_stored.pop(source["page_group_digests"][1])
    tx_missing = SimpleNamespace(get=AsyncMock(side_effect=lambda kind, digest: missing_stored.get(digest)))
    with pytest.raises(RootTrustError, match="page group is missing"):
        await load_issuance_entries(tx_missing, source)

    # Wrong group_index fails closed.
    bad_group_source = deepcopy(source)
    bad_group = deepcopy(stored[source["page_group_digests"][1]])
    bad_group["group_index"] = 0
    bad_group_digest = record_digest(PAGE_GROUP_DOMAIN, bad_group)
    bad_group_source["page_group_digests"][1] = bad_group_digest
    bad_group_stored = {**stored, bad_group_digest: bad_group}
    tx_bad_group = SimpleNamespace(get=AsyncMock(side_effect=lambda kind, digest: bad_group_stored.get(digest)))
    with pytest.raises(RootTrustError, match="page group scope or position differs"):
        await load_issuance_entries(tx_bad_group, bad_group_source)

    # Duplicate page across groups fails closed.
    dup_cross_source = deepcopy(source)
    dup_group = deepcopy(stored[source["page_group_digests"][1]])
    first_group = stored[source["page_group_digests"][0]]
    dup_group["page_digests"] = [first_group["page_digests"][0]]
    dup_group_digest = record_digest(PAGE_GROUP_DOMAIN, dup_group)
    dup_cross_source["page_group_digests"][1] = dup_group_digest
    dup_stored = {**stored, dup_group_digest: dup_group}
    tx_dup = SimpleNamespace(get=AsyncMock(side_effect=lambda kind, digest: dup_stored.get(digest)))
    with pytest.raises(RootTrustError, match="Duplicate issuance source page across groups"):
        await load_issuance_entries(tx_dup, dup_cross_source)
