# SPDX-License-Identifier: Apache-2.0
"""Bounded encrypted issuance-source pages without changing circuit membership."""

from typing import Literal

from pydantic import Field, model_validator

from src.protocol.canonical import canonical_bytes, record_digest
from src.protocol.credential import scalar
from src.protocol.discovery_profile import DiscoveryError, parse_target
from src.protocol.root_snapshot import RootTrustError
from src.protocol.transfer import Address, Epoch, Hex32, OpaqueId, Record
from src.registry.pilot_tree import ISSUANCE_TREE_DEPTH

ISSUANCE_SOURCE_PAGE_SIZE = 128
MAX_MANIFEST_PAGES = 256
PAGE_DOMAIN = "clearproof/issuance-page/v1"
PAGE_GROUP_DOMAIN = "clearproof/issuance-page-group/v1"
_MAX_TREE_CAPACITY = 2**ISSUANCE_TREE_DEPTH


class IssuanceEntry(Record):
    credential_id: Hex32
    commitment: str = Field(max_length=77)

    @model_validator(mode="after")
    def canonical_leaf(self):
        scalar(self.commitment, nonzero=True)
        return self


class IssuanceSourceScope(Record):
    tenant_id: OpaqueId
    issuer_did: str = Field(max_length=512)
    chain_id: int = Field(ge=1, le=2**53 - 1)
    registry_address: Address
    evaluated_at: Epoch
    depth: int = Field(ge=1, le=32)

    @model_validator(mode="after")
    def canonical_scope(self):
        try:
            target = parse_target(self.issuer_did)
        except DiscoveryError:
            raise ValueError("Invalid issuance source scope") from None
        if target.did != self.issuer_did or self.registry_address == "0x" + "0" * 40:
            raise ValueError("Invalid issuance source scope")
        return self


class IssuanceSourcePage(IssuanceSourceScope):
    schema_version: Literal["clearproof-issuance-source-page-v1"] = "clearproof-issuance-source-page-v1"
    page_index: int = Field(ge=0, lt=_MAX_TREE_CAPACITY // ISSUANCE_SOURCE_PAGE_SIZE)
    entries: tuple[IssuanceEntry, ...] = Field(min_length=1, max_length=ISSUANCE_SOURCE_PAGE_SIZE)


class IssuanceSourcePageGroup(IssuanceSourceScope):
    schema_version: Literal["clearproof-issuance-source-page-group-v1"] = "clearproof-issuance-source-page-group-v1"
    group_index: int = Field(ge=0, lt=_MAX_TREE_CAPACITY // (ISSUANCE_SOURCE_PAGE_SIZE * MAX_MANIFEST_PAGES))
    page_digests: tuple[Hex32, ...] = Field(min_length=1, max_length=MAX_MANIFEST_PAGES)

    @model_validator(mode="after")
    def unique_pages(self):
        if len(set(self.page_digests)) != len(self.page_digests):
            raise ValueError("Duplicate source page in group")
        return self


class PagedIssuanceSource(IssuanceSourceScope):
    schema_version: Literal["clearproof-issuance-source-v2"] = "clearproof-issuance-source-v2"
    entry_count: int = Field(ge=257, le=_MAX_TREE_CAPACITY)
    page_digests: tuple[Hex32, ...] = Field(min_length=3, max_length=MAX_MANIFEST_PAGES)

    @model_validator(mode="after")
    def complete_pages(self):
        if len(self.page_digests) != (self.entry_count + ISSUANCE_SOURCE_PAGE_SIZE - 1) // ISSUANCE_SOURCE_PAGE_SIZE:
            raise ValueError("Issuance source page count differs")
        if len(set(self.page_digests)) != len(self.page_digests) or self.entry_count > 2**self.depth:
            raise ValueError("Duplicate source page or tree capacity exceeded")
        return self


class GroupedIssuanceSource(IssuanceSourceScope):
    schema_version: Literal["clearproof-issuance-source-v3"] = "clearproof-issuance-source-v3"
    entry_count: int = Field(ge=MAX_MANIFEST_PAGES * ISSUANCE_SOURCE_PAGE_SIZE + 1, le=_MAX_TREE_CAPACITY)
    page_group_digests: tuple[Hex32, ...] = Field(min_length=2, max_length=MAX_MANIFEST_PAGES)

    @model_validator(mode="after")
    def complete_groups(self):
        total_pages = (self.entry_count + ISSUANCE_SOURCE_PAGE_SIZE - 1) // ISSUANCE_SOURCE_PAGE_SIZE
        expected_groups = (total_pages + MAX_MANIFEST_PAGES - 1) // MAX_MANIFEST_PAGES
        if len(self.page_group_digests) != expected_groups:
            raise ValueError("Issuance source page group count differs")
        if len(set(self.page_group_digests)) != len(self.page_group_digests) or self.entry_count > 2**self.depth:
            raise ValueError("Duplicate source page group or tree capacity exceeded")
        return self


def issuance_source_domain(source: dict) -> str:
    if "schema_version" not in source:
        return "clearproof/issuance-source/v1"
    version = source.get("schema_version")
    if version == "clearproof-issuance-source-v3":
        GroupedIssuanceSource.model_validate_json(canonical_bytes(source))
        return "clearproof/issuance-source/v3"
    PagedIssuanceSource.model_validate_json(canonical_bytes(source))
    return "clearproof/issuance-source/v2"


def issuance_page_domain(page: dict) -> str:
    if page.get("schema_version") == "clearproof-issuance-source-page-group-v1":
        return PAGE_GROUP_DOMAIN
    return PAGE_DOMAIN


def pack_issuance_source(scope: dict, entries: tuple[tuple[str, str], ...]) -> tuple[dict, tuple[dict, ...]]:
    scope = IssuanceSourceScope.model_validate(scope).model_dump(mode="json")
    if len(entries) > 2 ** scope["depth"]:
        raise ValueError("Pilot issuance tree capacity exceeded")
    values = [dict(credential_id=key, commitment=leaf) for key, leaf in entries]
    if len(values) <= 256:
        # Preserve the original source format and digest for existing roots.
        return {**scope, "entries": values}, ()
    pages = tuple(
        IssuanceSourcePage(
            **scope,
            page_index=index,
            entries=tuple(IssuanceEntry(**v) for v in values[start : start + ISSUANCE_SOURCE_PAGE_SIZE]),
        ).model_dump(mode="json")
        for index, start in enumerate(range(0, len(values), ISSUANCE_SOURCE_PAGE_SIZE))
    )
    page_digests = tuple(record_digest(PAGE_DOMAIN, page) for page in pages)
    if len(pages) <= MAX_MANIFEST_PAGES:
        manifest = PagedIssuanceSource(
            **scope,
            entry_count=len(values),
            page_digests=page_digests,
        ).model_dump(mode="json")
        return manifest, pages
    groups = tuple(
        IssuanceSourcePageGroup(
            **scope,
            group_index=index,
            page_digests=page_digests[start : start + MAX_MANIFEST_PAGES],
        ).model_dump(mode="json")
        for index, start in enumerate(range(0, len(page_digests), MAX_MANIFEST_PAGES))
    )
    manifest = GroupedIssuanceSource(
        **scope,
        entry_count=len(values),
        page_group_digests=tuple(record_digest(PAGE_GROUP_DOMAIN, group) for group in groups),
    ).model_dump(mode="json")
    return manifest, pages + groups


async def _load_pages(
    tx, scope: IssuanceSourceScope, entry_count: int, page_digests: tuple[str, ...]
) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for index, digest in enumerate(page_digests):
        raw = await tx.get("root-source", digest)
        if raw is None or record_digest(PAGE_DOMAIN, raw) != digest:
            raise RootTrustError("Retained issuance page is missing or inconsistent")
        page = IssuanceSourcePage.model_validate_json(canonical_bytes(raw))
        if (
            page.page_index != index
            or any(getattr(page, k) != getattr(scope, k) for k in IssuanceSourceScope.model_fields)
            or len(page.entries) != min(ISSUANCE_SOURCE_PAGE_SIZE, entry_count - len(entries))
        ):
            raise RootTrustError("Retained issuance page scope or position differs")
        entries.extend((entry.credential_id, entry.commitment) for entry in page.entries)
    if any(entries[i][0] >= entries[i + 1][0] for i in range(len(entries) - 1)):
        raise RootTrustError("Retained issuance source is incomplete or unordered")
    return entries


async def load_issuance_entries(tx, source: dict) -> list[tuple[str, str]]:
    """Authenticate every linked page and ordering before reconstructing a tree."""
    if "schema_version" not in source:
        entries = source["entries"]
        if type(entries) is not list or len(entries) > 256:
            raise RootTrustError("Legacy issuance source exceeds its format bound")
        return [(entry["credential_id"], entry["commitment"]) for entry in entries]
    scope = IssuanceSourceScope.model_validate({k: source[k] for k in IssuanceSourceScope.model_fields})
    if source.get("schema_version") == "clearproof-issuance-source-v3":
        manifest = GroupedIssuanceSource.model_validate_json(canonical_bytes(source))
        total_pages = (manifest.entry_count + ISSUANCE_SOURCE_PAGE_SIZE - 1) // ISSUANCE_SOURCE_PAGE_SIZE
        all_page_digests: list[str] = []
        for group_index, group_digest in enumerate(manifest.page_group_digests):
            raw_group = await tx.get("root-source", group_digest)
            if raw_group is None or record_digest(PAGE_GROUP_DOMAIN, raw_group) != group_digest:
                raise RootTrustError("Retained issuance page group is missing or inconsistent")
            group = IssuanceSourcePageGroup.model_validate_json(canonical_bytes(raw_group))
            expected_len = min(MAX_MANIFEST_PAGES, total_pages - len(all_page_digests))
            if (
                group.group_index != group_index
                or any(getattr(group, k) != getattr(scope, k) for k in IssuanceSourceScope.model_fields)
                or len(group.page_digests) != expected_len
            ):
                raise RootTrustError("Retained issuance page group scope or position differs")
            all_page_digests.extend(group.page_digests)
        if len(set(all_page_digests)) != len(all_page_digests):
            raise RootTrustError("Duplicate issuance source page across groups")
        return await _load_pages(tx, scope, manifest.entry_count, tuple(all_page_digests))
    manifest = PagedIssuanceSource.model_validate_json(canonical_bytes(source))
    return await _load_pages(tx, scope, manifest.entry_count, manifest.page_digests)
