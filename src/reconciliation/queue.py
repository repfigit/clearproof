"""Bounded scan pages for a tenant's ageing investigation queue."""

from typing import Literal

from pydantic import Field

from src.protocol.transfer import Epoch, Hex32, Record
from src.reconciliation.events import InvestigationFinding, TransferScope
from src.reconciliation.provider_links import ProviderLink


class QueueRequest(Record):
    after: Hex32 | None = None
    limit: int = Field(default=8, ge=1, le=16)
    minimum_age_seconds: Epoch = 0


class QueueItem(Record):
    scope: TransferScope
    scope_digest: Hex32
    states: dict[str, str]
    findings: tuple[InvestigationFinding, ...]
    oldest_age_seconds: Epoch
    provider_links: tuple[ProviderLink, ...] = Field(default=(), max_length=8)


class QueuePage(Record):
    schema_version: Literal["clearproof-investigation-queue-v1"] = "clearproof-investigation-queue-v1"
    as_of: Epoch
    scanned_transfers: int
    items: tuple[QueueItem, ...]
    next_cursor: Hex32 | None
    ordering: Literal["scope-pages-age-within-page"] = "scope-pages-age-within-page"
