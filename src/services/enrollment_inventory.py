# SPDX-License-Identifier: Apache-2.0
"""Live, bounded discovery and resumable validated indexing of encrypted enrollment."""

from typing import Literal

from pydantic import Field, model_validator

from src.auth.principal import Principal
from src.protocol.discovery_profile import DiscoveryError, parse_target
from src.protocol.transfer import Address, Epoch, Hex32, Record
from src.services.enrollment import (
    EnrollmentIntegrityError,
    enrollment_audience,
    enrollment_scope,
    validate_retained_enrollment,
)
from src.storage.database import Database
from src.storage.pilot import PilotStore
from src.storage.pilot_cipher import RecordCipher

ENROLLMENT_PAGE_SIZE = 64


class InventoryAudience(Record):
    chain_id: int = Field(ge=1, le=2**53 - 1)
    registry_address: Address

    @model_validator(mode="after")
    def nonzero_registry(self):
        if self.registry_address == "0x" + "0" * 40:
            raise ValueError("Invalid inventory audience")
        return self


class EnrollmentPageRequest(Record):
    issuer_did: str = Field(max_length=512)
    after: Hex32 | None = None
    limit: int = Field(default=ENROLLMENT_PAGE_SIZE, ge=1, le=ENROLLMENT_PAGE_SIZE)

    @model_validator(mode="after")
    def canonical_issuer(self):
        try:
            target = parse_target(self.issuer_did)
        except DiscoveryError:
            raise ValueError("Issuer requires canonical did:web") from None
        if target.did != self.issuer_did:
            raise ValueError("Issuer requires canonical did:web")
        return self


class EnrollmentInventoryEntry(Record):
    credential_id: Hex32
    eligible: bool


class EnrollmentInventoryPage(Record):
    schema_version: Literal["clearproof-enrollment-inventory-v1"] = "clearproof-enrollment-inventory-v1"
    scope: Literal["live-enrollment-inventory"] = "live-enrollment-inventory"
    checked_at: Epoch
    entries: tuple[EnrollmentInventoryEntry, ...] = Field(max_length=ENROLLMENT_PAGE_SIZE)
    next_cursor: Hex32 | None
    authorization_consumed: Literal[False] = False


class EnrollmentBackfillRequest(Record):
    after: Hex32 | None = None
    limit: int = Field(default=ENROLLMENT_PAGE_SIZE, ge=1, le=ENROLLMENT_PAGE_SIZE)


class EnrollmentBackfillPage(Record):
    validated_records: int = Field(ge=0, le=ENROLLMENT_PAGE_SIZE)
    next_cursor: Hex32 | None
    inventory_complete: bool


class EnrollmentInventoryService:
    def __init__(
        self, db: Database, cipher: RecordCipher, principal: Principal, *, chain_id: int, registry_address: str
    ):
        self._principal = Principal.model_validate(principal)
        self._audience = InventoryAudience(chain_id=chain_id, registry_address=registry_address)
        self._store = PilotStore(db, cipher, self._principal)

    async def page(self, request: EnrollmentPageRequest, *, now: int) -> EnrollmentInventoryPage:
        request = EnrollmentPageRequest.model_validate(request)
        self._principal.require_issuer(request.issuer_did)
        self._principal.require("evidence:decrypt")
        if type(now) is not int or not 0 <= now < 2**53:
            raise ValueError("Invalid inventory clock")
        scope = enrollment_audience(
            self._principal.tenant_id, request.issuer_did, self._audience.chain_id, self._audience.registry_address
        )
        async with self._store.transaction() as tx:
            await tx.check_enrollment_inventory()
            ids = await tx.enrollment_ids(scope, after=request.after, limit=request.limit + 1)
            entries = []
            for record_id in ids[: request.limit]:
                stored = await tx.get("credential", record_id)
                consent = validate_retained_enrollment(tx.tenant_id, record_id, stored)
                if enrollment_scope(consent) != scope:
                    raise EnrollmentIntegrityError("Enrollment inventory audience differs")
                credential = consent.credential
                eligible = (
                    stored["accepted_at"] <= now
                    and credential.issued_at <= now < credential.expires_at
                    and credential.sanctions_clear
                    and await tx.get("revocation", record_id) is None
                )
                entries.append(EnrollmentInventoryEntry(credential_id=record_id, eligible=eligible))
        return EnrollmentInventoryPage(
            checked_at=now,
            entries=tuple(entries),
            next_cursor=ids[request.limit - 1] if len(ids) > request.limit else None,
        )

    async def backfill_page(self, *, after: str | None = None, limit: int = ENROLLMENT_PAGE_SIZE) -> dict:
        """Operator repair: authenticate each immutable source before indexing it.

        Replaying a page is safe. Skipped pages cannot establish completeness;
        discovery and tree construction independently check for unindexed rows.
        """
        self._principal.require("tenant:admin")
        self._principal.require("credential:issue")
        self._principal.require("evidence:decrypt")
        if type(limit) is not int or not 1 <= limit <= ENROLLMENT_PAGE_SIZE:
            raise ValueError("Invalid inventory backfill page")
        async with self._store.transaction() as tx:
            ids = await tx.record_ids("credential", after=after, limit=limit + 1)
            for record_id in ids[:limit]:
                stored = await tx.get("credential", record_id)
                consent = validate_retained_enrollment(tx.tenant_id, record_id, stored)
                self._principal.require_issuer(consent.credential.issuer_did)
                await tx.index_enrollment(record_id, enrollment_scope(consent))
            try:
                await tx.check_enrollment_inventory()
                complete = True
            except ValueError:
                complete = False
        return dict(
            validated_records=min(len(ids), limit),
            next_cursor=ids[limit - 1] if len(ids) > limit else None,
            inventory_complete=complete,
        )
