"""Operator-configured navigation references, separate from source evidence or authority."""

from collections import Counter
from typing import Annotated
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from src.protocol.transfer import Hex32, OpaqueId, Record


class ProviderLink(Record):
    source_id: OpaqueId
    label: OpaqueId
    url: Annotated[str, Field(min_length=1, max_length=2048, pattern=r"^[\x21-\x7e]+$")]

    @field_validator("url")
    @classmethod
    def safe_navigation(cls, value):
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or "\\" in value
        ):
            raise ValueError("Provider links require an HTTPS URL without credentials, query or fragment")
        # Validate the port without resolving or contacting the host.
        _ = parsed.port
        return value


class ScopedProviderLink(ProviderLink):
    tenant_id: OpaqueId
    scope_digest: Hex32


class ProviderLinkCatalog:
    def __init__(self, links=()):
        self.links = tuple(ScopedProviderLink.model_validate(link) for link in links)
        counts = Counter((link.tenant_id, link.scope_digest) for link in self.links)
        identities = {(link.tenant_id, link.scope_digest, link.source_id, link.url) for link in self.links}
        if len(self.links) > 256 or any(count > 8 for count in counts.values()) or len(identities) != len(self.links):
            raise ValueError("Provider link catalogue exceeds bounds or contains duplicate references")

    def for_events(self, tenant_id, scope_digest, events):
        sources = {event.source_id for event in events}
        return tuple(
            ProviderLink.model_validate(link.model_dump(exclude={"tenant_id", "scope_digest"}))
            for link in sorted(self.links, key=lambda link: (link.source_id, link.label, link.url))
            if link.tenant_id == tenant_id and link.scope_digest == scope_digest and link.source_id in sources
        )
