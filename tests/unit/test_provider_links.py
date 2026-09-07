from types import SimpleNamespace

import pytest

from src.reconciliation.provider_links import ProviderLink, ProviderLinkCatalog, ScopedProviderLink


def configured(**changes):
    return ScopedProviderLink.model_validate(
        dict(
            tenant_id="tenant-a",
            scope_digest="ab" * 32,
            source_id="custody",
            label="provider-console",
            url="https://console.example/transactions/opaque-id",
            **changes,
        )
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://console.example/tx",
        "javascript:alert(1)",
        "https://user:secret@console.example/tx",
        "https://console.example/tx?token=secret",
        "https://console.example/tx#secret",
        "https://console.example/tx\nforged",
        "https://console.example:invalid/tx",
        "https://console.example\\@evil.example",
    ],
)
def test_navigation_rejects_active_content_credentials_and_hidden_fields(url):
    with pytest.raises(ValueError):
        ProviderLink(source_id="custody", label="console", url=url)


def test_links_require_same_tenant_scope_and_an_observed_source():
    link = configured()
    catalog = ProviderLinkCatalog((link,))
    event = SimpleNamespace(source_id="custody")
    assert catalog.for_events("tenant-a", "ab" * 32, (event,))[0].url == link.url
    assert catalog.for_events("tenant-b", "ab" * 32, (event,)) == ()
    assert catalog.for_events("tenant-a", "cd" * 32, (event,)) == ()
    assert catalog.for_events("tenant-a", "ab" * 32, ()) == ()
    assert catalog.for_events("tenant-a", "ab" * 32, (SimpleNamespace(source_id="other"),)) == ()
    assert "tenant_id" not in catalog.for_events("tenant-a", "ab" * 32, (event,))[0].model_dump()


def test_catalog_rejects_duplicates_and_excess_per_transfer():
    link = configured()
    with pytest.raises(ValueError):
        ProviderLinkCatalog((link, link))
    with pytest.raises(ValueError):
        ProviderLinkCatalog(tuple(link.model_copy(update={"url": f"https://console.example/{n}"}) for n in range(9)))
