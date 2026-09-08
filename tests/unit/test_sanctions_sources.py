"""Synthetic source parsing over HTTPX's in-process transport; no live requests."""

import hashlib
import json
import runpy
import sys
from pathlib import Path

import httpx
import pytest

from scripts import build_sanctions_tree as builder

ADDRESS = "0x" + "12" * 20
OTHER = "0x" + "34" * 20
FETCHERS = [
    (builder.fetch_ofac_sdn_xml, builder.OFAC_SDN_XML_URL),
    (builder.fetch_ofac_consolidated_csv, builder.OFAC_CONS_CSV_URL),
    (builder.fetch_eu_sanctions_xml, builder.EU_SANCTIONS_URL),
]


@pytest.mark.parametrize("namespace", ["", ' xmlns="urn:synthetic-sanctions"'])
async def test_ofac_xml_extracts_crypto_features_ids_and_raw_text(namespace):
    payload = (
        f'<root{namespace}><feature>Digital currency address <value>{ADDRESS}</value></feature>'
        f'<id>ordinary label</id><id>ETH {OTHER}</id><feature/>'
        f'<notes>{ADDRESS}</notes><!-- {OTHER} --></root>'
    ).encode()
    calls = []

    def serve(request):
        calls.append(request)
        return httpx.Response(200, content=payload, headers={"Last-Modified": "synthetic-timestamp"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(serve)) as client:
        addresses, metadata = await builder.fetch_ofac_sdn_xml(client)
    assert set(addresses) == {ADDRESS, OTHER}
    assert metadata["addresses_found"] == 2
    assert metadata["sha256"] == hashlib.sha256(payload).hexdigest()
    assert metadata["last_modified"] == "synthetic-timestamp"
    assert metadata["content_length"] == len(payload)
    assert metadata["fetched"] is True and metadata["error"] is None
    assert [str(request.url) for request in calls] == [builder.OFAC_SDN_XML_URL]


@pytest.mark.parametrize(
    "fetcher,url,payload",
    [
        (builder.fetch_ofac_consolidated_csv, builder.OFAC_CONS_CSV_URL,
         f'ordinary,ignored\nDigital currency,"{ADDRESS}";({OTHER})\n"{ADDRESS}"\n'),
        (builder.fetch_eu_sanctions_xml, builder.EU_SANCTIONS_URL,
         f'<root> "{ADDRESS}" <entry> {OTHER} </entry> {ADDRESS} ignored </root>'),
    ],
)
async def test_csv_and_eu_sources_extract_addresses_and_record_raw_digest(fetcher, url, payload):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, text=payload))
    ) as client:
        addresses, metadata = await fetcher(client)
    assert set(addresses) == {ADDRESS, OTHER}
    assert metadata == {
        "source": url, "fetched": True, "error": None, "status_code": 200,
        "content_length": len(payload.encode()), "sha256": hashlib.sha256(payload.encode()).hexdigest(),
        "last_modified": "unknown", "addresses_found": 2,
    }


@pytest.mark.parametrize("fetcher,url", FETCHERS)
@pytest.mark.parametrize("failure", ["http", "timeout"])
async def test_source_failures_return_explicit_metadata_without_addresses(fetcher, url, failure):
    def serve(request):
        if failure == "timeout":
            raise httpx.ReadTimeout("synthetic read timeout", request=request)
        return httpx.Response(503, text="synthetic outage")

    async with httpx.AsyncClient(transport=httpx.MockTransport(serve)) as client:
        addresses, metadata = await fetcher(client)
    assert addresses == []
    assert metadata["source"] == url
    assert metadata["fetched"] is False
    assert metadata["error"]
    assert "sha256" not in metadata
    assert "addresses_found" not in metadata


async def test_malformed_ofac_xml_keeps_raw_digest_but_reports_parse_failure():
    payload = b"<unfinished"
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=payload))
    ) as client:
        addresses, metadata = await builder.fetch_ofac_sdn_xml(client)
    assert addresses == []
    assert metadata["fetched"] is True
    assert metadata["sha256"] == hashlib.sha256(payload).hexdigest()
    assert metadata["error"]
    assert "addresses_found" not in metadata


@pytest.mark.parametrize("value", ["synthetic.eth", "12" * 20, "0x" + "1" * 37, "0x" + "1" * 43, "0x" + "g" * 40])
def test_address_detection_rejects_names_and_malformed_tokens(value):
    assert not builder._looks_like_eth_address(value)


def test_address_tokenizer_handles_punctuation_and_case_without_name_resolution():
    upper = OTHER.upper()
    assert builder._extract_eth_addresses_from_text(f'[{ADDRESS}], "{upper}"; synthetic.eth') == [ADDRESS, upper]


@pytest.fixture
def outputs(tmp_path, monkeypatch):
    artifacts = tmp_path / "synthetic-artifacts"
    tree = artifacts / "sanctions_tree.json"
    vectors = artifacts / "sanctions_test_vectors.json"
    monkeypatch.setattr(builder, "ARTIFACTS_DIR", str(artifacts))
    monkeypatch.setattr(builder, "OUTPUT_PATH", str(tree))
    monkeypatch.setattr(builder, "TEST_VECTORS_PATH", str(vectors))
    monkeypatch.setattr(builder, "KNOWN_OFAC_ADDRESSES", [ADDRESS, ADDRESS.upper(), OTHER])
    return tree, vectors


@pytest.mark.parametrize("offline", [False, True])
async def test_build_outputs_retain_provenance_and_verify_without_rewriting(outputs, monkeypatch, offline):
    tree, vectors = outputs
    requests = []

    def serve(request):
        requests.append(str(request.url))
        return httpx.Response(200, text=f"<root> {ADDRESS} </root>")

    client_type = httpx.AsyncClient
    monkeypatch.setattr(
        builder.httpx, "AsyncClient",
        lambda **kwargs: client_type(transport=httpx.MockTransport(serve), **kwargs),
    )
    await builder.main(offline=offline, target_depth=3)
    data = json.loads(tree.read_text())
    assert data["depth"] == 3 and data["padded_size"] == 8
    assert data["leaf_count"] == 2 and data["sentinel_count"] == 2
    assert set(data["sorted_addresses"]) == {ADDRESS, OTHER}
    manifest = data["source_manifest"]
    assert manifest["total_unique_addresses"] == 2
    assert manifest["normalization_spec"]["ens_resolution"] == "never"
    assert manifest["build_script_hash"] == hashlib.sha256(Path(builder.__file__).read_bytes()).hexdigest()
    if offline:
        assert requests == []
        assert manifest["sources"] == {"mode": "offline"}
    else:
        assert requests == [url for _, url in FETCHERS]
        assert all(source["fetched"] and source["error"] is None for source in manifest["sources"].values())
    before = (tree.read_bytes(), vectors.read_bytes())
    assert await builder.verify_tree() is True
    with pytest.raises(SystemExit) as result:
        await builder.main(verify=True)
    assert result.value.code == 0
    assert (tree.read_bytes(), vectors.read_bytes()) == before
    # Duplicate normalized inputs must not affect the actual root.
    reference = await builder.build_merkle_tree([OTHER, ADDRESS, ADDRESS.upper()], target_depth=3)
    assert reference["root"] == data["root"]


async def test_missing_and_altered_vectors_fail_verification_without_writes(outputs):
    tree, vectors = outputs
    assert await builder.verify_tree() is False
    with pytest.raises(SystemExit) as result:
        await builder.main(verify=True)
    assert result.value.code == 1
    assert not tree.exists() and not vectors.exists()
    await builder.main(offline=True)
    data = json.loads(vectors.read_text())
    data["vectors"][0]["expected_leaf_hash"] = "0"
    vectors.write_text(json.dumps(data))
    before = (tree.read_bytes(), vectors.read_bytes())
    assert await builder.verify_tree() is False
    assert (tree.read_bytes(), vectors.read_bytes()) == before


def test_cli_verify_entry_uses_isolated_existing_vectors(tmp_path, monkeypatch):
    root = tmp_path / "isolated"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    script = scripts / "build_sanctions_tree.py"
    script.symlink_to(Path(builder.__file__).resolve())
    (root / "src").symlink_to(Path(builder.PROJECT_ROOT) / "src", target_is_directory=True)
    artifacts = root / "artifacts"
    artifacts.mkdir()
    vectors = artifacts / "sanctions_test_vectors.json"
    vectors.write_text(json.dumps({"vectors": [{
        "address_int": str(int(ADDRESS, 16)), "normalized": ADDRESS,
        "expected_leaf_hash": str(builder._native_poseidon_hash([builder.SANCTIONS_DOMAIN_TAG, int(ADDRESS, 16)])),
    }]}))
    before = vectors.read_bytes()
    monkeypatch.setattr(sys, "argv", [str(script), "--verify"])
    with pytest.raises(SystemExit) as result:
        runpy.run_path(str(script), run_name="__main__")
    assert result.value.code == 0
    assert vectors.read_bytes() == before
    assert not (artifacts / "sanctions_tree.json").exists()
