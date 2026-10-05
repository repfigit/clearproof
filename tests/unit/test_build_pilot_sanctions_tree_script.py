"""Pilot sanctions tree builder: legacy feed reuse, raw-address rules and audit re-verification.

No network: feed fetchers are replaced with synthetic results.
"""

import json
import runpy
import sys

import pytest

from scripts import build_pilot_sanctions_tree as builder
from scripts import build_sanctions_tree as legacy
from src.registry.pilot_sanctions import PilotSanctionsTree

A, B, C = "0x" + "ab" * 20, "0x" + "12" * 20, "0x" + "03" * 20


def legacy_artifact(path, addresses, **manifest):
    path.write_text(
        json.dumps(
            {
                "root": "123",
                "sorted_addresses": addresses,
                "source_manifest": {
                    "build_script_version": legacy.BUILD_SCRIPT_VERSION,
                    "fetch_timestamp": "synthetic-time",
                    "sources": {"synthetic": {"addresses_found": len(addresses)}},
                    "normalization_spec": {"ens_resolution": "never"},
                    **manifest,
                },
            }
        )
    )
    return path


def test_canonical_addresses_reuse_legacy_normalization_and_dedupe():
    raw = ["  0xABABABABABABABABABABABABABABABABABABABAB ", A, "121212121212121212121212121212121212121" + "2", C]
    assert builder.canonical_addresses(raw) == sorted([A, B, C])


@pytest.mark.parametrize("raw", [None, [1], ["vitalik.eth"], ["0x" + "00" * 20], [""]])
def test_canonical_addresses_reject_names_zero_and_non_strings(raw):
    with pytest.raises(ValueError):
        builder.canonical_addresses(raw)


async def test_build_from_legacy_artifact_then_verify(tmp_path, capsys):
    source = legacy_artifact(tmp_path / "legacy.json", [A, B, C])
    output = tmp_path / "out" / "pilot.json"
    assert await builder.main(["--input", str(source), "--output", str(output)]) == 0
    artifact = json.loads(output.read_text())
    tree = PilotSanctionsTree([A, B, C])
    assert artifact["root"] == tree.root and artifact["sorted_addresses"] == sorted([A, B, C])
    assert artifact["proof_profile"] == "pilot-transfer-v3" and artifact["ens_resolution"] == "never"
    assert artifact["input"]["kind"] == "legacy-sanctions-tree"
    assert artifact["input"]["legacy_root"] == "123"
    assert artifact["build"]["script_version"] == builder.BUILD_SCRIPT_VERSION
    assert "Next: publish" in capsys.readouterr().out
    assert await builder.main(["--verify", "--output", str(output)]) == 0
    assert "OK: 3 addresses" in capsys.readouterr().out


@pytest.mark.parametrize(
    "tamper",
    [
        lambda a: a.update(sorted_addresses=list(reversed(a["sorted_addresses"]))),
        lambda a: a.update(root="1"),
        lambda a: a.update(sorted_addresses=a["sorted_addresses"][1:]),
    ],
)
async def test_verify_rejects_unsorted_or_altered_publication(tmp_path, capsys, tamper):
    source = legacy_artifact(tmp_path / "legacy.json", [A, B, C])
    output = tmp_path / "pilot.json"
    assert await builder.main(["--input", str(source), "--output", str(output)]) == 0
    artifact = json.loads(output.read_text())
    tamper(artifact)
    output.write_text(json.dumps(artifact))
    assert await builder.main(["--verify", "--output", str(output)]) == 1
    assert "FAIL:" in capsys.readouterr().err


async def test_verify_reports_missing_artifact(tmp_path, capsys):
    assert await builder.main(["--verify", "--output", str(tmp_path / "missing.json")]) == 1
    assert "FAIL:" in capsys.readouterr().err


@pytest.mark.parametrize(
    "content,message",
    [
        ({"root": "1"}, "sorted_addresses"),
        ([], "sorted_addresses"),
        (
            {"sorted_addresses": [A], "source_manifest": {"normalization_spec": {"ens_resolution": "allowed"}}},
            "raw addresses only",
        ),
    ],
)
def test_legacy_artifact_must_list_raw_addresses(tmp_path, content, message):
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps(content))
    with pytest.raises(ValueError, match=message):
        builder.load_legacy_artifact(str(path))


def test_legacy_artifact_without_manifest_is_accepted(tmp_path):
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps({"sorted_addresses": [A]}))
    addresses, provenance = builder.load_legacy_artifact(str(path))
    assert addresses == [A] and provenance["sources"] is None


async def test_fetch_reuses_legacy_fetchers_without_network(tmp_path, monkeypatch):
    calls = []

    def fake(name, found):
        async def fetch(client):
            calls.append(name)
            return found, {"fetched": True, "addresses_found": len(found)}

        return fetch

    monkeypatch.setattr(legacy, "fetch_ofac_sdn_xml", fake("sdn", [A]))
    monkeypatch.setattr(legacy, "fetch_ofac_consolidated_csv", fake("csv", [B.upper().replace("0X", "0x")]))
    monkeypatch.setattr(legacy, "fetch_eu_sanctions_xml", fake("eu", [C, A]))
    monkeypatch.setattr(legacy, "KNOWN_OFAC_ADDRESSES", [C])
    output = tmp_path / "pilot.json"
    assert await builder.main(["--fetch", "--output", str(output)]) == 0
    artifact = json.loads(output.read_text())
    assert calls == ["sdn", "csv", "eu"]
    assert artifact["sorted_addresses"] == sorted([A, B, C])
    assert artifact["input"]["kind"] == "live-feeds"
    assert set(artifact["input"]["sources"]) == {
        "hardcoded_ofac",
        "ofac_sdn_xml",
        "ofac_consolidated_csv",
        "eu_sanctions_xml",
    }


async def test_offline_fetch_uses_only_hardcoded_addresses(tmp_path, monkeypatch):
    async def forbidden(client):
        raise AssertionError("offline mode must not fetch")

    monkeypatch.setattr(legacy, "fetch_ofac_sdn_xml", forbidden)
    output = tmp_path / "pilot.json"
    assert await builder.main(["--fetch", "--offline", "--output", str(output)]) == 0
    artifact = json.loads(output.read_text())
    assert artifact["input"]["kind"] == "offline"
    assert artifact["address_count"] == len({legacy.normalize_address(a) for a in legacy.KNOWN_OFAC_ADDRESSES})


async def test_offline_requires_fetch(capsys):
    with pytest.raises(SystemExit):
        await builder.main(["--offline"])
    assert "--offline requires --fetch" in capsys.readouterr().err


def test_cli_entry_verifies_isolated_artifact(tmp_path, monkeypatch):
    output = tmp_path / "pilot.json"
    output.write_text(json.dumps(PilotSanctionsTree([A]).artifact()))
    monkeypatch.setattr(sys, "argv", [builder.__file__, "--verify", "--output", str(output)])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(builder.__file__, run_name="__main__")
    assert exit_info.value.code == 0
