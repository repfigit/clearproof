"""Generate current pilot constants; never generate proving keys or approve a profile.

Run with --check in CI. A cryptographic parameter change still requires a new
profile, reviewed specification and keys; regenerating files is not a migration.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path("specs/pilot-signals-v3.json")
BEGIN = "<!-- BEGIN GENERATED PILOT SIGNALS -->"
END = "<!-- END GENERATED PILOT SIGNALS -->"


def validate(data: dict) -> None:
    """Reject malformed or ambiguous sources before writing any outputs."""
    if (
        type(data) is not dict
        or set(data)
        != {"schema_version", "profile", "public_signals", "tree_depths", "domain_tags", "limits", "projection_fields"}
        or type(data["schema_version"]) is not int
        or data["schema_version"] != 1
        or data["profile"] != "pilot-transfer-v3"
    ):
        raise ValueError("Expected the versioned pilot-transfer-v3 schema")
    for key, keys, low, high in (
        ("tree_depths", {"issuance", "issuer", "sanctions"}, 1, 32),
        (
            "domain_tags",
            {
                "holder",
                "credential",
                "issuer_leaf",
                "projection",
                "authorization_scope",
                "authorization_nullifier",
                "bound_projection",
                "sanctions_leaf",
            },
            1,
            65535,
        ),
        ("limits", {"proof_lifetime_seconds", "max_transfer_age_seconds", "max_asset_decimals"}, 1, 86400),
    ):
        values = data[key]
        if (
            type(values) is not dict
            or set(values) != keys
            or any(type(v) is not int or not low <= v <= high for v in values.values())
        ):
            raise ValueError(f"Invalid {key}")
    if len(set(data["domain_tags"].values())) != len(data["domain_tags"]):
        raise ValueError("Domain tags must be distinct")
    for key, count, extra in (("public_signals", 8, "meaning"), ("projection_fields", 48, "bits")):
        rows = data[key]
        if type(rows) is not list or len(rows) != count:
            raise ValueError(f"Invalid {key} length")
        names = []
        for row in rows:
            if (
                type(row) is not dict
                or set(row) != {"name", extra}
                or type(row["name"]) is not str
                or not re.fullmatch(r"[a-z][a-z0-9_]*", row["name"])
            ):
                raise ValueError(f"Invalid {key} entry")
            names.append(row["name"])
            value = row[extra]
            if extra == "bits":
                if type(value) is not int or not 1 <= value <= 252:
                    raise ValueError("Invalid projection bit width")
            elif type(value) is not str or not value or any(c in value for c in "\n\r|"):
                raise ValueError("Invalid signal meaning")
        if len(set(names)) != count:
            raise ValueError(f"Duplicate {key} names")


def camel(name: str) -> str:
    return "".join(part.title() for part in name.split("_"))


def unique_object(pairs: list[tuple]) -> dict:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate JSON object keys")
    return result


def render(root: Path) -> dict[Path, str]:
    raw = (root / SOURCE).read_bytes()
    data = json.loads(raw, object_pairs_hook=unique_object)
    validate(data)
    digest = hashlib.sha256(raw).hexdigest()
    banner = f"Generated: {SOURCE}; SHA256 {digest}."
    signals = tuple(row["name"] for row in data["public_signals"])
    fields = tuple(row["name"] for row in data["projection_fields"])
    widths = tuple(row["bits"] for row in data["projection_fields"])
    constants = {"PILOT_PUBLIC_SIGNAL_COUNT": len(signals), "PROJECTION_FIELD_COUNT": len(fields)}
    constants.update({name.upper() + "_INDEX": i for i, name in enumerate(signals)})
    constants.update({name.upper() + "_TREE_DEPTH": v for name, v in data["tree_depths"].items()})
    constants.update({name.upper() + "_DOMAIN_TAG": v for name, v in data["domain_tags"].items()})
    constants.update({name.upper(): v for name, v in data["limits"].items()})
    python = f'"""{banner}"""\n\nPROFILE = {data["profile"]!r}\nPUBLIC_SIGNALS = (\n'
    python += "".join(f"    {name!r},\n" for name in signals) + ")\n"
    python += "".join(f"{key} = {value}\n" for key, value in constants.items())
    python += "FIELD_NAMES = (\n" + "".join(f"    {name!r},\n" for name in fields) + ")\n"
    python += "PROJECTION_FIELD_WIDTHS = (\n" + "".join(f"    {v},\n" for v in widths) + ")\n"
    ts = f"// {banner}\nexport const PROFILE = '{data['profile']}' as const;\n"
    ts += "export const PUBLIC_SIGNALS = [\n" + "".join(f"  '{n}',\n" for n in signals) + "] as const;\n"
    ts += "export const PILOT_SIGNAL_INDICES = {\n"
    ts += "".join(f"  {name}: {i},\n" for i, name in enumerate(signals)) + "} as const;\n"
    ts += "".join(f"export const {key} = {value};\n" for key, value in constants.items())
    sol = f"// SPDX-License-Identifier: Apache-2.0\n// {banner}\npragma solidity ^0.8.24;\n\n"
    sol += f"uint256 constant PILOT_SIGNAL_COUNT = {len(signals)};\n\n"
    sol += "library PilotSignalConstants {\n" + f'    string internal constant PROFILE = "{data["profile"]}";\n'
    sol += "".join(f"    uint256 internal constant {key} = {v};\n" for key, v in constants.items()) + "}\n"
    circom = f"pragma circom 2.1.6;\n// {banner}\n\n"
    circom += "".join(f"function Pilot{camel(key)}() {{ return {v}; }}\n" for key, v in constants.items())
    circom += "function PilotProjectionWidth(i) {\n    var widths[48] = [" + ", ".join(map(str, widths)) + "];\n"
    circom += "    return widths[i];\n}\n"
    main = f"pragma circom 2.1.6;\n// {banner}\n"
    main += "component main {public [" + ", ".join(signals) + "]} = PilotCompliance(\n"
    main += "    PilotIssuanceTreeDepth(), PilotIssuerTreeDepth(), PilotSanctionsTreeDepth());\n"
    table = "| Index | Signal | Meaning |\n| --- | --- | --- |\n"
    table += "".join(f"| {i} | {row['name']} | {row['meaning']} |\n" for i, row in enumerate(data["public_signals"]))
    outputs = {
        Path("src/prover/generated_signals.py"): python,
        Path("packages/proof/src/generated-signals.ts"): ts,
        Path("packages/contracts/contracts/generated/PilotSignalConstants.sol"): sol,
        Path("circuits/generated/pilot_constants.circom"): circom,
        Path("circuits/generated/pilot_main.circom"): main,
        Path("packages/circuits/pilot-profile.json"): json.dumps(
            {
                "profile": data["profile"],
                "template": "PilotCompliance("
                + ", ".join(str(data["tree_depths"][key]) for key in ("issuance", "issuer", "sanctions"))
                + ")",
                "treeDepths": {
                    "issuance": data["tree_depths"]["issuance"],
                    "authorizedIssuers": data["tree_depths"]["issuer"],
                    "sanctions": data["tree_depths"]["sanctions"],
                },
                "publicSignals": signals,
            },
            indent=2,
        )
        + "\n",
    }
    for path in (Path("specs/pilot-transfer-v3.md"), Path("docs/internal/CIRCUIT_SIGNALS.md")):
        text = (root / path).read_text()
        if text.count(BEGIN) != 1 or text.count(END) != 1 or text.index(BEGIN) >= text.index(END):
            raise ValueError(f"Missing or ambiguous generation markers in {path}")
        before, after = text.split(BEGIN)[0], text.split(END)[1]
        outputs[path] = before + BEGIN + f"\n\n{table}\n" + END + after
    return outputs


def generate(root: Path, *, check: bool) -> list[str]:
    outputs = render(root)  # Validate every input before modifying anything.
    drift = []
    for path, content in outputs.items():
        target = root / path
        if not target.exists() or target.read_text() != content:
            drift.append(str(path))
            if not check:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content)
    return drift


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail on drift without writing any files")
    args = parser.parse_args(argv)
    try:
        drift = generate(ROOT, check=args.check)
    except (ValueError, OSError) as exc:
        print(f"Signal generation failed: {exc}")
        return 2
    if args.check and drift:
        print("Generated pilot constants differ: " + ", ".join(drift))
        return 1
    print("Pilot constants match the source" if args.check else "Pilot constants generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
