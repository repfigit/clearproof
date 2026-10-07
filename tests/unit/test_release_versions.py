"""Release versions are one string until 1.0.0.

The package version, Python project, lockfiles, workspace @clearproof
dependencies, and PROJECT_STATUS.npmVersion and sourceVersion must match.
Already published tarballs are immutable and are outside this check.
"""

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _manifests() -> list[Path]:
    return [
        ROOT / "package.json",
        *sorted((ROOT / "apps").glob("*/package.json")),
        *sorted((ROOT / "packages").glob("*/package.json")),
    ]


def _lock_key(manifest: Path) -> str:
    if manifest.parent == ROOT:
        return ""
    return manifest.parent.relative_to(ROOT).as_posix()


def _declared(spec: str) -> str:
    if spec.startswith("^"):
        return spec[1:]
    return spec


def _package_versions() -> dict[str, str]:
    found: dict[str, str] = {}
    for manifest in _manifests():
        rel = manifest.relative_to(ROOT).as_posix()
        data = json.loads(manifest.read_text())
        found[rel] = data["version"]
        dependencies = {
            **data.get("dependencies", {}),
            **data.get("devDependencies", {}),
            **data.get("peerDependencies", {}),
        }
        for name, spec in dependencies.items():
            if name.startswith("@clearproof/"):
                found[f"{rel} dependency {name}"] = _declared(spec)
    return found


def _lock_versions() -> dict[str, str]:
    lock = json.loads((ROOT / "package-lock.json").read_text())
    found = {"package-lock.json": lock["version"]}
    for manifest in _manifests():
        path = _lock_key(manifest)
        entry = lock["packages"][path]
        label = "package-lock root package" if path == "" else f"package-lock {path}"
        found[label] = entry["version"]
        for name, spec in entry.get("dependencies", {}).items():
            if name.startswith("@clearproof/"):
                found[f"{label} dependency {name}"] = _declared(spec)
    return found


def _python_version() -> dict[str, str]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    lock_text = (ROOT / "uv.lock").read_text()
    match = re.search(r'\[\[package\]\]\nname = "clearproof"\nversion = "([^"]+)"\n', lock_text)
    if match is None:
        raise AssertionError("uv.lock has no clearproof package version")
    return {"pyproject.toml": project["project"]["version"], "uv.lock clearproof": match.group(1)}


def _status_versions() -> dict[str, str]:
    status = (ROOT / "packages/content/src/project.ts").read_text()
    found: dict[str, str] = {}
    for field in ("npmVersion", "sourceVersion"):
        match = re.search(rf"{field}: '([^']+)'", status)
        if match is None:
            raise AssertionError(f"PROJECT_STATUS.{field} is missing")
        found[f"PROJECT_STATUS.{field}"] = match.group(1)
    return found


def test_release_versions_match() -> None:
    found = _package_versions() | _lock_versions() | _python_version() | _status_versions()
    expected = found["package.json"]
    mismatches = {name: value for name, value in sorted(found.items()) if value != expected}
    assert not mismatches, f"release version {expected} diverges:\n" + "\n".join(
        f"{name} = {value}" for name, value in mismatches.items()
    )
