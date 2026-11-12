#!/usr/bin/env python3
"""Compare freshly built sanctions trees with the copies committed at a git ref.

The daily workflow rebuilds the trees from live feeds and must decide whether to
open a review PR. ``artifacts/`` is ignored, so ``git diff`` cannot answer that:
an ignored, untracked file never shows as changed. This script reads the
committed copy straight from the object store and compares tree roots, so a new
fetch timestamp alone is not a change and a first publication always is.

It also enforces the leaf-count floor: a legacy tree that lost more than half of
its addresses is treated as a feed failure and stops the workflow.

Usage:
    python scripts/sanctions_tree_diff.py [--ref HEAD] [--github-output "$GITHUB_OUTPUT"]

Exit status: 0 on success (changed or not), 1 when the floor is breached or an
artifact is missing or malformed.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

LEGACY_TREE = "artifacts/sanctions_tree.json"
PILOT_TREE = "artifacts/pilot_sanctions_tree.json"


class TreeDiffError(Exception):
    """A tree artifact is missing, malformed, or fails the leaf-count floor."""


def _summary(document: object, label: str) -> tuple[str, int]:
    """Return (root, leaf_count) or raise if the artifact lacks either."""
    if not isinstance(document, dict):
        raise TreeDiffError(f"{label}: artifact is not a JSON object")
    root, count = document.get("root"), document.get("leaf_count")
    if type(root) not in (str, int) or root == "":
        raise TreeDiffError(f"{label}: missing tree root")
    if type(count) is not int or count < 0:
        raise TreeDiffError(f"{label}: missing leaf_count")
    return str(root), count


def built_summary(repo: Path, path: str) -> tuple[str, int]:
    try:
        document = json.loads((repo / path).read_text())
    except FileNotFoundError as exc:
        raise TreeDiffError(f"{path}: not built") from exc
    except json.JSONDecodeError as exc:
        raise TreeDiffError(f"{path}: invalid JSON") from exc
    return _summary(document, path)


def committed_summary(repo: Path, ref: str, path: str) -> tuple[str, int] | None:
    """Summary of the copy committed at ``ref``, or None when none is committed."""
    listed = subprocess.run(
        ["git", "ls-tree", "--name-only", ref, "--", path],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    if not listed.stdout.strip():
        return None
    shown = subprocess.run(["git", "show", f"{ref}:{path}"], cwd=repo, capture_output=True, text=True, check=True)
    try:
        return _summary(json.loads(shown.stdout), f"{ref}:{path}")
    except json.JSONDecodeError as exc:
        raise TreeDiffError(f"{ref}:{path}: invalid JSON") from exc


def compare(repo: Path, ref: str) -> dict[str, str]:
    """Return the workflow outputs; raise TreeDiffError to stop the workflow."""
    legacy_new = built_summary(repo, LEGACY_TREE)
    pilot_new = built_summary(repo, PILOT_TREE)
    legacy_old = committed_summary(repo, ref, LEGACY_TREE)
    pilot_old = committed_summary(repo, ref, PILOT_TREE)

    previous = legacy_old[1] if legacy_old else 0
    if legacy_new[1] == 0:
        raise TreeDiffError("new legacy tree has no leaves; refusing to publish an empty list")
    if legacy_new[1] < previous / 2:
        raise TreeDiffError(
            f"sanctions leaf count dropped more than 50% ({previous} -> {legacy_new[1]}); "
            "this may indicate a data source issue"
        )

    legacy_changed = legacy_old is None or legacy_old[0] != legacy_new[0]
    pilot_changed = pilot_old is None or pilot_old[0] != pilot_new[0]
    return {
        "changed": "true" if legacy_changed or pilot_changed else "false",
        "legacy_changed": "true" if legacy_changed else "false",
        "pilot_changed": "true" if pilot_changed else "false",
        "prev_count": str(previous),
        "new_count": str(legacy_new[1]),
        "pilot_prev_count": str(pilot_old[1] if pilot_old else 0),
        "pilot_new_count": str(pilot_new[1]),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ref", default="HEAD", help="Git ref holding the reviewed trees (default: HEAD)")
    parser.add_argument("--repo", default=".", help="Repository root (default: current directory)")
    parser.add_argument("--github-output", help="Append key=value outputs to this file")
    args = parser.parse_args(argv)
    try:
        outputs = compare(Path(args.repo), args.ref)
    except TreeDiffError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    lines = [f"{key}={value}" for key, value in outputs.items()]
    print("\n".join(lines))
    if args.github_output:
        with open(args.github_output, "a") as handle:
            handle.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
