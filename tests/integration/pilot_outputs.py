"""Explicitly requested synthetic acceptance outputs; never enabled for ordinary test runs."""

import json
import os
from pathlib import Path


def retain_output(name: str, value, *, private=False):
    directory = os.environ.get("CLEARPROOF_PILOT_RUN_OUTPUT")
    if directory is None:
        return
    if Path(name).name != name or not name.endswith(".json"):
        raise ValueError("Invalid pilot output name")
    target = Path(directory) / ("private" if private else "reports") / name
    raw = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"
    # Fail on duplicate capture or a pre-existing file instead of silently replacing evidence.
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
