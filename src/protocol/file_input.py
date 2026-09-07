"""Bounded regular-file reads for local protocol commands."""

import os
import stat
from pathlib import Path


def read_bounded(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Expected a regular input file")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Input size limit")
    return raw
