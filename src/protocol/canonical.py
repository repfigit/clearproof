"""Bounded canonical JSON for versioned pilot records, not arbitrary Unicode JSON."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

MAX_RECORD_BYTES = 65536


def canonical_bytes(value: Any) -> bytes:
    """ASCII strings, safe integers, booleans, null, arrays and objects only.

    This restricted profile avoids floating point and Unicode sorting ambiguity.
    It is intentionally not a general implementation of RFC 8785.
    """

    budget = MAX_RECORD_BYTES

    def charge(amount: int) -> None:
        nonlocal budget
        budget -= amount
        if budget < 0:
            raise ValueError("Canonical record exceeds validation budget")

    def validate(item: Any, depth: int) -> None:
        charge(8)
        if depth > 8:
            raise ValueError("Canonical record exceeds nesting limit")
        if item is None or type(item) is bool:
            return
        if type(item) is int and abs(item) <= 2**53 - 1:
            return
        if type(item) is str and len(item) <= 4096 and all(32 <= ord(c) <= 126 for c in item):
            charge(len(item))
            return
        if type(item) is list and len(item) <= 256:
            for child in item:
                validate(child, depth + 1)
            return
        if type(item) is dict and len(item) <= 64:
            for key, child in item.items():
                if type(key) is not str or not re.fullmatch(r"[ -~]{1,128}", key):
                    raise ValueError("Invalid canonical record key")
                charge(len(key) + 3)
                validate(child, depth + 1)
            return
        raise ValueError("Unsupported canonical record value")

    validate(value, 0)
    result = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode(
        "ascii"
    )
    if len(result) > MAX_RECORD_BYTES:
        raise ValueError("Canonical record exceeds 64 KiB")
    return result


def record_digest(domain: str, value: Any) -> str:
    if not re.fullmatch(r"clearproof/[a-z-]+/v[1-9][0-9]*", domain):
        raise ValueError("Invalid commitment domain")
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + canonical_bytes(value)).hexdigest()
