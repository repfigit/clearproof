"""Bounded storage encoding for public BN254 scalar-field signals.

This validates representation, not a proof version's arity or cryptographic validity.
Legacy Python list text is accepted only by the one-time database migration.
"""

from __future__ import annotations

import json
import re

import psycopg
from psycopg.types.json import Jsonb

SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
MAX_SIGNALS = 128
MAX_SIGNALS_BYTES = 16_384
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,76})")
_QUOTED_DECIMAL = r"(?:'[0-9]{1,77}'|\"[0-9]{1,77}\")"
_LEGACY_LIST = re.compile(rf"\s*\[\s*{_QUOTED_DECIMAL}(?:\s*,\s*{_QUOTED_DECIMAL})*\s*,?\s*\]\s*")


def validate_public_signals(value: object) -> list[str]:
    if type(value) is not list or not 1 <= len(value) <= MAX_SIGNALS:
        raise ValueError("public_signals must be a bounded, nonempty array")
    for signal in value:
        if type(signal) is not str or not _DECIMAL.fullmatch(signal) or int(signal) >= SCALAR_FIELD:
            raise ValueError("public_signals must contain canonical decimal scalar-field strings")
    return value.copy()


def decode_legacy_signals(value: object) -> list[str]:
    if not isinstance(value, str):
        return validate_public_signals(value)
    if len(value) > MAX_SIGNALS_BYTES or len(value.encode("utf-8")) > MAX_SIGNALS_BYTES:
        raise ValueError("public_signals legacy encoding exceeds the byte limit")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        # The old representation was a list of quoted decimal strings. Recognize
        # only that grammar: no Python parsing, escapes, concatenation or evaluation.
        if not _LEGACY_LIST.fullmatch(value):
            raise ValueError("public_signals legacy encoding allows only quoted decimal strings") from None
        parsed = re.findall(r"['\"]([0-9]+)['\"]", value)
    except (ValueError, RecursionError):
        raise ValueError("public_signals legacy encoding is invalid") from None
    return validate_public_signals(parsed)


async def migrate_public_signals(conn: psycopg.AsyncConnection) -> None:
    """Upgrade in bounded pages, within the migration runner's atomic transaction."""
    last_id = None
    while True:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT proof_id,
                       CASE WHEN octet_length(public_signals::text) <= %s
                            THEN public_signals ELSE NULL END
                FROM proofs WHERE (%s::text IS NULL OR proof_id > %s)
                ORDER BY proof_id LIMIT 100 FOR UPDATE
                """,
                (MAX_SIGNALS_BYTES, last_id, last_id),
            )
            rows = await cur.fetchall()
            if not rows:
                return
            for proof_id, encoded in rows:
                signals = decode_legacy_signals(encoded)
                if isinstance(encoded, str):
                    await cur.execute(
                        "UPDATE proofs SET public_signals = %s WHERE proof_id = %s", (Jsonb(signals), proof_id)
                    )
            last_id = rows[-1][0]


# Guard every writer, including SQL clients that bypass the Python model.
# The constants are internal schema parameters, never user-provided SQL.
PUBLIC_SIGNALS_CONSTRAINT = f"""
CREATE FUNCTION clearproof_valid_public_signals(signals JSONB) RETURNS BOOLEAN
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE
    element JSONB;
    decimal_text TEXT;
BEGIN
    IF jsonb_typeof(signals) <> 'array' THEN RETURN FALSE; END IF;
    IF jsonb_array_length(signals) NOT BETWEEN 1 AND {MAX_SIGNALS}
       OR octet_length(signals::text) > {MAX_SIGNALS_BYTES} THEN RETURN FALSE; END IF;
    FOR element IN SELECT jsonb_array_elements(signals) LOOP
        IF jsonb_typeof(element) <> 'string' THEN RETURN FALSE; END IF;
        decimal_text := element #>> '{{}}';
        IF decimal_text !~ '^(0|[1-9][0-9]{{0,76}})$' THEN RETURN FALSE; END IF;
        IF decimal_text::numeric >= {SCALAR_FIELD} THEN RETURN FALSE; END IF;
    END LOOP;
    RETURN TRUE;
END
$$;
ALTER TABLE proofs ADD CONSTRAINT proofs_public_signals_valid
CHECK (clearproof_valid_public_signals(public_signals));
"""
