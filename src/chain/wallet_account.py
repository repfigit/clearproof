"""Chain-side smart-account signature verification (ERC-1271 / ERC-6492) and
EIP-7702 delegation-indicator detection.

This module is deliberately **chain-side only**: it never performs local
``ecrecover``. The caller (e.g. ``src/services/wallet_ownership.py``) owns the
EOA path and uses this module for accounts that carry on-chain code or that
present an ERC-6492 counterfactual wrapper.

PUBLIC CONTRACT
---------------

``account_code(w3, address) -> str``
    ``eth_getCode`` for ``address``, normalized to a lowercase ``0x``-prefixed
    hex string (``"0x"`` when the account is an EOA or has empty code).

``delegation_indicator(code) -> dict``
    Detect the EIP-7702 delegation indicator in account code. Returns
    ``{"delegated": bool, "delegate": str | None, "indicator_malformed": bool}``.

    The strict indicator form enforced here is::

        0xef0100 || delegate (20 bytes) || zero padding (3 bytes)

    i.e. 0xef0100 followed by a 23-byte payload of which the first 20 bytes are
    the delegate address and the remaining bytes MUST be zero. Code that starts
    with ``0xef0100`` but does not match this exact form is NOT a valid
    delegation indicator: it is reported with ``delegated=False`` and
    ``indicator_malformed=True``. Code without the ``0xef0100`` prefix is
    ordinary contract code: ``delegated=False``, ``indicator_malformed=False``.

    ``delegate`` is the extracted address as lowercase ``0x``-prefixed hex
    (``None`` unless ``delegated`` is True).

``parse_erc6492(signature) -> dict | None``
    Parse an ERC-6492 counterfactual signature wrapper::

        inner_signature || contract_address (20) || data_to_sign
                         || len(data_to_sign) as 32 bytes || MAGIC_SUFFIX

    where ``MAGIC_SUFFIX`` is ``0x64926492649264926492649264926492``. Returns
    ``None`` when the magic suffix is absent (an ordinary signature). Raises
    ``ValueError`` when the suffix is present but the surrounding layout is
    inconsistent — including trailing junk after the suffix, lengths that do
    not fit, or an empty inner signature.

``verify_signature(w3, address, digest, signature) -> (valid, method)``
    Unified verification. ``method`` is one of ``"eoa"``, ``"erc-1271"``,
    ``"erc-6492"``.

    - If ``signature`` carries the ERC-6492 magic suffix, the ERC-6492 path
      wins regardless of current account code. The wrapper is parsed strictly;
      a structurally invalid wrapper is ``(False, "erc-6492")`` (fail closed,
      not an exception). A valid wrapper is verified by simulating the account
      deployment via ``eth_call`` with a state override that sets the account's
      code to ``data_to_sign`` (the deploy payload) and calling
      ``isValidSignature(bytes32,bytes)`` on it (ERC-1271 semantics).
    - Otherwise the account code is read. Empty code raises
      :class:`EoaVerificationRequired` — the sentinel the caller uses to fall
      back to its own ``ecrecover`` path (method ``"eoa"``).
    - Non-empty code — including a 7702-delegated EOA, whose delegation
      indicator is treated as contract code — is validated with an ERC-1271
      style ``eth_call`` of ``isValidSignature(bytes32,bytes)`` against the
      account. A 7702-delegated account therefore never falls back to the EOA
      path here: if the delegate does not implement ERC-1271 the call reverts
      and the result is ``(False, "erc-1271")``.
    - Magic return value ``0x1626ba7e`` followed by 28 zero bytes →
      ``(True, method)``; any other return value or a revert →
      ``(False, method)``.

FAIL-CLOSED RULES
-----------------

RPC/transport failures (network errors, malformed RPC responses) are never
interpreted as a valid signature: they are wrapped in
:class:`WalletAccountRPCError` and raised. Only a genuine on-chain answer —
magic value or revert — maps to a boolean result. ``eth_call`` reverts
(including a missing ``isValidSignature`` selector) count as signature
*invalidity*, not RPC failure.
"""

from typing import Any

from web3.exceptions import ContractLogicError, Web3RPCError

# ERC-1271 magic return value of isValidSignature(bytes32,bytes).
ERC_1271_MAGIC_VALUE = "0x1626ba7e"
_IS_VALID_SIGNATURE_SELECTOR = bytes.fromhex("1626ba7e")

# ERC-6492 magic suffix (32 bytes) and EIP-7702 delegation prefix (3 bytes).
ERC_6492_MAGIC_SUFFIX = "0x64926492649264926492649264926492"
EIP7702_DELEGATION_PREFIX = "0xef0100"

_MAGIC_VALUE_BYTES = bytes.fromhex("1626ba7e" + "00" * 28)
_MAGIC_SUFFIX_BYTES = bytes.fromhex("64926492649264926492649264926492")
_DELEGATION_PREFIX_BYTES = bytes.fromhex("ef0100")

# EIP-7702 indicator as enforced by this module: 3-byte prefix + 23-byte
# payload (20-byte delegate address + 3 bytes of zero padding).
_INDICATOR_PAYLOAD_LEN = 23
_INDICATOR_TOTAL_LEN = len(_DELEGATION_PREFIX_BYTES) + _INDICATOR_PAYLOAD_LEN  # 26

_ADDRESS_HEX_LEN = 40


class WalletAccountRPCError(Exception):
    """Raised when an RPC/transport failure prevents chain-side verification.

    Fail closed: callers must treat this as "verification unavailable", never
    as a valid signature.
    """


class EoaVerificationRequired(Exception):
    """Sentinel raised by ``verify_signature`` for an account with empty code.

    The module performs no local ``ecrecover``; the caller catches this and
    runs its own EOA path (``method="eoa"``).
    """


def _normalize_address(address: str) -> str:
    if not isinstance(address, str):
        raise ValueError("Address must be a 0x-prefixed hex string")
    value = address.strip().lower()
    if not value.startswith("0x") or len(value) != 2 + _ADDRESS_HEX_LEN:
        raise ValueError("Address must be a 20-byte 0x-prefixed hex string")
    try:
        bytes.fromhex(value[2:])
    except ValueError:
        raise ValueError("Address must be a 20-byte 0x-prefixed hex string") from None
    return value


def _normalize_hex(value: str, label: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a 0x-prefixed hex string")
    text = value.strip()
    if not text.startswith("0x") or len(text) % 2 != 0:
        raise ValueError(f"{label} must be a 0x-prefixed hex string of even length")
    try:
        return bytes.fromhex(text[2:])
    except ValueError:
        raise ValueError(f"{label} must be a 0x-prefixed hex string") from None


# ---------------------------------------------------------------------------
# account code + EIP-7702 delegation indicator
# ---------------------------------------------------------------------------


async def account_code(w3: Any, address: str) -> str:
    """Return the account's code via ``eth_getCode`` as lowercase hex.

    ``"0x"`` is returned for an EOA or any account with empty code.
    Raises :class:`WalletAccountRPCError` on RPC/transport failure.
    """
    normalized = _normalize_address(address)
    try:
        raw = await w3.eth.get_code(normalized)
    except Exception as exc:  # transport/RPC failure — fail closed
        raise WalletAccountRPCError(f"eth_getCode failed for {normalized}: {exc}") from exc
    return "0x" + bytes(raw).hex()


def delegation_indicator(code: str) -> dict:
    """Classify account code against the strict EIP-7702 indicator form.

    See the module docstring for the exact rule and the meaning of
    ``indicator_malformed``.
    """
    result = {"delegated": False, "delegate": None, "indicator_malformed": False}
    try:
        raw = _normalize_hex(code, "code")
    except ValueError:
        # Non-hex/odd-length code cannot carry an indicator; ordinary code path.
        return result
    if not raw.startswith(_DELEGATION_PREFIX_BYTES):
        return result
    if len(raw) != _INDICATOR_TOTAL_LEN:
        result["indicator_malformed"] = True
        return result
    payload = raw[len(_DELEGATION_PREFIX_BYTES) :]
    if payload[20:] != b"\x00" * (len(payload) - 20):
        result["indicator_malformed"] = True
        return result
    result["delegated"] = True
    result["delegate"] = "0x" + payload[:20].hex()
    return result


# ---------------------------------------------------------------------------
# ERC-6492 wrapper parsing
# ---------------------------------------------------------------------------


def parse_erc6492(signature: str) -> dict | None:
    """Parse an ERC-6492 counterfactual signature wrapper (see module docstring).

    Returns ``None`` when the magic suffix is absent. Raises ``ValueError`` on
    any structural inconsistency when the suffix is present.
    """
    raw = _normalize_hex(signature, "signature")
    pos = raw.rfind(_MAGIC_SUFFIX_BYTES)
    if pos == -1:
        return None
    if pos != len(raw) - len(_MAGIC_SUFFIX_BYTES):
        raise ValueError("ERC-6492 wrapper has trailing junk after the magic suffix")
    body = raw[:pos]
    if len(body) < 32 + 20 + 1:
        raise ValueError("ERC-6492 wrapper too short")
    length = int.from_bytes(body[-32:], "big")
    rest = body[:-32]
    if len(rest) < length + 20:
        raise ValueError("ERC-6492 wrapper length prefix overruns the signature")
    data_to_sign = rest[-length:] if length else b""
    rest = rest[: len(rest) - length]
    contract_address = rest[-20:]
    inner_signature = rest[:-20]
    if not inner_signature:
        raise ValueError("ERC-6492 wrapper has an empty inner signature")
    return {
        "contract_address": "0x" + contract_address.hex(),
        "data_to_sign": "0x" + data_to_sign.hex(),
        "inner_signature": "0x" + inner_signature.hex(),
    }


# ---------------------------------------------------------------------------
# signature verification
# ---------------------------------------------------------------------------


def _encode_is_valid_signature_call(digest: bytes, signature: bytes) -> str:
    """ABI-encode ``isValidSignature(bytes32,bytes)`` call data."""
    if len(digest) != 32:
        raise ValueError("Digest must be exactly 32 bytes")
    if not signature:
        raise ValueError("Signature must be non-empty")
    head = _IS_VALID_SIGNATURE_SELECTOR + digest + (0x40).to_bytes(32, "big") + len(signature).to_bytes(32, "big")
    padding = (-len(signature)) % 32
    return (head + signature + b"\x00" * padding).hex()


def _is_magic_value(raw: bytes) -> bool:
    return raw == _MAGIC_VALUE_BYTES


async def _call_is_valid_signature(
    w3: Any, target: str, call_data: str, method: str, state_override: dict | None = None
) -> bool:
    """Run the ERC-1271 style call; map reverts to invalid, transport errors to raise."""
    tx: dict = {"to": target, "data": "0x" + call_data}
    kwargs: dict = {}
    if state_override is not None:
        kwargs["state_override"] = state_override
    try:
        raw = await w3.eth.call(tx, **kwargs)
    except (ContractLogicError, Web3RPCError):
        # Revert (missing selector, validation failure, ...) → invalid signature.
        return False
    except Exception as exc:  # transport/RPC failure — fail closed by raising
        raise WalletAccountRPCError(f"eth_call isValidSignature failed for {target}: {exc}") from exc
    return _is_magic_value(bytes(raw))


async def verify_signature(w3: Any, address: str, digest: bytes, signature: str) -> tuple[bool, str]:
    """Verify ``signature`` over ``digest`` for ``address`` (see module docstring).

    Returns ``(valid, method)`` with ``method`` in ``{"eoa", "erc-1271",
    "erc-6492"}``. Raises :class:`EoaVerificationRequired` for an undeployed,
    non-wrapped account (EOA sentinel for the caller's ``ecrecover`` path) and
    :class:`WalletAccountRPCError` on RPC/transport failure.
    """
    normalized = _normalize_address(address)
    if isinstance(digest, (bytes, bytearray)):
        digest_bytes = bytes(digest)
    else:
        raise ValueError("Digest must be bytes")
    if len(digest_bytes) != 32:
        raise ValueError("Digest must be exactly 32 bytes")
    signature_bytes = _normalize_hex(signature, "signature")

    try:
        wrapper = parse_erc6492(signature)
    except ValueError:
        return False, "erc-6492"

    if wrapper is not None:
        contract_address = wrapper["contract_address"]
        inner_sig = _normalize_hex(wrapper["inner_signature"], "inner_signature")
        call_data = _encode_is_valid_signature_call(digest_bytes, inner_sig)
        override = {contract_address: {"code": wrapper["data_to_sign"]}}
        valid = await _call_is_valid_signature(w3, contract_address, call_data, "erc-6492", state_override=override)
        return valid, "erc-6492"

    code = await account_code(w3, normalized)
    if code == "0x":
        raise EoaVerificationRequired(f"{normalized} has no account code; caller must verify via ecrecover (EOA path)")
    call_data = _encode_is_valid_signature_call(digest_bytes, signature_bytes)
    valid = await _call_is_valid_signature(w3, normalized, call_data, "erc-1271")
    return valid, "erc-1271"
