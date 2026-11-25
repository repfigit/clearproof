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

    The strict Pectra EIP-7702 delegation designation form enforced here is::

        0xef0100 || delegate (20 bytes)

    i.e. 23 bytes total (3-byte ``0xef0100`` prefix followed by a 20-byte
    delegate address). Code that starts with ``0xef0100`` but does not match
    this exact 23-byte form is NOT a valid delegation indicator: it is reported
    with ``delegated=False`` and ``indicator_malformed=True``. Code without the
    ``0xef0100`` prefix is ordinary contract code: ``delegated=False``,
    ``indicator_malformed=False``.

    ``delegate`` is the extracted address as lowercase ``0x``-prefixed hex
    (``None`` unless ``delegated`` is True).

``is_erc6492_signature(signature) -> bool``
    Return True when ``signature`` is valid even-length ``0x``-prefixed hex
    ending with the 32-byte ERC-6492 magic suffix.

``parse_erc6492(signature) -> dict | None``
    Parse a canonical EIP-6492 counterfactual signature wrapper::

        abi.encode(address factory, bytes factoryCalldata, bytes innerSignature)
            || MAGIC_SUFFIX

    where ``MAGIC_SUFFIX`` is the 32-byte constant
    ``0x6492649264926492649264926492649264926492649264926492649264926492``.
    Returns ``None`` when the magic suffix is absent (an ordinary signature).
    Raises ``ValueError`` when the suffix is present (or appears with trailing
    bytes) and the payload is not canonical ABI encoding, has a zero factory
    address, empty factory calldata, or an empty inner signature.

``verify_signature(w3, address, digest, signature) -> (valid, method)``
    Unified verification. ``method`` is one of ``"eoa"``, ``"erc-1271"``,
    ``"erc-6492"``.

    - If ``signature`` carries the ERC-6492 magic suffix, the ERC-6492 path
      wins regardless of current account code. The wrapper is parsed strictly;
      a structurally invalid wrapper is ``(False, "erc-6492")`` (fail closed,
      not an exception). A valid wrapper is verified via a deployless
      ``eth_call`` (no ``to`` address, no ``state_override``, no caller-supplied
      runtime bytecode): the validator deploys the account via the on-chain
      ``factory.call(factoryCalldata)`` if ``address`` has no code, verifies
      that code was actually deployed at ``address``, and staticcalls
      ``address.isValidSignature(digest, innerSignature)``.
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

from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_abi.exceptions import DecodingError
from web3.exceptions import ContractLogicError, Web3RPCError

# ERC-1271 magic return value of isValidSignature(bytes32,bytes).
ERC_1271_MAGIC_VALUE = "0x1626ba7e"
_IS_VALID_SIGNATURE_SELECTOR = bytes.fromhex("1626ba7e")

# EIP-6492 32-byte magic suffix and EIP-7702 3-byte delegation prefix.
ERC_6492_MAGIC_SUFFIX = "0x" + "6492" * 16
EIP7702_DELEGATION_PREFIX = "0xef0100"

_MAGIC_VALUE_BYTES = bytes.fromhex("1626ba7e" + "00" * 28)
_MAGIC_SUFFIX_BYTES = bytes.fromhex("6492" * 16)
_ERC6492_VALID_RETURN = (1).to_bytes(32, "big")
_DELEGATION_PREFIX_BYTES = bytes.fromhex("ef0100")

# EIP-7702 delegation designation (Pectra): 3-byte prefix (0xef0100) + 20-byte
# delegate address = 23 bytes total.
_DELEGATE_ADDR_LEN = 20
_INDICATOR_TOTAL_LEN = len(_DELEGATION_PREFIX_BYTES) + _DELEGATE_ADDR_LEN  # 23

_ADDRESS_HEX_LEN = 40
_ZERO_ADDRESS = "0x" + "00" * 20

# Apache-2.0 deployless ERC-6492 validator creation bytecode (Solidity 0.8.24,
# optimizer runs=200, evmVersion=paris, metadata.bytecodeHash=none).
# Constructor(address signer, bytes32 hash, address factory, bytes factoryCalldata, bytes innerSignature):
#   - Requires signer != 0 and innerSignature.length > 0.
#   - If signer.code.length == 0: requires factory != 0, factory.code.length > 0,
#     factoryCalldata.length > 0, calls factory.call(factoryCalldata), and
#     requires signer.code.length > 0 afterwards.
#   - Staticcalls signer.isValidSignature(hash, innerSignature) and checks the
#     32-byte return equals bytes32(bytes4(0x1626ba7e)).
#   - Returns 32-byte ABI bool (0x00..01 or 0x00..00) from constructor.
_ERC6492_DEPLOYLESS_BYTECODE = bytes.fromhex(
    "608060405234801561001057600080fd5b506040516103fd3803806103fd83398101604081"
    "905261002f916102f0565b60006001600160a01b0386161580159061004a57506000825111"
    "5b1561013457856001600160a01b03163b600003610126576001600160a01b038416158015"
    "9061008357506000846001600160a01b03163b115b8015610090575060008351115b156101"
    "21576000846001600160a01b0316846040516100af919061037f565b600060405180830381"
    "6000865af19150503d80600081146100ec576040519150601f19603f3d011682016040523d"
    "82523d6000602084013e6100f1565b606091505b5050905080801561010c57506000876001"
    "600160a01b03163b115b1561011f5761011c87878561013e565b91505b505b610134565b61"
    "013186868461013e565b90505b8060005260206000f35b6000806000856001600160a01b03"
    "16631626ba7e60e01b868660405160240161016892919061039b565b60408051601f198184"
    "030181529181526020820180516001600160e01b03166001600160e01b0319909416939093"
    "1790925290516101a6919061037f565b600060405180830381855afa9150503d8060008114"
    "6101e1576040519150601f19603f3d011682016040523d82523d6000602084013e6101e656"
    "5b606091505b50915091508180156101f9575080516020145b80156102135750630b135d3f"
    "60e11b610211826103d5565b145b9695505050505050565b80516001600160a01b03811681"
    "1461023457600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b"
    "60005b8381101561026a578181015183820152602001610252565b50506000910152565b60"
    "0082601f83011261028457600080fd5b81516001600160401b038082111561029e5761029e"
    "610239565b604051601f8301601f19908116603f011681019082821181831017156102c657"
    "6102c6610239565b816040528381528660208588010111156102df57600080fd5b61021384"
    "602083016020890161024f565b600080600080600060a0868803121561030857600080fd5b"
    "6103118661021d565b9450602086015193506103266040870161021d565b60608701519093"
    "506001600160401b038082111561034357600080fd5b61034f89838a01610273565b935060"
    "8088015191508082111561036557600080fd5b5061037288828901610273565b9150509295"
    "509295909350565b6000825161039181846020870161024f565b9190910192915050565b82"
    "815260406020820152600082518060408401526103c081606085016020870161024f565b60"
    "1f01601f1916919091016060019392505050565b805160208083015191908110156103f657"
    "6000198160200360031b1b821691505b5091905056fe"
)


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
    """Classify account code against the strict 23-byte EIP-7702 indicator form.

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
    result["delegated"] = True
    result["delegate"] = "0x" + raw[len(_DELEGATION_PREFIX_BYTES) :].hex()
    return result


# ---------------------------------------------------------------------------
# ERC-6492 wrapper parsing
# ---------------------------------------------------------------------------


def is_erc6492_signature(signature: str) -> bool:
    """Return True if ``signature`` ends with the 32-byte EIP-6492 magic suffix."""
    try:
        raw = _normalize_hex(signature, "signature")
    except ValueError:
        return False
    return raw.endswith(_MAGIC_SUFFIX_BYTES)


def parse_erc6492(signature: str) -> dict | None:
    """Parse a canonical EIP-6492 counterfactual signature wrapper.

    Wrapper layout::

        abi.encode(address factory, bytes factoryCalldata, bytes innerSignature)
            || ERC_6492_MAGIC_SUFFIX (32 bytes)

    Returns ``None`` when the magic suffix is absent. Raises ``ValueError`` on
    any structural or canonical-encoding inconsistency when the suffix appears.
    """
    raw = _normalize_hex(signature, "signature")
    pos = raw.rfind(_MAGIC_SUFFIX_BYTES)
    if pos == -1:
        return None
    if pos != len(raw) - len(_MAGIC_SUFFIX_BYTES):
        raise ValueError("ERC-6492 wrapper has trailing junk after the magic suffix")
    body = raw[:pos]
    try:
        factory, factory_calldata, inner_signature = abi_decode(["address", "bytes", "bytes"], body)
    except (DecodingError, ValueError) as exc:
        raise ValueError("ERC-6492 wrapper ABI payload is malformed") from exc
    if abi_encode(["address", "bytes", "bytes"], [factory, factory_calldata, inner_signature]) != body:
        raise ValueError("ERC-6492 wrapper ABI payload is noncanonical")
    factory_addr = factory.lower()
    if factory_addr == _ZERO_ADDRESS:
        raise ValueError("ERC-6492 wrapper factory address cannot be zero")
    if not factory_calldata:
        raise ValueError("ERC-6492 wrapper has empty factory calldata")
    if not inner_signature:
        raise ValueError("ERC-6492 wrapper has an empty inner signature")
    return {
        "factory": factory_addr,
        "factory_calldata": "0x" + factory_calldata.hex(),
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


def _encode_erc6492_deployless_call(
    signer: str, digest: bytes, factory: str, factory_calldata: bytes, inner_signature: bytes
) -> str:
    """Encode deployless eth_call initcode for ERC6492DeploylessValidator."""
    args = abi_encode(
        ["address", "bytes32", "address", "bytes", "bytes"],
        [signer, digest, factory, factory_calldata, inner_signature],
    )
    return "0x" + (_ERC6492_DEPLOYLESS_BYTECODE + args).hex()


def _is_magic_value(raw: bytes) -> bool:
    return raw == _MAGIC_VALUE_BYTES


async def _call_is_valid_signature(w3: Any, target: str, call_data: str) -> bool:
    """Run the ERC-1271 call; map reverts to invalid, transport errors to raise."""
    tx: dict = {"to": target, "data": "0x" + call_data}
    try:
        raw = await w3.eth.call(tx)
    except (ContractLogicError, Web3RPCError):
        # Revert (missing selector, validation failure, ...) → invalid signature.
        return False
    except Exception as exc:  # transport/RPC failure — fail closed by raising
        raise WalletAccountRPCError(f"eth_call isValidSignature failed for {target}: {exc}") from exc
    return _is_magic_value(bytes(raw))


async def _call_erc6492_validator(
    w3: Any, signer: str, digest: bytes, factory: str, factory_calldata: bytes, inner_signature: bytes
) -> bool:
    """Run the deployless ERC-6492 eth_call without state_override."""
    tx: dict = {"data": _encode_erc6492_deployless_call(signer, digest, factory, factory_calldata, inner_signature)}
    try:
        raw = await w3.eth.call(tx)
    except (ContractLogicError, Web3RPCError):
        return False
    except Exception as exc:  # transport/RPC failure — fail closed by raising
        raise WalletAccountRPCError(f"eth_call ERC-6492 validation failed for {signer}: {exc}") from exc
    return bytes(raw) == _ERC6492_VALID_RETURN


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
        factory_calldata = _normalize_hex(wrapper["factory_calldata"], "factory_calldata")
        inner_sig = _normalize_hex(wrapper["inner_signature"], "inner_signature")
        valid = await _call_erc6492_validator(
            w3, normalized, digest_bytes, wrapper["factory"], factory_calldata, inner_sig
        )
        return valid, "erc-6492"

    code = await account_code(w3, normalized)
    if code == "0x":
        raise EoaVerificationRequired(f"{normalized} has no account code; caller must verify via ecrecover (EOA path)")
    call_data = _encode_is_valid_signature_call(digest_bytes, signature_bytes)
    valid = await _call_is_valid_signature(w3, normalized, call_data)
    return valid, "erc-1271"
