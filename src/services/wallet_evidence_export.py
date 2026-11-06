"""Supervisor-readable evidence export for wallet-ownership verifications.

Purpose (AIF-87 item 6): render an attestation record stored by
``WalletOwnershipService`` (schema ``clearproof-wallet-attestation-v1`` or
``clearproof-wallet-attestation-v2``) as one JSON record a supervisor can read
without re-running the verification: which address was verified, with which
method, against which EBA Travel Rule limb, with which challenge and signature,
at which times, and with what delegation re-check history. This export is
evidence of a verification event; it is not a legal opinion, not proof of
current control, and not a substitute for the CASP's own risk assessment.

Regulatory mapping. EBA/GL/2024/11 ("Travel Rule Guidelines"), section 4.8.4,
paragraph 83 reads verbatim:

    83. In order to assess whether the self-hosted address is owned or
    controlled by the originator or beneficiary, respectively, CASPs should use
    at least one of the following verification methods:
    a) unattended verifications as specified in the Guidelines on the use of
       Remote Customer Onboarding Solutions under Article 13(1) of Directive
       (EU) 2015/849 displaying the address;
    b) attended verification as specified in the Guidelines on the use of
       Remote Customer Onboarding Solutions under Article 13(1) of Directive
       (EU) 2015/849;
    c) sending of a predefined amount (preferably the smallest denomination of
       a given crypto-asset), set by the CASP, from and to the self-hosted
       address to the CASP's account;
    d) requesting the customer to digitally sign a specific message into the
       account and wallet software with the key corresponding to that address;
    e) other suitable technical means as long as they allow for reliable and
       secure assessment and the CASP is fully satisfied that it knows who owns
       or controls the address.

Mapping used by :func:`eba_limb_for`:

==================  ===========  ==========================================================
Method string       EBA limb     Rationale
==================  ===========  ==========================================================
``eoa``             ¶83(d)       EIP-191 signature over a canonical challenge (v1) or a
                                 SIWE message (v2) is exactly "digitally sign a specific
                                 message ... with the key corresponding to that address".
``erc-1271``        ¶83(e)       Smart-contract wallet signature verification (EIP-1271
                                 / ERC-1271 ``isValidSignature``).
``erc-6492``        ¶83(e)       Counterfactual (pre-deployment) contract wallet
                                 signature verification.
==================  ===========  ==========================================================

Honest limits, marked as uncertain rather than papered over:

* The Guidelines do not name ERC-1271 or ERC-6492. Mapping smart-contract
  wallet control checks to the ¶83(e) catch-all is OUR interpretation, not EBA
  guidance; a supervisor may reasonably disagree.
* The final Guidelines number the methods a) through e). Secondary commentary
  sometimes cites "(i)/(ii)/(iii)" limbs; we cite the final text verbatim and
  do not invent numbering. The Guidelines' wallet-verification methods live in
  section 4.8.4 of the Guidelines text, not in its Annex I, which lists
  information fields.
* ¶83(d) speaks of "the key corresponding to that address". A smart-contract
  wallet, or an EOA delegated under EIP-7702, may not have such a key in the
  plain sense; this exporter never upgrades a method to a stronger limb than
  the method itself evidences, and never asserts legal ownership.
* A delegation re-check history documents what was observed at each check. It
  does not establish who beneficially owns or controls the wallet.

The exporter is pure and synchronous: no I/O, no clock, no network. Fields the
source record does not contain are exported as ``null`` and are never
fabricated. Malformed input raises :class:`ValueError` (fail closed).
``generated_at`` is exported as ``null``; the caller must fill it at export
time because a pure module has no clock.
"""

_RECORD_VERSION = "clearproof-evidence-export-v1"
_ATTESTATION_V1 = "clearproof-wallet-attestation-v1"
_ATTESTATION_V2 = "clearproof-wallet-attestation-v2"
_KNOWN_SCHEMAS = (_ATTESTATION_V1, _ATTESTATION_V2)

_EBA_SOURCE = "EBA/GL/2024/11 (Travel Rule Guidelines), section 4.8.4, paragraph 83"
_LIMB_D_QUOTE = (
    "requesting the customer to digitally sign a specific message into the account and wallet software with the "
    "key corresponding to that address;"
)
_LIMB_E_QUOTE = (
    "other suitable technical means as long as they allow for reliable and secure assessment and the CASP is "
    "fully satisfied that it knows who owns or controls the address."
)

_LIMBS = {
    "eoa": {
        "paragraph": "83(d)",
        "quote": _LIMB_D_QUOTE,
        "note": (
            "Verbatim limb text. A Clearproof EOA verification signs a canonical challenge message with EIP-191 "
            "personal_sign (attestation v1) or a SIWE message (attestation v2)."
        ),
    },
    "erc-1271": {
        "paragraph": "83(e)",
        "quote": _LIMB_E_QUOTE,
        "note": (
            "Verbatim limb text. The Guidelines do not name ERC-1271; mapping contract-wallet signature "
            "verification to this catch-all is our interpretation and is marked uncertain."
        ),
    },
    "erc-6492": {
        "paragraph": "83(e)",
        "quote": _LIMB_E_QUOTE,
        "note": (
            "Verbatim limb text. The Guidelines do not name ERC-6492; mapping counterfactual contract-wallet "
            "signature verification to this catch-all is our interpretation and is marked uncertain."
        ),
    },
}

# Tolerant alias sets for attestation-v2 fields, which are authored concurrently
# and may not be frozen yet. The first present key wins; absence exports as null.
_METHOD_KEYS = ("verification_method", "method", "wallet_verification_method")
_MESSAGE_KEYS = ("siwe_message", "message", "challenge_message")
_RECORDED_DELEGATION_KEYS = ("delegation", "delegation_status")


def eba_limb_for(method: str) -> dict:
    """Map a wallet verification method to its EBA/GL/2024/11 paragraph 83 limb.

    Returns a dict with ``paragraph`` (for example ``"83(d)"``), ``quote`` (the
    verbatim limb text), ``source`` and ``note``. Unknown methods raise
    :class:`ValueError` rather than being silently mapped to a limb.
    """
    if type(method) is not str:
        raise ValueError("Wallet verification method must be a string")
    limb = _LIMBS.get(method.strip().lower())
    if limb is None:
        raise ValueError(f"Unknown wallet verification method: {method!r}")
    return {
        "paragraph": limb["paragraph"],
        "quote": limb["quote"],
        "source": _EBA_SOURCE,
        "note": limb["note"],
    }


def _first_present(record: dict, keys: tuple[str, ...]):
    for key in keys:
        if key in record:
            return record[key]
    return None


def _require_str(value, label: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"Attestation record requires a non-empty string {label}")
    return value


def _require_int(value, label: str) -> int:
    if type(value) is not int:
        raise ValueError(f"Attestation record requires an integer {label}")
    return value


def _method_and_limb(attestation: dict, schema: str) -> tuple[str, dict]:
    method = _first_present(attestation, _METHOD_KEYS)
    if method is None:
        if schema != _ATTESTATION_V1:
            raise ValueError("Attestation record requires a verification method")
        # The v1 profile supports exactly one method: an EIP-191 signature by the
        # subject EOA over the canonical challenge (contract wallets unsupported).
        method = "eoa"
    if type(method) is not str:
        raise ValueError("Attestation record requires a string verification method")
    return method, eba_limb_for(method)


def _challenge_text(attestation: dict, challenge: dict):
    text = _first_present(attestation, _MESSAGE_KEYS)
    if text is None:
        text = _first_present(challenge, _MESSAGE_KEYS)
    return text if type(text) is str else None


def _delegation_section(history: list[dict] | None) -> dict | None:
    if history is None:
        return None
    if not isinstance(history, list):
        raise ValueError("Delegation history must be a list of entries")
    entries = []
    for index, entry in enumerate(history):
        if not isinstance(entry, dict):
            raise ValueError(f"Delegation history entry {index} must be an object")
        checked_at = _require_int(entry.get("checked_at"), f"delegation history entry {index} checked_at")
        delegated = entry.get("delegated")
        if type(delegated) is not bool:
            raise ValueError(f"Delegation history entry {index} requires a boolean delegated flag")
        normalized = {"checked_at": checked_at, "delegated": delegated, "delegate": None, "reason": None}
        for key in ("delegate", "reason"):
            value = entry.get(key)
            if value is not None and type(value) is not str:
                raise ValueError(f"Delegation history entry {index} requires a string or null {key}")
            normalized[key] = value
        entries.append(normalized)
    newest = max(range(len(entries)), key=lambda index: entries[index]["checked_at"]) if entries else None
    return {"status": None if newest is None else entries[newest], "history": entries}


def _credential_section(challenge: dict, credential_ref: dict | None) -> dict:
    credential = challenge.get("credential")
    linkage: dict = {}
    if isinstance(credential, dict):
        for key in ("credential_nonce", "issuer_did", "tenant_id"):
            if key in credential:
                linkage[key] = credential[key]
    if credential_ref is not None:
        if not isinstance(credential_ref, dict):
            raise ValueError("Credential reference must be an object")
        linkage["reference"] = dict(credential_ref)
    return linkage


def export_evidence(
    attestation: dict,
    delegation_history: list[dict] | None = None,
    credential_ref: dict | None = None,
) -> dict:
    """Render a stored wallet-ownership attestation as a supervisor-readable record.

    ``attestation`` is the dict stored by ``WalletOwnershipService`` under
    schema ``clearproof-wallet-attestation-v1`` or ``-v2``. ``delegation_history``
    is an optional list of ``{checked_at, delegated, delegate, reason}`` entries
    ordered as recorded; ``credential_ref`` optionally links the verification to
    an issued credential or enrollment record. Missing source fields are
    exported as ``null``; malformed input raises :class:`ValueError`.
    """
    if not isinstance(attestation, dict):
        raise ValueError("Attestation record must be an object")
    schema = attestation.get("schema_version")
    if schema not in _KNOWN_SCHEMAS:
        raise ValueError(f"Attestation record has an unsupported schema_version: {schema!r}")
    challenge = attestation.get("challenge")
    if not isinstance(challenge, dict):
        raise ValueError("Attestation record requires a challenge object")
    credential = challenge.get("credential")
    if not isinstance(credential, dict):
        raise ValueError("Attestation challenge requires a credential object")
    subject_address = _require_str(credential.get("subject_wallet"), "credential subject_wallet")
    signature = _require_str(attestation.get("signature"), "signature")
    method, limb = _method_and_limb(attestation, schema)
    if method.strip().lower() == "eoa" and (len(signature) != 132 or not signature.startswith("0x")):
        raise ValueError("EOA attestation requires a 65-byte 0x-prefixed signature")
    verified_at = _require_int(attestation.get("issued_at"), "issued_at")
    attestation_expires_at = _require_int(attestation.get("expires_at"), "expires_at")
    challenge_issued_at = _require_int(challenge.get("timestamp"), "challenge timestamp")
    challenge_expires_at = challenge.get("expires_at")
    if challenge_expires_at is not None:
        challenge_expires_at = _require_int(challenge_expires_at, "challenge expires_at")

    delegation = _delegation_section(delegation_history)
    if delegation is not None:
        delegation["recorded_status"] = _first_present(attestation, _RECORDED_DELEGATION_KEYS)

    return {
        "record_version": _RECORD_VERSION,
        "schema_version": schema,
        "attestation_id": attestation.get("attestation_id"),
        "subject_address": subject_address,
        "verification_method": method,
        "eba_limb": limb,
        "challenge": _challenge_text(attestation, challenge),
        "challenge_issued_at": challenge_issued_at,
        "challenge_expires_at": challenge_expires_at,
        "signature": signature,
        "verified_at": verified_at,
        "attestation_expires_at": attestation_expires_at,
        "delegation": delegation,
        "credential": _credential_section(challenge, credential_ref),
        "tenant_id": challenge.get("tenant_id"),
        "actor_id": challenge.get("actor_id"),
        "chain_id": challenge.get("chain_id"),
        "registry_address": challenge.get("registry_address"),
        "generated_at": None,
    }
