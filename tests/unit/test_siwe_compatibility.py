"""Exercise the actual SIWE parser and EOA verifier used by API authentication."""

from datetime import datetime, timedelta, timezone

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct


def test_real_siwe_parse_and_signature_binding():
    from siwe import DomainMismatch, InvalidSignature, NonceMismatch, SiweMessage

    account = Account.create()
    now = datetime.now(timezone.utc)
    message = SiweMessage(
        domain="vasp.example",
        address=account.address,
        statement="Sign in to the local test service.",
        uri="https://vasp.example",
        version="1",
        chain_id=1,
        nonce="a1b2c3d4e5f6",
        issued_at=now.isoformat(),
        expiration_time=(now + timedelta(minutes=5)).isoformat(),
    )
    wire = message.prepare_message()
    parsed = SiweMessage.from_message(wire)
    assert parsed.prepare_message() == wire
    signature = account.sign_message(encode_defunct(text=wire)).signature.hex()
    parsed.verify(signature, domain="vasp.example", nonce="a1b2c3d4e5f6", timestamp=now)
    with pytest.raises(DomainMismatch):
        parsed.verify(signature, domain="wrong.example")
    with pytest.raises(NonceMismatch):
        parsed.verify(signature, nonce="wrongnonce")
    wrong = Account.create().sign_message(encode_defunct(text=wire)).signature.hex()
    with pytest.raises(InvalidSignature):
        parsed.verify(wrong)
