"""Authentication failures are exercised with real tokens and request parsing."""

import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException
from starlette.requests import Request


@pytest.fixture
def auth(monkeypatch):
    monkeypatch.setenv("PII_MASTER_KEY", "a" * 64)
    monkeypatch.setenv("AUTH_MODE", "api-key")
    monkeypatch.setenv("API_KEY", "synthetic-key")
    from src.api.middleware import auth

    monkeypatch.setattr(auth, "API_KEY", "synthetic-key")
    return auth


def request(headers=()):
    return Request({"type": "http", "headers": list(headers)})


@pytest.mark.parametrize("mode", ["jwt", "siwe"])
@pytest.mark.parametrize("header", [None, b"Basic synthetic", b"Bearer"])
async def test_bearer_modes_reject_missing_or_wrong_scheme(auth, monkeypatch, mode, header):
    monkeypatch.setattr(auth, "AUTH_MODE", mode)
    headers = () if header is None else ((b"authorization", header),)
    with pytest.raises(HTTPException) as error:
        await auth.JWTAuthDependency(request(headers))
    assert error.value.status_code == 401
    assert "Missing Bearer token" in error.value.detail


async def test_unknown_authentication_mode_fails_closed(auth, monkeypatch):
    monkeypatch.setattr(auth, "AUTH_MODE", "UNSUPPORTED")
    with pytest.raises(HTTPException) as error:
        await auth.JWTAuthDependency(request(((b"x-api-key", b"synthetic-key"),)))
    assert error.value.status_code == 500
    assert error.value.detail == "Unknown AUTH_MODE: unsupported"


@pytest.mark.parametrize("configured", ["", "different-key"])
async def test_api_key_misconfiguration_or_mismatch(auth, monkeypatch, configured):
    monkeypatch.setattr(auth, "AUTH_MODE", "api-key")
    monkeypatch.setattr(auth, "API_KEY", configured)
    with pytest.raises(HTTPException) as error:
        await auth.JWTAuthDependency(request(((b"x-api-key", b"synthetic-key"),)))
    assert error.value.status_code == (500 if not configured else 401)


async def test_api_key_header_is_required(auth, monkeypatch):
    monkeypatch.setattr(auth, "AUTH_MODE", "api-key")
    with pytest.raises(HTTPException) as error:
        await auth.JWTAuthDependency(request())
    assert error.value.status_code == 401
    assert error.value.detail == "Missing X-API-Key header"


async def test_api_key_success_returns_minimal_claims(auth, monkeypatch):
    monkeypatch.setattr(auth, "AUTH_MODE", "API-KEY")
    monkeypatch.setattr(auth.time, "time", lambda: 1000)
    assert await auth.JWTAuthDependency(request(((b"x-api-key", b"synthetic-key"),))) == {
        "sub": "api-key-user",
        "iat": 1000,
    }


def test_missing_jwt_dependency_reports_server_configuration_failure(auth, monkeypatch):
    monkeypatch.setitem(sys.modules, "jwt", None)
    with pytest.raises(HTTPException) as error:
        auth.verify_jwt_token("synthetic")
    assert error.value.status_code == 500
    assert "PyJWT not installed" in error.value.detail


def test_missing_jwt_public_key_reports_server_configuration_failure(auth, monkeypatch):
    monkeypatch.setattr(auth, "JWT_PUBLIC_KEY", None)
    with pytest.raises(HTTPException) as error:
        auth.verify_jwt_token("synthetic")
    assert error.value.status_code == 500
    assert "JWT_PUBLIC_KEY" in error.value.detail


@pytest.mark.parametrize("state", ["valid", "expired", "wrong-signature"])
async def test_real_es256_token_verification(auth, monkeypatch, state):
    import time

    import jwt

    private = ec.generate_private_key(ec.SECP256R1())
    public = (
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    monkeypatch.setattr(auth, "JWT_PUBLIC_KEY", public)
    monkeypatch.setattr(auth, "AUTH_MODE", "jwt")
    now = int(time.time())
    claims = {
        "sub": "synthetic-subject",
        "iss": auth.JWT_ISSUER,
        "aud": auth.JWT_AUDIENCE,
        "iat": now - 60,
        "exp": now - 1 if state == "expired" else now + 3600,
    }
    signing_key = ec.generate_private_key(ec.SECP256R1()) if state == "wrong-signature" else private
    token = jwt.encode(claims, signing_key, algorithm="ES256")
    incoming = request(((b"authorization", ("Bearer " + token).encode()),))
    if state == "valid":
        assert await auth.JWTAuthDependency(incoming) == claims
    else:
        with pytest.raises(HTTPException) as error:
            await auth.JWTAuthDependency(incoming)
        assert error.value.status_code == 401
        if state == "expired":
            assert error.value.detail == "Token expired"
        else:
            assert "Invalid token" in error.value.detail
