"""Startup-loaded runtime configuration objects stored on ``app.state``.

All environment-derived API configuration (auth settings, event authorities and
investigation links, Fireblocks relay integrations, and the shared
``RecordCipher``) is loaded once during FastAPI lifespan startup and attached to
``app.state``. Route handlers and middleware read from ``request.app.state``
instead of re-parsing environment variables or constructing ``RecordCipher`` on
every request.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Mapping, Optional

import jwt
from fastapi import HTTPException, Request
from pydantic import Field, model_validator

from src.adapters.fireblocks import FireblocksBinding, FireblocksVerifier
from src.protocol.transfer import Epoch, OpaqueId, Record
from src.prover.pilot_artifacts import strict_json
from src.reconciliation.provider_links import ScopedProviderLink
from src.storage.pilot_cipher import RecordCipher

if TYPE_CHECKING:
    from src.services.event_ingestion import EventAuthority

# ---------------------------------------------------------------------------
# Auth configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True, repr=False)
class AuthConfig:
    """Authentication and static API-key principal scope loaded at startup."""

    auth_mode: str = "api-key"
    api_key: str = ""
    jwt_public_key: Optional[str] = None
    jwt_issuer: str = "zk-travel-rule"
    jwt_audience: str = "zk-travel-rule-api"
    siwe_domain: str = "localhost"
    api_key_tenant_id: Optional[str] = None
    api_key_actor_id: Optional[str] = None
    api_key_roles: tuple[str, ...] = ()
    api_key_issuer_dids: tuple[str, ...] = ()

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> AuthConfig:
        source = os.environ if env is None else env
        return cls(
            auth_mode=source.get("AUTH_MODE", "api-key"),
            api_key=source.get("API_KEY", ""),
            jwt_public_key=source.get("JWT_PUBLIC_KEY"),
            jwt_issuer=source.get("JWT_ISSUER", "zk-travel-rule"),
            jwt_audience=source.get("JWT_AUDIENCE", "zk-travel-rule-api"),
            siwe_domain=source.get("SIWE_DOMAIN", "localhost"),
            api_key_tenant_id=source.get("API_KEY_TENANT_ID"),
            api_key_actor_id=source.get("API_KEY_ACTOR_ID"),
            api_key_roles=tuple(r for r in source.get("API_KEY_ROLES", "").split(",") if r),
            api_key_issuer_dids=tuple(d for d in source.get("API_KEY_ISSUER_DIDS", "").split(",") if d),
        )


def _state_has_attr(state: Any, name: str) -> bool:
    """Return True if ``name`` was explicitly set on ``state`` (even to ``None``)."""
    backing = getattr(state, "_state", None)
    if isinstance(backing, dict):
        return name in backing
    return hasattr(state, name)


def _request_app_state(request: Optional[Request]):
    if request is None:
        return None
    try:
        app = getattr(request, "app", None)
    except KeyError:
        return None
    return getattr(app, "state", None) if app is not None else None


def get_auth_config(request: Optional[Request] = None) -> AuthConfig:
    """Return ``app.state.auth_config`` when populated, lazily resolving when absent.

    During normal serving, lifespan populates ``app.state.auth_config``. When a
    bare ``FastAPI()`` or synthetic ``Request`` is used without lifespan, this
    falls back to the legacy module-level settings in ``src.api.middleware.auth``
    and static API-key scope env vars (never raising ``AttributeError``).
    """
    state = _request_app_state(request)
    if state is not None and _state_has_attr(state, "auth_config"):
        config = getattr(state, "auth_config", None)
        if isinstance(config, AuthConfig):
            return config

    from src.api.middleware import auth as _auth

    return AuthConfig(
        auth_mode=_auth.AUTH_MODE,
        api_key=_auth.API_KEY,
        jwt_public_key=_auth.JWT_PUBLIC_KEY,
        jwt_issuer=_auth.JWT_ISSUER,
        jwt_audience=_auth.JWT_AUDIENCE,
        siwe_domain=os.environ.get("SIWE_DOMAIN", "localhost"),
        api_key_tenant_id=os.getenv("API_KEY_TENANT_ID"),
        api_key_actor_id=os.getenv("API_KEY_ACTOR_ID"),
        api_key_roles=tuple(r for r in os.getenv("API_KEY_ROLES", "").split(",") if r),
        api_key_issuer_dids=tuple(d for d in os.getenv("API_KEY_ISSUER_DIDS", "").split(",") if d),
    )


resolve_auth_config = get_auth_config


def get_siwe_auth(request: Optional[Request] = None):
    """Return ``app.state.siwe_auth`` if set, lazily constructing and caching it when absent."""
    from src.auth.siwe_auth import SIWEAuth

    state = _request_app_state(request)
    if state is not None and _state_has_attr(state, "siwe_auth"):
        existing = getattr(state, "siwe_auth", None)
        if isinstance(existing, SIWEAuth):
            return existing
    config = resolve_auth_config(request)
    instance = SIWEAuth(domain=config.siwe_domain)
    if state is not None and not _state_has_attr(state, "siwe_auth"):
        state.siwe_auth = instance
    return instance


# ---------------------------------------------------------------------------
# Event / investigation configuration
# ---------------------------------------------------------------------------


class AuthorityConfig(Record):
    authorities: tuple[Any, ...] = Field(max_length=256)


class LinkConfig(Record):
    links: tuple[ScopedProviderLink, ...] = Field(max_length=256)


def _authority_config_model() -> type[Record]:
    from src.services.event_ingestion import EventAuthority

    class _AuthorityConfig(Record):
        authorities: tuple[EventAuthority, ...] = Field(max_length=256)

    _AuthorityConfig.model_rebuild(_types_namespace={"EventAuthority": EventAuthority})
    return _AuthorityConfig


@dataclass(frozen=True)
class EventConfig:
    """Parsed pilot event authorities and optional investigation provider links.

    ``authorities`` is ``None`` when ``PILOT_EVENT_AUTHORITIES`` was unset
    (ingestion endpoints fail closed with 503 while read-only investigation
    remains available).
    """

    authorities: Optional[tuple[EventAuthority, ...]] = None
    links: tuple[ScopedProviderLink, ...] = ()

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> EventConfig:
        source = os.environ if env is None else env
        authorities: Optional[tuple[EventAuthority, ...]] = None
        if "PILOT_EVENT_AUTHORITIES" in source:
            raw = source["PILOT_EVENT_AUTHORITIES"].encode()
            strict_json(raw, limit=65536)
            authorities = _authority_config_model().model_validate_json(raw).authorities

        links: tuple[ScopedProviderLink, ...] = ()
        if "PILOT_INVESTIGATION_LINKS" in source:
            raw_links = source["PILOT_INVESTIGATION_LINKS"].encode()
            strict_json(raw_links, limit=65536)
            links = LinkConfig.model_validate_json(raw_links).links

        return cls(authorities=authorities, links=links)


# ---------------------------------------------------------------------------
# Fireblocks relay configuration
# ---------------------------------------------------------------------------


class FireblocksIntegration(Record):
    integration_id: OpaqueId
    binding: FireblocksBinding
    jwks: dict
    key_valid_from_ms: Epoch
    key_valid_until_ms: Epoch
    max_age_ms: int = Field(ge=1, le=30 * 86400000)


class FireblocksIntegrations(Record):
    integrations: tuple[FireblocksIntegration, ...] = Field(max_length=16)

    @model_validator(mode="after")
    def unique(self):
        if len({item.integration_id for item in self.integrations}) != len(self.integrations):
            raise ValueError("Duplicate integration ID")
        return self


@dataclass(frozen=True, repr=False)
class CompiledFireblocksIntegration:
    """One validated Fireblocks integration paired with its pre-built verifier."""

    integration: FireblocksIntegration
    verifier: FireblocksVerifier


@dataclass(frozen=True, repr=False)
class FireblocksConfig:
    """Startup-validated Fireblocks relay integrations indexed by integration ID."""

    integrations: tuple[FireblocksIntegration, ...] = ()
    verifiers: Mapping[str, FireblocksVerifier] = field(default_factory=dict)

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> Optional[FireblocksConfig]:
        source = os.environ if env is None else env
        if "PILOT_FIREBLOCKS_INTEGRATIONS" not in source:
            return None
        return cls.from_raw(source["PILOT_FIREBLOCKS_INTEGRATIONS"].encode())

    @classmethod
    def from_raw(cls, raw_config: bytes) -> FireblocksConfig:
        strict_json(raw_config, limit=65536)
        parsed = FireblocksIntegrations.model_validate_json(raw_config)
        verifiers: dict[str, FireblocksVerifier] = {}
        for item in parsed.integrations:
            verifiers[item.integration_id] = FireblocksVerifier(
                json.dumps(item.jwks).encode(),
                valid_from=item.key_valid_from_ms,
                valid_until=item.key_valid_until_ms,
                max_age_ms=item.max_age_ms,
            )
        return cls(integrations=parsed.integrations, verifiers=verifiers)

    def lookup(self, integration_id: str, tenant_id: str) -> Optional[CompiledFireblocksIntegration]:
        for item in self.integrations:
            if item.integration_id == integration_id and item.binding.scope.tenant_id == tenant_id:
                verifier = self.verifiers.get(item.integration_id)
                if verifier is None:
                    try:
                        verifier = FireblocksVerifier(
                            json.dumps(item.jwks).encode(),
                            valid_from=item.key_valid_from_ms,
                            valid_until=item.key_valid_until_ms,
                            max_age_ms=item.max_age_ms,
                        )
                    except (ValueError, TypeError, KeyError, RecursionError, jwt.PyJWTError) as exc:
                        raise ValueError("Fireblocks verifier unavailable") from exc
                return CompiledFireblocksIntegration(integration=item, verifier=verifier)
        return None


# ---------------------------------------------------------------------------
# Lazy-caching app.state accessors
# ---------------------------------------------------------------------------


def get_event_config(request: Request) -> Optional[EventConfig]:
    """Return ``app.state.event_config``, lazily constructing and caching it if absent.

    When lifespan has populated ``app.state.event_config`` (or a test explicitly
    sets it, including to ``None``), that value is returned without re-reading
    the environment. When the attribute is absent (e.g. a bare ``FastAPI()``
    app tested without lifespan), ``EventConfig.from_env()`` is constructed
    once and cached on ``app.state.event_config``.
    """
    state = _request_app_state(request)
    if state is None:
        return None
    if _state_has_attr(state, "event_config"):
        config = getattr(state, "event_config", None)
        return config if isinstance(config, EventConfig) else None
    config = EventConfig.from_env()
    state.event_config = config
    return config


def get_fireblocks_config(request: Request) -> Optional[FireblocksConfig]:
    """Return ``app.state.fireblocks_config``, lazily constructing and caching it if absent.

    When lifespan has populated ``app.state.fireblocks_config`` (or a test
    explicitly sets it, including to ``None``), that value is returned without
    re-reading the environment. When the attribute is absent (e.g. a bare
    ``FastAPI()`` app tested without lifespan), ``FireblocksConfig.from_env()``
    is constructed once and cached on ``app.state.fireblocks_config``.
    """
    state = _request_app_state(request)
    if state is None:
        return None
    if _state_has_attr(state, "fireblocks_config"):
        config = getattr(state, "fireblocks_config", None)
        return config if isinstance(config, FireblocksConfig) else None
    config = FireblocksConfig.from_env()
    state.fireblocks_config = config
    return config


def get_record_cipher(request: Request, *, detail: str = "Pilot encryption configuration is unavailable") -> Any:
    """Return ``request.app.state.record_cipher`` or fail closed with 503.

    Raises ``HTTPException(503)`` when the cipher has not been installed on
    ``app.state`` (for example, if startup did not populate it or a test
    explicitly clears ``app.state.record_cipher``).
    """
    state = _request_app_state(request)
    cipher = getattr(state, "record_cipher", None) if state is not None else None
    if cipher is None:
        raise HTTPException(status_code=503, detail=detail)
    return cipher


def require_record_cipher(request: Request) -> RecordCipher:
    """Return ``request.app.state.record_cipher`` or raise ``RuntimeError``.

    Used inside helpers that already map ``RuntimeError`` to their route-specific
    redacted 503 detail.
    """
    state = _request_app_state(request)
    cipher = getattr(state, "record_cipher", None) if state is not None else None
    if cipher is None:
        raise RuntimeError("RecordCipher is not configured on app.state")
    return cipher
