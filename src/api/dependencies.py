"""
Shared FastAPI dependencies for the ZK Travel Rule API.

Single source of truth for registry singletons — every router that needs a
registry resolves it through a dependency here. This eliminates the split-brain
bug where each route module constructed its own in-memory instance (AIF-80).
"""

from functools import lru_cache

from src.registry.credential_registry import CredentialRegistry


@lru_cache(maxsize=1)
def get_credential_registry() -> CredentialRegistry:
    """Return the application-wide CredentialRegistry singleton.

    Cached via ``lru_cache`` so every call site (and every request) shares
    the same in-memory instance. The cache is never evicted (maxsize=1) —
    the registry lives for the process lifetime.

    This is the **only** place in the codebase that constructs a
    ``CredentialRegistry()``. Every other module depends on this accessor.
    """
    return CredentialRegistry()
