"""API route modules for proof, credential, health, and auth endpoints."""

from src.api.routes.proof import router as proof_router
from src.api.routes.credential import router as credential_router
from src.api.routes.health import router as health_router
from src.api.routes.auth import router as auth_router

__all__ = ["proof_router", "credential_router", "health_router", "auth_router"]
