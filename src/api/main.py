"""
FastAPI entrypoint for the ZK Travel Rule Compliance Bridge.

Creates the application with CORS middleware, includes all routers,
and configures startup/shutdown lifecycle events.
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.routes.proof import router as proof_router
from src.api.routes.credential import router as credential_router
from src.api.routes.health import router as health_router
from src.api.routes.auth import router as auth_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown hooks."""
    logger.info(
        "ZK Travel Rule Compliance Bridge starting — version %s",
        app.version,
    )
    logger.info("Circuit artifacts dir: %s", os.getenv("CIRCUIT_ARTIFACTS_DIR", "./artifacts"))
    yield
    logger.info("ZK Travel Rule Compliance Bridge shutting down.")


def create_app() -> FastAPI:
    """Build and return the configured FastAPI application."""
    app = FastAPI(
        title="ZK Travel Rule Compliance Bridge",
        version="0.1.0",
        description=(
            "Privacy-preserving compliance infrastructure for FATF Travel Rule obligations. "
            "Generates and verifies ZK proofs that both parties are KYC-compliant and sanctions-clear."
        ),
        lifespan=lifespan,
    )

    # --- CORS -----------------------------------------------------------
    allowed_origins = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --- Routers --------------------------------------------------------
    app.include_router(proof_router)
    app.include_router(credential_router)
    app.include_router(health_router)
    app.include_router(auth_router)

    return app


# Default application instance for `uvicorn src.api.main:app`
app = create_app()
