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

from src.api.routes.auth import router as auth_router
from src.api.routes.credential import router as credential_router
from src.api.routes.discovery import router as discovery_router
from src.api.routes.enrollment import router as enrollment_router
from src.api.routes.events import router as events_router
from src.api.routes.fireblocks import router as fireblocks_router
from src.api.routes.health import router as health_router
from src.api.routes.pilot_proof import router as pilot_proof_router
from src.api.routes.policy import router as policy_router
from src.api.routes.proof import router as proof_router
from src.storage.database import Database

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown hooks."""
    logger.info(
        "ZK Travel Rule Compliance Bridge starting — version %s",
        app.version,
    )
    logger.info("Circuit artifacts dir: %s", os.getenv("CIRCUIT_ARTIFACTS_DIR", "./artifacts"))

    pii_key = os.getenv("PII_MASTER_KEY", "")
    if not pii_key:
        raise RuntimeError(
            "PII_MASTER_KEY environment variable is required. Set a stable 32+ byte key for PII encryption."
        )
    is_valid_hex = len(pii_key) == 64
    if is_valid_hex:
        try:
            bytes.fromhex(pii_key)
        except ValueError:
            is_valid_hex = False
    is_valid_utf8 = len(pii_key.encode("utf-8")) >= 32
    if not is_valid_hex and not is_valid_utf8:
        raise RuntimeError(
            "PII_MASTER_KEY does not meet minimum entropy requirements. "
            "Provide either exactly 64 hex characters (32 bytes decoded) "
            "or a value that is at least 32 bytes when UTF-8 encoded."
        )

    db_url = os.getenv("DATABASE_URL")
    if db_url:
        pool_min = int(os.getenv("DB_POOL_MIN", "2"))
        pool_max = int(os.getenv("DB_POOL_MAX", "10"))
        db = Database(pool_min=pool_min, pool_max=pool_max)
        await db.connect()
        app.state.db = db
        logger.info("Database connected")
    else:
        app.state.db = None
        logger.warning("DATABASE_URL not set — running in in-memory mode")

    yield

    db = getattr(app.state, "db", None)
    if db is not None:
        await db.close()
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

    allowed_origins = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if "*" in allowed_origins:
        logger.warning(
            "CORS_ALLOWED_ORIGINS contains '*' with allow_credentials=True. "
            "This is insecure and not permitted — removing wildcard."
        )
        allowed_origins = [o for o in allowed_origins if o != "*"]
        if not allowed_origins:
            allowed_origins = ["http://localhost:3000"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Idempotency-Key", "X-API-Key"],
    )

    app.include_router(proof_router)
    app.include_router(credential_router)
    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(discovery_router)
    app.include_router(enrollment_router)
    app.include_router(policy_router)
    app.include_router(pilot_proof_router)
    app.include_router(events_router)
    app.include_router(fireblocks_router)

    return app


app = create_app()
