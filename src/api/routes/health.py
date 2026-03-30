"""
Health and metrics endpoints.

GET /health  — Liveness / readiness probe.
GET /metrics — Basic operational metrics.
"""

import time

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["health"])


# ---------------------------------------------------------------------------
# In-memory metrics accumulator (replaced by Prometheus/OTEL in production)
# ---------------------------------------------------------------------------

class _MetricsStore:
    """Simple in-memory metrics for the MVP."""

    def __init__(self) -> None:
        self.proof_generated_count: int = 0
        self.proof_verified_count: int = 0
        self.proof_generation_total_ms: float = 0.0
        self.proof_verification_total_ms: float = 0.0
        self.credential_issued_count: int = 0
        self.credential_revoked_count: int = 0
        self._started_at: float = time.time()

    @property
    def avg_proof_generation_ms(self) -> float:
        if self.proof_generated_count == 0:
            return 0.0
        return self.proof_generation_total_ms / self.proof_generated_count

    @property
    def avg_proof_verification_ms(self) -> float:
        if self.proof_verified_count == 0:
            return 0.0
        return self.proof_verification_total_ms / self.proof_verified_count

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self._started_at


# Singleton — importable by other modules to record metrics.
metrics = _MetricsStore()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: int


class MetricsResponse(BaseModel):
    proof_generated_count: int
    proof_verified_count: int
    avg_proof_generation_ms: float
    avg_proof_verification_ms: float
    credential_issued_count: int
    credential_revoked_count: int
    uptime_seconds: float


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/health", response_model=HealthResponse, summary="Health check")
async def health():
    """Liveness / readiness probe. Returns 200 if the service is operational."""
    return HealthResponse(
        status="ok",
        version="0.1.0",
        timestamp=int(time.time()),
    )


@router.get("/metrics", response_model=MetricsResponse, summary="Operational metrics")
async def get_metrics():
    """
    Basic operational metrics.

    In production these are exported via OpenTelemetry / Prometheus;
    this endpoint provides a quick JSON view for debugging.
    """
    return MetricsResponse(
        proof_generated_count=metrics.proof_generated_count,
        proof_verified_count=metrics.proof_verified_count,
        avg_proof_generation_ms=round(metrics.avg_proof_generation_ms, 2),
        avg_proof_verification_ms=round(metrics.avg_proof_verification_ms, 2),
        credential_issued_count=metrics.credential_issued_count,
        credential_revoked_count=metrics.credential_revoked_count,
        uptime_seconds=round(metrics.uptime_seconds, 2),
    )
