"""
External Protocol Bridges for the ZK Travel Rule Compliance Bridge.

Provides bridge classes that translate hybrid payloads (ZK proof + encrypted PII)
into wire formats consumed by the three major Travel Rule protocols:

- TRPBridge:        TRP/OpenVASP REST bridge (HTTPS POST, JSON)
- TRISABridge:      TRISA SecureEnvelope dict builder (legacy REST-compatible)
- GRPC_TRISABridge: TRISA gRPC bridge (proto-generated, mTLS, full protocol)
- TAIP10Bridge:     TAIP-10 selective disclosure bridge (W3C Verifiable Presentations)

The GRPC_TRISA bridge implements the official TRISA Network gRPC service using
proto files from github.com/trisacrypto/trisa. For production use, prefer the
gRPC bridge over the legacy dict-based TRISABridge.
"""

from .taip10_bridge import TAIP10Bridge
from .trisa_bridge import TRISABridge
from .trp_bridge import TRPBridge
from .grpc_trisa_bridge import (
    TRISAClient,
    TRISAServer,
    SecureEnvelopeBuilder,
    TRISAError,
)

__all__ = [
    "TRPBridge",
    "TRISABridge",
    "TRISAClient",
    "TRISAServer",
    "SecureEnvelopeBuilder",
    "TRISAError",
    "TAIP10Bridge",
]
