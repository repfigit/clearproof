"""
External Protocol Bridges for the ZK Travel Rule Compliance Bridge.

Provides bridge classes that translate hybrid payloads (ZK proof + encrypted PII)
into wire formats consumed by the three major Travel Rule protocols:

- TRPBridge:   TRP/OpenVASP REST bridge (HTTPS POST, JSON)
- TRISABridge: TRISA gRPC bridge (mTLS, AES-256-GCM + RSA key wrapping)
- TAIP10Bridge: TAIP-10 selective disclosure bridge (W3C Verifiable Presentations)
"""

from .taip10_bridge import TAIP10Bridge
from .trisa_bridge import TRISABridge
from .trp_bridge import TRPBridge

__all__ = ["TRPBridge", "TRISABridge", "TAIP10Bridge"]
