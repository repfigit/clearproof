#!/usr/bin/env python3
"""
Generate an X25519 keypair for HPKE v2 PII envelopes (RFC 9180).

Usage:
    python scripts/hpke_keygen.py

Prints the environment variables to configure:
    VASP_HPKE_PRIVATE_KEY  — keep secret; opens envelopes addressed to you
    VASP_HPKE_PUBLIC_KEY   — published via /.well-known/clearproof.json
"""

from __future__ import annotations

import base64
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.sar.hpke_envelope import derive_key_id, generate_keypair  # noqa: E402


def main() -> None:
    priv, pub = generate_keypair()
    b64 = lambda b: base64.urlsafe_b64encode(b).decode("ascii")  # noqa: E731
    print("# HPKE v2 keypair (X25519) — store the private key in your secrets manager")
    print(f"VASP_HPKE_PRIVATE_KEY={b64(priv)}")
    print(f"VASP_HPKE_PUBLIC_KEY={b64(pub)}")
    print(f"# key id (kid fingerprint): {derive_key_id(pub)}")


if __name__ == "__main__":
    main()
