# Well-Known clearproof Discovery Spec

## Overview

Any VASP that supports clearproof publishes a JSON document at:

```
https://<vasp-domain>/.well-known/clearproof.json
```

This enables plug-and-play discovery. A new VASP publishes one file and registers on-chain — they're immediately discoverable by every participant in the network.

## Schema

```json
{
  "version": "0.2.0",
  "vasp": {
    "name": "Example Exchange",
    "did": "did:web:exchange.example",
    "jurisdiction": "702"
  },
  "clearproof": {
    "endpoint": "https://exchange.example/clearproof/v1",
    "publicKey": "age1...",
    "supportedChains": [1, 42161, 8453, 137, 10],
    "supportedVersions": ["0.2.0"],
    "proofFormat": "groth16"
  },
  "contact": {
    "compliance": "compliance@exchange.example",
    "technical": "devops@exchange.example"
  },
  "updatedAt": "2026-04-01T00:00:00Z"
}
```

## Field Reference

### Required fields

| Field | Type | Description |
| --- | --- | --- |
| `version` | string | clearproof protocol version |
| `clearproof.endpoint` | string | HTTPS URL for proof exchange API |
| `clearproof.publicKey` | string | Public key for PII encryption (age or X25519) |
| `clearproof.supportedChains` | number[] | EVM chain IDs where this VASP accepts proofs |

### Optional fields

| Field | Type | Description |
| --- | --- | --- |
| `vasp.name` | string | Display name |
| `vasp.did` | string | Decentralized identifier |
| `vasp.jurisdiction` | string | ISO 3166-1 numeric code |
| `clearproof.supportedVersions` | string[] | Protocol versions accepted (default: latest) |
| `clearproof.proofFormat` | string | Always "groth16" for now |
| `contact.compliance` | string | Email for compliance inquiries |
| `contact.technical` | string | Email for technical support |
| `updatedAt` | string | ISO 8601 timestamp of last update |

## Discovery Flow

```
1. Originating VASP knows counterparty domain (from address-to-VASP lookup)
2. Fetch https://counterparty.example/.well-known/clearproof.json
3. Verify the counterparty supports the required chain and version
4. Use endpoint + publicKey to send hybrid payload
```

If the well-known URL returns 404, the counterparty does not support clearproof. Fall back to standard Travel Rule exchange (TRISA/TRP cleartext).

## Trust Model

The well-known URL provides **self-declared** capability information. It is secured by TLS (the VASP controls their domain) but not independently verified.

For higher trust, verify the VASP is also registered in the **on-chain VASPRegistry**. The registry entry's `discoveryEndpoint` should match the domain serving the well-known file.

```
Trust levels:
  1. Well-known only     — self-declared, TLS-secured
  2. Well-known + on-chain — verified registration, immutable audit trail
```

## Key Rotation

To rotate the encryption public key, the VASP updates their `clearproof.json` file. No on-chain transaction needed. The `updatedAt` field signals when the key changed.

Clients should cache the well-known response with a TTL of 1 hour and re-fetch on cache miss.

## CORS

The well-known endpoint should include CORS headers to allow browser-based clients:

```
Access-Control-Allow-Origin: *
```

This is safe because the document contains only public discovery information.

## Content-Type

Serve as `application/json` with UTF-8 encoding.
