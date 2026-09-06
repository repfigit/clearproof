# Clearproof discovery profile 0.4.0

Status: development profile implemented on the adoption-pilot branch. This is a breaking update to the 0.3.0 discovery draft; it is not a claim that the deployed API or public npm 0.3.0 already supports it.

A counterparty publishes `https://<authority>/.well-known/clearproof.json`. The Python API and Node SDK consume the same profile and test vectors in [fixtures/discovery-0.4.0.json](fixtures/discovery-0.4.0.json). No directory enumeration or address-to-VASP lookup is provided.

## Identity and capabilities

| Field | Requirement |
| --- | --- |
| `version` | Exactly `0.4.0`; other versions are unsupported |
| `vasp.did` | Full exact requested `did:web` identity, including any path components |
| `clearproof.endpoint` | HTTPS URL on the same exact authority, with a path and no credentials, query, fragment or backslash |
| `clearproof.supportedVersions` | Nonempty unique strings, including `0.4.0`; no default negotiation |
| `clearproof.supportedChains` | 1–64 unique positive integers no larger than JavaScript's maximum safe integer |
| `clearproof.proofFormat` | `groth16` |
| `clearproof.hpkePublicKey` | Canonical base64url encoding of a usable, canonically encoded 32-byte X25519 public key; padded or unpadded |
| `clearproof.hpkeKeyId` | First 16 bytes of SHA-256 of the raw public key, canonical base64url; padded or unpadded |
| `clearproof.hpkeKeyPurpose` | Exactly `pii-envelope-v2` |
| `clearproof.hpkeSuites` | Includes `DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_256_GCM` |

Version and suite arrays contain 1–16 unique strings of 1–128 characters. Display name, jurisdiction, contact and `updatedAt` are optional informational metadata. `updatedAt` is not independent time evidence. Discovery capability versions do not identify the circuit artifact or establish its public-signal ABI; a verifier must check those separately.

This profile accepts lowercase ASCII DNS names (including punycode), optionally followed by a nondefault port. IP literals, single-label hosts, trailing dots, URL inputs and noncanonical ports are rejected. A DID port uses uppercase `%3A`, following the [did:web method's port convention](https://w3c-ccg.github.io/did-method-web/). Path components in this profile use ASCII letters, digits, `.`, `_` and `-`, and cannot be `.` or `..`. Other DID methods and broader DID URL syntax are unsupported.

A bare `beneficiary.example` means `did:web:beneficiary.example`. A request for `did:web:beneficiary.example:vasps:eu` still fetches this profile's root well-known file, but its `vasp.did` must match that entire DID. The helper does not resolve a DID document or infer control of a nested DID from a different DID on the same domain.

## Connection policy

Python uses an [HTTPcore network backend](https://www.encode.io/httpcore/network-backends/) to connect to a vetted IP while retaining the original TLS hostname. Node uses its [HTTPS request API](https://nodejs.org/api/https.html) with the vetted IP, original SNI and Host. Both clients:

- Resolve DNS for each uncached fetch, check every answer and connect directly to the first allowed address. A mixed allowed/disallowed answer set fails. Connection failure is unavailable; no fallback to an unchecked address occurs.
- Require TLS certificate and hostname verification. They ignore proxy environment variables and reject every redirect.
- Block loopback, private, link-local, shared-address, documentation, multicast and reserved destinations by default. IPv6 accepts the global-unicast range with conservative exclusions, blocking translation and mapped-address bypasses. Shared network vectors specify the policy.
- Accept only uncompressed UTF-8 `application/json`, at most 64 KiB. A whole-request deadline includes DNS, TLS and body reads (default 10 seconds, maximum 60 seconds).

An operator may explicitly allow private enterprise destinations by exact authority and CIDR. In Python, instantiate `DiscoveryClient(policy=EgressPolicy({...}))`. The API's default resolver also reads `DISCOVERY_PRIVATE_DESTINATIONS`, a JSON authority-to-CIDR map. In Node, pass `privateDestinations` to `DiscoveryClient`. For example:

```json
{"beneficiary.corp.example:8443": ["10.42.0.0/16"]}
```

These are operator trust settings, never transfer-request fields. An exception for one authority does not allow another host or port. CIDRs describe network ranges; host bits are normalized. Enterprise certificates must still validate: Python accepts an operator SSL context or system CA configuration, and Node accepts an operator CA bundle. The Node discovery transport requires Node.js; browser fetch cannot provide the same socket policy. Use a controlled server integration for browser applications.

Discovery validates the advertised endpoint's origin but does not contact it. Any later proof-exchange transport must apply its own connection policy at send time; discovery approval cannot prevent rebinding in an unrelated HTTP client.

## Results, caching and rotation

Python raises `DiscoveryUnsupported`, `DiscoveryUnavailable` or `DiscoveryInvalid`, all subclasses of `DiscoveryError`. Node throws `DiscoveryError` with `code` equal to `unsupported`, `unavailable` or `invalid`. Neither returns an ambiguous `null` or converts an error into `supportsChain=false`.

| Result | Examples | Action |
| --- | --- | --- |
| Unsupported | HTTP 404, older profile, no compatible suite/version | Establish a compatible integration explicitly |
| Unavailable | DNS/TLS failure, timeout, non-200 service error | Retry or investigate availability without changing encryption |
| Invalid | DID mismatch, malformed key, redirect, disallowed address, malformed response | Correct configuration or investigate the counterparty |

Each client owns a maximum of 128 cached successful documents, keyed by the full DID. Default TTL is five minutes, configurable from zero to one hour. Expiry uses a monotonic clock starting before the fetch. Documents returned to callers are copied. Errors are not cached and expired documents are not served after errors. Clearing a cache prevents in-flight responses from refilling it; already waiting callers still receive their original response.

Use `clear_cache()` / `clearCache()` after known key rotation. Construct a new client when changing its trust configuration. Python's default client replaces its cache when the configured authority map or CA environment paths change; restart or explicitly clear it when CA file contents change at the same path. Node helper calls with custom options are isolated; retain a `DiscoveryClient` instance for custom-policy caching.

Retain retiring private keys for the agreed envelope retention and in-flight window. A fingerprint detects a substituted key/ID pair mismatch; it is not an independent authorization for key rotation.

## Migration and API encryption

The old `publicKey` field mixed age and X25519 key representations. It is now optional informational legacy metadata and is **never** used as an HPKE key. Upgrade a publisher to the complete 0.4.0 fields before upgrading counterparties. There is no automatic interpretation of 0.2.0/0.3.0 documents as this profile.

The proof API defaults to `PII_ENVELOPE_MODE=hpke-v2`. Resolution uses a supplied HPKE key, then operator `BENEFICIARY_HPKE_PUBLIC_KEY`, then enabled DID discovery. All explicit keys use strict X25519 validation. Invalid/unsupported discovery rejects the request with HTTP 422; unavailable discovery returns HTTP 503. These checks run before proving or encrypting. No error or missing key selects legacy encryption.

For a deliberately configured legacy integration, the operator can select `PII_ENVELOPE_MODE=legacy-v1`. It does not attempt discovery, requires the existing master-key configuration and rejects supplied HPKE keys as a mode conflict. It does not make a counterparty able to decrypt without separate shared-key provisioning. Remove that mode after migration. `HPKE_DISCOVERY_ENABLED=0` disables lookup but does not permit fallback.

The publisher requires a configured HPKE key, validates its own document, derives its DID from `VASP_DOMAIN` when no DID is supplied, and rejects an inconsistent public/private keypair. Invalid server configuration returns HTTP 503 without exposing key values.

## Limits of assurance

TLS metadata is self-declared domain information. This helper does not establish licensing, registry membership, issuer authority, sanctions status or authorization to receive a particular transfer. A supplied request key and a domain-declared key still need recipient authorization in the application trust model (CP-008). HPKE base mode does not authenticate the sender. None of these checks is a regulatory certification or a production security audit.
