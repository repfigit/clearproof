# ADR 0010: RFC 3161 evidence for signed historical decisions

Date: 2026-09-06  
Status: implemented for local pilot evaluation; production authority remains unapproved

A decision signature authenticates the operator's claim but cannot authenticate its
clock. We use RFC 3161 responses over a domain-separated serialization of the
complete signed decision. The request contains a digest and random nonce; it does
not disclose the receipt, private transfer information or proof preimage to a TSA.
No network client or public TSA submission is implemented or needed for local tests.

Verification uses `rfc3161-client>=1.0.8,<2`, not custom timestamp cryptography.
Reviewer configuration pins the exact TSA leaf certificate, roots, policy OID,
authority validity, acceptable accuracy and maximum capture delay. Leaf EKU must
be critical and exclusively timestamping. The response profile requires strict
DER, SHA-256 message imprint and SHA-256/384/512 CMS digests. All cryptographic and
certificate checks are performed by the maintained library. The dependency floor
includes its certificate-selection security fix.

We interpret genTime with its stated accuracy as an interval, using integer
microseconds. The whole interval must lie within independently approved authority
time and precede reviewer time. For a decision-window result it must also lie
between the claimed decision time and the configured maximum delay, before proof
expiry. Missing accuracy cannot be treated as zero. A later certificate expiry
does not invalidate an earlier timestamp; known authority compromise at review
time leaves it untrusted pending further evidence.

A timestamp proves the signed record existed by the interval's upper bound. It
does not prove the decision occurred at its exact claimed second, that external
source observations were truthful, or that funds moved. A valid timestamp over an
untrusted decision is possible, so timing and decision authentication remain
separate report fields. The generated observation is not a replacement for the
operator's decision/capture times.

The nonce prevents confusion in a request/response protocol. This offline verifier
checks the exact message imprint rather than a live request nonce; it makes no
online freshness or liveness claim. Reusing the same valid timestamp for the same
immutable decision is allowed and does not authorize replay.

Timestamp evidence is attached after authorization as a separate immutable,
encrypted record. It cannot be part of the signed receipt itself without a cycle.
The first accepted response is preserved; the same response is idempotent and a
different response requires a future renewal design. Export includes it when
available. Stripping it leaves review indeterminate. Independent source approval and compromise review are separate requirements
for a supported local-decision result. The public CLI remains open.

Sources checked September 6, 2026:

- [RFC 3161: Time-Stamp Protocol](https://www.rfc-editor.org/rfc/rfc3161.html)
- [Trail of Bits rfc3161-client](https://github.com/trailofbits/rfc3161-client)
- [Certificate-validation advisory](https://github.com/trailofbits/rfc3161-client/security/advisories/GHSA-3xxc-pwj6-jgrj)
- [OpenSSL timestamp command](https://docs.openssl.org/master/man1/openssl-ts/)

The test authority uses fresh synthetic keys and the local OpenSSL clock. It
exercises the protocol and independent trust wiring; it is not an independently
operated or production-assured time source.
