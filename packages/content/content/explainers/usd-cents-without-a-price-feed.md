---
id: UP-EX-005
title: USD cents without a price feed — how the pilot proof handles valuation
date: 2026-09-22
publishAfter: 2026-09-22T00:00:00Z
sourceCommit: dfda3eab85b9ab2e664826e05ee455e4c0cdad1c
claimRefs:
  - docs/adr/0007-scoped-valuation-approvals.md
  - src/protocol/valuation_approval.py
  - src/prover/pilot_valuation.py
  - src/protocol/transfer.py
status: approved
summary: The pilot circuit proves exact USD-cent arithmetic over a quoted price, but no oracle tells it what the price is. Reading the scoped valuation approval design shows where pricing trust actually lives — and why a proof of arithmetic is not a proof of price.
canonical: /explainers/usd-cents-without-a-price-feed
templateVersion: explainer-v1
---

Travel Rule compliance turns a transfer of tokens into a question about money:
how much is this worth in USD, and does it cross a reporting threshold? That
question hides a hard dependency. Somewhere, something must assert a price. In
Clearproof's current source, that "something" is not an oracle inside the
circuit — it is a signed approval checked outside it, and the source is explicit
that its truthfulness remains an assumption. This explainer walks through how a
USD valuation enters the pilot proof, what the circuit proves about it, and what
it deliberately does not.

## The quote is a rational number, not a feed

The pilot transfer record carries a `Valuation` (`clearproof-valuation-v1`,
defined in
[src/protocol/transfer.py](https://github.com/repfigit/clearproof/blob/main/src/protocol/transfer.py)):
a rational USD-cents-per-base-unit price as an exact 128-bit numerator over
denominator, an asset ID, observation and expiry times, a source ID and a
SHA-256 digest of the source evidence. The comment in the source says the ratio
must be reduced and that no stablecoin peg is assumed. Nothing in the record
claims the price is current, best, or even true — it claims only what was
observed, from which source, with which evidence digest, over which interval.

## The circuit proves arithmetic, not price

Inside the composed pilot circuit, the valuation sub-problem is pure integer
arithmetic (`src/prover/pilot_valuation.py`): multiply the transfer amount by
the numerator, divide by the denominator, and constrain both the USD-cent
quotient and the remainder. The remainder is constrained so the quotient is the
exact floor of the division — not an approximation the prover can nudge. The
reduced ratio itself participates in the private projection, so a proof made
with one price cannot be re-verified against a different one.

But no Circom constraint makes the numerator or denominator equal to a market
price. The circuit proves: "given these inputs, the USD cents figure follows."
It cannot prove: "these inputs are what the market said."

## The approval layer: signatures, not oracles

Commit 2a3dbc7 introduced the
[`ValuationApproval`](https://github.com/repfigit/clearproof/blob/main/src/protocol/valuation_approval.py)
layer. An authority signs the complete valuation — the quote, tenant, asset
catalog digest, signing time and key ID — under a dedicated Ed25519 domain
(`clearproof/valuation-approval/v1`, with a separate key domain for
`clearproof/valuation-key/v1`). The approval binds the quote's full validity
interval: an approval must be signed while the quote is live, and freshly
signing an old observation cannot reset its age.

Operator configuration pins each public key to a tenant, a catalog digest,
exact chain-qualified assets, exact source IDs and a key validity interval.
Verification checks the quote against the trusted catalog, tenant, signing
time, expiry, key interval, source and asset scope, and the signature itself.

[ADR 0007](https://github.com/repfigit/clearproof/blob/main/docs/adr/0007-scoped-valuation-approvals.md)
is explicit about the boundary: "The signing authority must validate the source
evidence and correct asset/base unit interpretation before signing... The
authority's pricing truthfulness is an explicit trust assumption. No stablecoin
peg is inferred. This approves a scoped quote within configured bounds, not
necessarily the latest quote, a business policy, legal compliance or
settlement."

## Why the signature is checked outside the circuit

The Ed25519 signature verification happens in the application layer, not
inside the Circom circuit. ADR 0007 says this directly: "Ed25519 signatures are
verified outside the circuit; they are not claimed to be ZK-verified." Inside
the circuit, the signed quote's operands feed the projection; the application
verifier independently re-validates the quote using its authenticated tenant
and actual clock before accepting the projection.

This split matters for evaluation. A proof says the arithmetic is right for the
bound quote. The approval says an operator-chosen authority endorsed the quote.
Neither says the quote reflects any market. That three-way split — arithmetic,
endorsement, truth — is the honest description of the pilot's pricing boundary.

## What this means for an evaluator

If you evaluate a system that claims ZK Travel Rule compliance, ask where the
price comes from. A useful checklist, grounded in this source:

- Is the quote an exact rational with evidence digest and validity interval, or
  a floating-point number that could silently lose precision?
- Who signs the approval, and what are they trusted to know?
- Is the signature verified in-circuit, or is that verification honestly
  described as application-layer?
- Does the documentation claim the circuit proves price truth, or does it
  state, as ADR 0007 does, that pricing truthfulness is a trust assumption?

Clearproof's current source takes the fourth position, and states it. That
statement is not a weakness in the design — it is the design making its trust
boundary visible instead of hiding it inside a proof that cannot carry it.
