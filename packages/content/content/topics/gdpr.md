---
title: GDPR Data-Minimization
category: concepts
order: 8
cli-topic: gdpr
---

# Privacy and data minimization

clearproof explores reducing disclosure by separating verification of specific predicates from encrypted exchange of required personal information. This is an architectural objective, not a GDPR exemption or a compliance certification.

## Encryption and proofs have different roles

A proof can establish its encoded statement without exposing every private witness value. Encrypted personal information can travel to an authorized recipient. The recipient may still need to obtain, verify and retain information under applicable requirements.

For covered EU crypto transfers, the Transfer of Funds Regulation sets information and missing-information obligations. An amount tier does not define a blanket exemption from those obligations. [EU Regulation 2023/1113, Articles 14–17](https://eur-lex.europa.eu/eli/reg/2023/1113/oj/eng)

Encrypted personal data remains personal data. Keeping it off-chain and limiting disclosure must be considered alongside purpose, access, retention and governance. [EDPB Guidelines 02/2025, final version 2, July 7, 2026](https://www.edpb.europa.eu/system/files/2026-07/edpb_guidelines_202502_blockchain_v2_en.pdf)

## What remains visible

Current public proof metadata includes amount tier, jurisdiction, timestamps, roots, credential commitments, transfer references and a review signal. Commitments and hashes are not automatically anonymous: linkage to other records or public transactions can identify or correlate people.

A named advisory field may be omitted from a bridge while still appearing in the public-signal array. Confidential advisory handling is part of the planned proof-version work.

## Deployment questions

- Which facts actually need a private predicate proof?
- Which recipient is authorized to receive each piece of information?
- How are credentials, source data and recipient keys authenticated?
- What can repeated commitments, timestamps and status checks reveal?
- How are retention, access, deletion, incident handling and evidence export implemented?

Measure disclosure and operational data copying in the intended deployment. Neither encryption, ZK, nor explorer verification independently establishes compliance.

Read [current assurance limits](/docs/security).
