# SPDX-License-Identifier: Apache-2.0
"""Measure synthetic inventory discovery and complete root construction on owned PostgreSQL."""

import argparse
import asyncio
import hashlib
import json
import os
import platform
import statistics
import time
import uuid
from pathlib import Path

import psycopg
from eth_account import Account
from psycopg import sql
from psycopg.conninfo import make_conninfo

from src.auth.principal import Principal
from src.protocol.credential import PilotCredential, holder_commitment
from src.protocol.enrollment import EnrollmentConsent
from src.services.enrollment import EnrollmentService
from src.services.enrollment_inventory import EnrollmentInventoryService, EnrollmentPageRequest
from src.services.issuance_source import MAX_ISSUANCE_ENTRIES
from src.services.issuance_tree import build_issuance_tree
from src.storage.database import Database
from src.storage.keyring import KeyRing, KeyVersion
from src.storage.pilot import PilotStore
from src.storage.pilot_cipher import RecordCipher


async def measure(counts: list[int], samples: int) -> dict:
    admin = os.environ["DATABASE_URL"]
    schema = "inventory_bench_" + uuid.uuid4().hex
    async with await psycopg.AsyncConnection.connect(admin) as conn:
        await conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        version = (await (await conn.execute("SHOW server_version")).fetchone())[0]
    os.environ["DATABASE_URL"] = make_conninfo(admin, options=f"-c search_path={schema}")
    database = Database(pool_min=1, pool_max=2)
    issuer, registry, chain = "did:web:inventory.example", "0x" + "1" * 40, 31337
    who = Principal(
        tenant_id="synthetic-inventory-benchmark",
        actor_id="synthetic-operator",
        roles=("tenant:admin", "credential:issue", "evidence:decrypt"),
        issuer_dids=(issuer,),
    )
    # Public test-only keys; never used for deployed or customer records.
    wallet = Account.from_key(bytes([8]) * 32)
    cipher = RecordCipher(KeyRing(KeyVersion("benchmark-v1", bytes([9]) * 32, activated_at=0)))
    now, populated, rows = 120, 0, []
    try:
        await database.connect()
        enrollment = EnrollmentService(database, cipher, who, chain_id=chain, registry_address=registry)
        inventory = EnrollmentInventoryService(database, cipher, who, chain_id=chain, registry_address=registry)
        for count in counts:
            for index in range(populated + 1, count + 1):
                credential = PilotCredential(
                    tenant_id=who.tenant_id,
                    credential_nonce=f"{index:064x}",
                    issuer_did=issuer,
                    subject_wallet=wallet.address.lower(),
                    holder_commitment=holder_commitment("123456"),
                    jurisdiction="US",
                    kyc_tier=2,
                    sanctions_clear=True,
                    issued_at=100,
                    expires_at=1000,
                )
                consent = EnrollmentConsent(
                    credential=credential, chain_id=chain, registry_address=registry, consent_expires_at=200
                )
                signature = "0x" + wallet.sign_message(consent.signing_message()).signature.hex()
                await enrollment.enroll(consent, signature, idempotency_key=f"synthetic-{index}", now=110)
            populated = count
            page_times, tree_times = [], []
            for _ in range(samples):
                started = time.perf_counter()
                page = await inventory.page(EnrollmentPageRequest(issuer_did=issuer), now=now)
                page_times.append(time.perf_counter() - started)
                assert len(page.entries) == min(count, 64) and all(entry.eligible for entry in page.entries)
                started = time.perf_counter()
                async with PilotStore(database, cipher, who).transaction() as tx:
                    candidate = await build_issuance_tree(
                        tx,
                        issuer_did=issuer,
                        chain_id=chain,
                        registry_address=registry,
                        now=now,
                    )
                tree_times.append(time.perf_counter() - started)
                assert len(candidate.tree.entries) == count and candidate.tree.depth == 32
            rows.append(
                dict(
                    enrollments=count,
                    samples=samples,
                    first_page_seconds=page_times,
                    root_build_seconds=tree_times,
                    first_page_median_seconds=statistics.median(page_times),
                    root_build_median_seconds=statistics.median(tree_times),
                    source_pages=len(candidate.pages),
                    tree_depth=candidate.tree.depth,
                )
            )
        root = Path(__file__).resolve().parents[2]
        names = (
            "src/storage/pilot.py",
            "src/services/enrollment_inventory.py",
            "src/services/issuance_tree.py",
            "src/services/issuance_source.py",
            "src/registry/pilot_tree.py",
        )
        return dict(
            schema_version="clearproof-inventory-benchmark-v1",
            synthetic_only=True,
            python=platform.python_version(),
            platform=platform.platform(),
            postgresql=version,
            affinity=sorted(os.sched_getaffinity(0)),
            software_guard=MAX_ISSUANCE_ENTRIES,
            source_sha256={name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names},
            measurements=rows,
            excludes=[
                "HTTP/authentication",
                "concurrent tenants",
                "chain/provider calls",
                "proof generation",
                "registrar signing/persistence",
                "service throughput",
                "production SLA",
            ],
        )
    finally:
        await database.close()
        os.environ["DATABASE_URL"] = admin
        async with await psycopg.AsyncConnection.connect(admin) as conn:
            await conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--counts", default="64,256,512,1024")
    parser.add_argument("--samples", type=int, default=3)
    args = parser.parse_args()
    counts = [int(value) for value in args.counts.split(",")]
    if counts != sorted(set(counts)) or not counts or not 1 <= counts[0] <= counts[-1] <= MAX_ISSUANCE_ENTRIES:
        parser.error("counts must be ascending unique integers within the software guard")
    if not 1 <= args.samples <= 10 or args.output.exists():
        parser.error("samples must be 1–10 and output must not exist")
    receipt = asyncio.run(measure(counts, args.samples))
    with args.output.open("x") as handle:
        json.dump(receipt, handle, indent=2)
        handle.write("\n")
    print(f"Saved synthetic aggregate measurements to {args.output}")


if __name__ == "__main__":
    main()
