# SPDX-License-Identifier: Apache-2.0
"""Persisted incremental Poseidon Merkle tree under PilotTransaction's tenant lock.

Append-only updates write O(depth) nodes per leaf without rebuilding the full tree.
All reads and mutations validate canonical scalars, contiguous indices, and stored
root consistency, failing closed on any corruption or drift.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from src.protocol.credential import scalar
from src.registry.pilot_tree import ISSUANCE_TREE_DEPTH, MAX_TREE_DEPTH, zero_root
from src.registry.poseidon import poseidon_hash
from src.storage.pilot import PilotTransaction, RecordConflict

_HEX32 = re.compile(r"^[0-9a-f]{64}$")


class MerkleIntegrityError(ValueError):
    """Persisted incremental Merkle state is missing, inconsistent, or drifted."""


@dataclass(frozen=True)
class MerkleRootState:
    scope_digest: str
    depth: int
    root_version: int
    leaf_count: int
    root_hash: str


@dataclass(frozen=True)
class PersistedMerkleLeaf:
    leaf_index: int
    credential_id: str
    commitment: str
    root_version: int


def _validate_scope_and_depth(scope_digest: str, depth: int) -> None:
    if type(scope_digest) is not str or not _HEX32.fullmatch(scope_digest):
        raise ValueError("Invalid Merkle scope digest")
    if type(depth) is not int or not 1 <= depth <= MAX_TREE_DEPTH:
        raise ValueError(f"Tree depth must be 1–{MAX_TREE_DEPTH}")


def _validate_leaf(credential_id: str, commitment: str) -> int:
    if type(credential_id) is not str or not _HEX32.fullmatch(credential_id):
        raise ValueError("Invalid Merkle credential identifier")
    return scalar(commitment, nonzero=True)


class IncrementalMerkleStore:
    """Tenant-scoped persisted Merkle tree operating inside a held PilotTransaction."""

    def __init__(self, tx: PilotTransaction, scope_digest: str, *, depth: int = ISSUANCE_TREE_DEPTH):
        _validate_scope_and_depth(scope_digest, depth)
        self._tx = tx
        self._scope = scope_digest
        self._depth = depth

    @property
    def scope_digest(self) -> str:
        return self._scope

    @property
    def depth(self) -> int:
        return self._depth

    def _conn(self):
        self._tx._check_open()
        return self._tx._conn

    async def read_root(self) -> MerkleRootState | None:
        conn = self._conn()
        row = await (
            await conn.execute(
                "SELECT root_version, leaf_count, root_hash FROM pilot_merkle_roots "
                "WHERE tenant_id=%s AND scope_digest=%s AND depth=%s",
                (self._tx.tenant_id, self._scope, self._depth),
            )
        ).fetchone()
        if row is None:
            return None
        root_version, leaf_count, root_hash = row
        scalar(root_hash)
        if leaf_count > 2**self._depth:
            raise MerkleIntegrityError("Persisted Merkle leaf count exceeds tree depth capacity")
        return MerkleRootState(
            scope_digest=self._scope,
            depth=self._depth,
            root_version=root_version,
            leaf_count=leaf_count,
            root_hash=root_hash,
        )

    async def last_credential_id(self) -> str | None:
        conn = self._conn()
        row = await (
            await conn.execute(
                "SELECT credential_id FROM pilot_merkle_leaves "
                "WHERE tenant_id=%s AND scope_digest=%s AND depth=%s "
                "ORDER BY leaf_index DESC LIMIT 1",
                (self._tx.tenant_id, self._scope, self._depth),
            )
        ).fetchone()
        return row[0] if row is not None else None

    async def read_leaves(self) -> list[PersistedMerkleLeaf]:
        conn = self._conn()
        rows = await (
            await conn.execute(
                "SELECT leaf_index, credential_id, commitment, root_version FROM pilot_merkle_leaves "
                "WHERE tenant_id=%s AND scope_digest=%s AND depth=%s ORDER BY leaf_index ASC",
                (self._tx.tenant_id, self._scope, self._depth),
            )
        ).fetchall()
        leaves: list[PersistedMerkleLeaf] = []
        for expected_idx, (leaf_index, credential_id, commitment, root_version) in enumerate(rows):
            if leaf_index != expected_idx:
                raise MerkleIntegrityError("Persisted Merkle leaf indices are non-contiguous")
            _validate_leaf(credential_id, commitment)
            leaves.append(
                PersistedMerkleLeaf(
                    leaf_index=leaf_index,
                    credential_id=credential_id,
                    commitment=commitment,
                    root_version=root_version,
                )
            )
        return leaves

    async def _load_node(self, level: int, node_index: int) -> int:
        conn = self._conn()
        row = await (
            await conn.execute(
                "SELECT node_hash FROM pilot_merkle_nodes "
                "WHERE tenant_id=%s AND scope_digest=%s AND depth=%s AND level=%s AND node_index=%s",
                (self._tx.tenant_id, self._scope, self._depth, level, node_index),
            )
        ).fetchone()
        if row is None:
            return zero_root(level)
        return scalar(row[0])

    async def _load_nodes_bulk(self, coords: list[tuple[int, int]]) -> dict[tuple[int, int], int]:
        if not coords:
            return {}
        conn = self._conn()
        levels = [c[0] for c in coords]
        indices = [c[1] for c in coords]
        rows = await (
            await conn.execute(
                "SELECT n.level, n.node_index, n.node_hash "
                "FROM pilot_merkle_nodes n "
                "JOIN unnest(%s::smallint[], %s::bigint[]) AS q(level, node_index) "
                "ON n.level = q.level AND n.node_index = q.node_index "
                "WHERE n.tenant_id=%s AND n.scope_digest=%s AND n.depth=%s",
                (levels, indices, self._tx.tenant_id, self._scope, self._depth),
            )
        ).fetchall()
        return {(level, idx): scalar(node_hash) for level, idx, node_hash in rows}

    async def _upsert_nodes(self, nodes: list[tuple[int, int, str]], root_version: int) -> None:
        conn = self._conn()
        levels = [n[0] for n in nodes]
        indices = [n[1] for n in nodes]
        hashes = [n[2] for n in nodes]
        await conn.execute(
            "INSERT INTO pilot_merkle_nodes "
            "(tenant_id, scope_digest, depth, level, node_index, node_hash, root_version) "
            "SELECT %s, %s, %s, u.level, u.node_index, u.node_hash, %s "
            "FROM unnest(%s::smallint[], %s::bigint[], %s::text[]) AS u(level, node_index, node_hash) "
            "ON CONFLICT (tenant_id, scope_digest, depth, level, node_index) "
            "DO UPDATE SET node_hash = EXCLUDED.node_hash, root_version = EXCLUDED.root_version",
            (self._tx.tenant_id, self._scope, self._depth, root_version, levels, indices, hashes),
        )

    async def _ensure_initialized(self) -> MerkleRootState:
        state = await self.read_root()
        if state is not None:
            return state
        conn = self._conn()
        empty_root = str(zero_root(self._depth))
        await conn.execute(
            "INSERT INTO pilot_merkle_roots (tenant_id, scope_digest, depth, root_version, leaf_count, root_hash) "
            "VALUES (%s, %s, %s, 0, 0, %s)",
            (self._tx.tenant_id, self._scope, self._depth, empty_root),
        )
        return MerkleRootState(
            scope_digest=self._scope,
            depth=self._depth,
            root_version=0,
            leaf_count=0,
            root_hash=empty_root,
        )

    async def append(self, credential_id: str, commitment: str) -> tuple[MerkleRootState, int]:
        """Append one leaf in O(depth) hashes/DB ops under the caller's tenant lock."""
        leaf_value = _validate_leaf(credential_id, commitment)
        state = await self._ensure_initialized()
        if state.leaf_count >= 2**self._depth:
            raise ValueError("Pilot issuance tree capacity exceeded")
        conn = self._conn()
        existing = await (
            await conn.execute(
                "SELECT leaf_index, commitment FROM pilot_merkle_leaves "
                "WHERE tenant_id=%s AND scope_digest=%s AND depth=%s AND (credential_id=%s OR commitment=%s) LIMIT 1",
                (self._tx.tenant_id, self._scope, self._depth, credential_id, commitment),
            )
        ).fetchone()
        if existing is not None:
            raise RecordConflict("Duplicate Merkle tree leaf or credential identifier")

        leaf_index = state.leaf_count
        next_version = state.root_version + 1
        if next_version > 2**53 - 1:
            raise ValueError("Merkle root version overflow")

        sibling_coords: list[tuple[int, int]] = []
        cursor = leaf_index
        for level in range(self._depth):
            sibling_coords.append((level, cursor ^ 1))
            cursor //= 2
        siblings = await self._load_nodes_bulk(sibling_coords)

        nodes_to_write: list[tuple[int, int, str]] = [(0, leaf_index, str(leaf_value))]
        current_hash = leaf_value
        cursor = leaf_index
        for level in range(self._depth):
            sibling_hash = siblings.get((level, cursor ^ 1), zero_root(level))
            if cursor & 1:
                current_hash = poseidon_hash([sibling_hash, current_hash])
            else:
                current_hash = poseidon_hash([current_hash, sibling_hash])
            cursor //= 2
            nodes_to_write.append((level + 1, cursor, str(current_hash)))

        new_root = str(current_hash)
        await conn.execute(
            "INSERT INTO pilot_merkle_leaves "
            "(tenant_id, scope_digest, depth, leaf_index, credential_id, commitment, root_version) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (self._tx.tenant_id, self._scope, self._depth, leaf_index, credential_id, commitment, next_version),
        )
        await self._upsert_nodes(nodes_to_write, next_version)
        updated = await conn.execute(
            "UPDATE pilot_merkle_roots SET root_version=%s, leaf_count=%s, root_hash=%s "
            "WHERE tenant_id=%s AND scope_digest=%s AND depth=%s AND root_version=%s",
            (next_version, leaf_index + 1, new_root, self._tx.tenant_id, self._scope, self._depth, state.root_version),
        )
        if updated.rowcount != 1:
            raise RecordConflict("Merkle root version conflict during append")
        return (
            MerkleRootState(
                scope_digest=self._scope,
                depth=self._depth,
                root_version=next_version,
                leaf_count=leaf_index + 1,
                root_hash=new_root,
            ),
            leaf_index,
        )

    async def append_many(self, entries: list[tuple[str, str]]) -> MerkleRootState:
        """Append a batch of leaves incrementally in O(len(entries) * depth) work."""
        if not entries:
            return await self._ensure_initialized()
        state = await self._ensure_initialized()
        if state.leaf_count + len(entries) > 2**self._depth:
            raise ValueError("Pilot issuance tree capacity exceeded")
        validated = [(cid, comm, _validate_leaf(cid, comm)) for cid, comm in entries]
        cids = [v[0] for v in validated]
        comms = [v[1] for v in validated]
        if len(set(cids)) != len(cids) or len(set(comms)) != len(comms):
            raise ValueError("Duplicate Merkle tree leaf or credential identifier")

        conn = self._conn()
        existing = await (
            await conn.execute(
                "SELECT 1 FROM pilot_merkle_leaves "
                "WHERE tenant_id=%s AND scope_digest=%s AND depth=%s "
                "AND (credential_id = ANY(%s) OR commitment = ANY(%s)) LIMIT 1",
                (self._tx.tenant_id, self._scope, self._depth, cids, comms),
            )
        ).fetchone()
        if existing is not None:
            raise RecordConflict("Duplicate Merkle tree leaf or credential identifier")

        start_index = state.leaf_count
        next_version = state.root_version + 1
        if next_version > 2**53 - 1:
            raise ValueError("Merkle root version overflow")

        # Only siblings strictly to the left of start_index can exist in the DB;
        # nodes along the new range are computed in memory and written once.
        needed: set[tuple[int, int]] = set()
        for offset in range(len(validated)):
            idx = start_index + offset
            for level in range(self._depth):
                sib = idx ^ 1
                if sib < (start_index >> level):
                    needed.add((level, sib))
                idx //= 2
        cache: dict[tuple[int, int], int] = await self._load_nodes_bulk(sorted(needed))
        dirty: dict[tuple[int, int], int] = {}

        leaf_indices: list[int] = []
        for offset, (_, _, leaf_val) in enumerate(validated):
            leaf_index = start_index + offset
            leaf_indices.append(leaf_index)
            cache[(0, leaf_index)] = leaf_val
            dirty[(0, leaf_index)] = leaf_val

        affected = set(leaf_indices)
        for level in range(self._depth):
            parents = sorted({idx // 2 for idx in affected})
            for parent in parents:
                left = cache.get((level, parent * 2), zero_root(level))
                right = cache.get((level, parent * 2 + 1), zero_root(level))
                parent_hash = poseidon_hash([left, right])
                cache[(level + 1, parent)] = parent_hash
                dirty[(level + 1, parent)] = parent_hash
            affected = set(parents)

        new_root = str(cache[(self._depth, 0)])
        await conn.execute(
            "INSERT INTO pilot_merkle_leaves "
            "(tenant_id, scope_digest, depth, leaf_index, credential_id, commitment, root_version) "
            "SELECT %s, %s, %s, u.leaf_index, u.credential_id, u.commitment, %s "
            "FROM unnest(%s::bigint[], %s::text[], %s::text[]) AS u(leaf_index, credential_id, commitment)",
            (self._tx.tenant_id, self._scope, self._depth, next_version, leaf_indices, cids, comms),
        )
        nodes_to_write = [(lvl, idx, str(val)) for (lvl, idx), val in dirty.items()]
        await self._upsert_nodes(nodes_to_write, next_version)
        updated = await conn.execute(
            "UPDATE pilot_merkle_roots SET root_version=%s, leaf_count=%s, root_hash=%s "
            "WHERE tenant_id=%s AND scope_digest=%s AND depth=%s AND root_version=%s",
            (
                next_version,
                start_index + len(validated),
                new_root,
                self._tx.tenant_id,
                self._scope,
                self._depth,
                state.root_version,
            ),
        )
        if updated.rowcount != 1:
            raise RecordConflict("Merkle root version conflict during batch append")
        return MerkleRootState(
            scope_digest=self._scope,
            depth=self._depth,
            root_version=next_version,
            leaf_count=start_index + len(validated),
            root_hash=new_root,
        )

    async def reset_and_populate(self, entries: list[tuple[str, str]]) -> MerkleRootState:
        """Replace persisted leaves/nodes for this scope (used on revocation/expiry rebuild)."""
        conn = self._conn()
        state = await self.read_root()
        next_version = (state.root_version if state else 0) + 1
        if next_version > 2**53 - 1:
            raise ValueError("Merkle root version overflow")
        if len(entries) > 2**self._depth:
            raise ValueError("Pilot issuance tree capacity exceeded")
        validated = [(cid, comm, _validate_leaf(cid, comm)) for cid, comm in entries]
        cids = [v[0] for v in validated]
        comms = [v[1] for v in validated]
        if len(set(cids)) != len(cids) or len(set(comms)) != len(comms):
            raise ValueError("Duplicate Merkle tree leaf or credential identifier")

        await conn.execute(
            "DELETE FROM pilot_merkle_nodes WHERE tenant_id=%s AND scope_digest=%s AND depth=%s",
            (self._tx.tenant_id, self._scope, self._depth),
        )
        await conn.execute(
            "DELETE FROM pilot_merkle_leaves WHERE tenant_id=%s AND scope_digest=%s AND depth=%s",
            (self._tx.tenant_id, self._scope, self._depth),
        )
        empty_root = str(zero_root(self._depth))
        if state is None:
            await conn.execute(
                "INSERT INTO pilot_merkle_roots (tenant_id, scope_digest, depth, root_version, leaf_count, root_hash) "
                "VALUES (%s, %s, %s, %s, 0, %s)",
                (self._tx.tenant_id, self._scope, self._depth, next_version, empty_root),
            )
        else:
            await conn.execute(
                "UPDATE pilot_merkle_roots SET root_version=%s, leaf_count=0, root_hash=%s "
                "WHERE tenant_id=%s AND scope_digest=%s AND depth=%s",
                (next_version, empty_root, self._tx.tenant_id, self._scope, self._depth),
            )

        if not validated:
            return MerkleRootState(
                scope_digest=self._scope,
                depth=self._depth,
                root_version=next_version,
                leaf_count=0,
                root_hash=empty_root,
            )

        cache: dict[tuple[int, int], int] = {}
        leaf_indices = list(range(len(validated)))
        for idx, (_, _, leaf_val) in enumerate(validated):
            cache[(0, idx)] = leaf_val
        affected = set(leaf_indices)
        for level in range(self._depth):
            parents = sorted({idx // 2 for idx in affected})
            for parent in parents:
                left = cache.get((level, parent * 2), zero_root(level))
                right = cache.get((level, parent * 2 + 1), zero_root(level))
                cache[(level + 1, parent)] = poseidon_hash([left, right])
            affected = set(parents)

        new_root = str(cache[(self._depth, 0)])
        await conn.execute(
            "INSERT INTO pilot_merkle_leaves "
            "(tenant_id, scope_digest, depth, leaf_index, credential_id, commitment, root_version) "
            "SELECT %s, %s, %s, u.leaf_index, u.credential_id, u.commitment, %s "
            "FROM unnest(%s::bigint[], %s::text[], %s::text[]) AS u(leaf_index, credential_id, commitment)",
            (self._tx.tenant_id, self._scope, self._depth, next_version, leaf_indices, cids, comms),
        )
        nodes_to_write = [(lvl, idx, str(val)) for (lvl, idx), val in cache.items()]
        await self._upsert_nodes(nodes_to_write, next_version)
        await conn.execute(
            "UPDATE pilot_merkle_roots SET leaf_count=%s, root_hash=%s "
            "WHERE tenant_id=%s AND scope_digest=%s AND depth=%s",
            (len(validated), new_root, self._tx.tenant_id, self._scope, self._depth),
        )
        return MerkleRootState(
            scope_digest=self._scope,
            depth=self._depth,
            root_version=next_version,
            leaf_count=len(validated),
            root_hash=new_root,
        )

    async def sync_entries(self, ordered_entries: list[tuple[str, str]]) -> MerkleRootState:
        """Synchronize persisted tree with the canonical ordered eligible entry list.

        When the existing persisted leaves are an exact prefix of ``ordered_entries``,
        only the newly appended tail is hashed and written incrementally in O(delta * depth).
        When a leaf was removed (revoked/expired) or inserted before the tail, rebuilds
        and persists the updated tree cleanly under the same tenant lock.
        """
        state = await self.read_root()
        if state is None:
            return await self.append_many(ordered_entries)

        existing = await self.read_leaves()
        if len(existing) != state.leaf_count:
            raise MerkleIntegrityError("Persisted Merkle root leaf_count differs from stored leaves")

        if state.leaf_count == 0:
            if state.root_hash != str(zero_root(self._depth)):
                raise MerkleIntegrityError("Empty Merkle root hash does not match zero_root")
            return await self.append_many(ordered_entries)

        stored_root_node = await self._load_node(self._depth, 0)
        if str(stored_root_node) != state.root_hash:
            raise MerkleIntegrityError("Persisted Merkle root node differs from root metadata")

        existing_pairs = [(leaf.credential_id, leaf.commitment) for leaf in existing]
        if existing_pairs == ordered_entries:
            return state
        if len(ordered_entries) > len(existing_pairs) and ordered_entries[: len(existing_pairs)] == existing_pairs:
            return await self.append_many(ordered_entries[len(existing_pairs) :])
        return await self.reset_and_populate(ordered_entries)

    async def membership(self, credential_id: str) -> dict:
        """Compute an authenticated Merkle membership path directly from persisted nodes in O(depth)."""
        if type(credential_id) is not str or not _HEX32.fullmatch(credential_id):
            raise ValueError("Invalid Merkle credential identifier")
        state = await self.read_root()
        if state is None or state.leaf_count == 0:
            raise KeyError("Tree entry not found")
        conn = self._conn()
        row = await (
            await conn.execute(
                "SELECT leaf_index, commitment FROM pilot_merkle_leaves "
                "WHERE tenant_id=%s AND scope_digest=%s AND depth=%s AND credential_id=%s",
                (self._tx.tenant_id, self._scope, self._depth, credential_id),
            )
        ).fetchone()
        if row is None:
            raise KeyError("Tree entry not found")
        leaf_index, commitment = row
        leaf_value = scalar(commitment, nonzero=True)
        stored_leaf = await self._load_node(0, leaf_index)
        if stored_leaf != leaf_value:
            raise MerkleIntegrityError("Persisted Merkle leaf node differs from leaf index")

        sibling_coords: list[tuple[int, int]] = []
        cursor = leaf_index
        for level in range(self._depth):
            sibling_coords.append((level, cursor ^ 1))
            cursor //= 2
        siblings_map = await self._load_nodes_bulk(sibling_coords)

        siblings: list[str] = []
        indices: list[int] = []
        computed = leaf_value
        cursor = leaf_index
        for level in range(self._depth):
            sib = siblings_map.get((level, cursor ^ 1), zero_root(level))
            direction = cursor & 1
            siblings.append(str(sib))
            indices.append(direction)
            computed = poseidon_hash([sib, computed] if direction else [computed, sib])
            cursor //= 2

        if str(computed) != state.root_hash:
            raise MerkleIntegrityError("Recomputed Merkle path root differs from persisted root")
        return {"root": state.root_hash, "siblings": siblings, "indices": indices}
