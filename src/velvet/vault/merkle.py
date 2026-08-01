"""RFC 6962 Merkle tree primitives for vault ledger record hashes."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, cast

JsonObject = dict[str, Any]

MERKLE_INCLUSION_PROOF_SCHEMA_VERSION = "velvet.vault.merkle_inclusion_proof.v1"
MERKLE_CONSISTENCY_PROOF_SCHEMA_VERSION = "velvet.vault.merkle_consistency_proof.v1"
EMPTY_TREE_HASH = sha256(b"").digest()


class MerkleProofError(ValueError):
    """Raised when a Merkle proof or hash is malformed."""


@dataclass
class MerkleLog:
    """Appendable in-memory RFC 6962 log.

    Leaves are bytes. For the Velvet vault, callers pass the raw 32-byte digest
    represented by each ledger record's ``record_hash``.
    """

    _leaves: list[bytes] = field(default_factory=list)

    def append(self, leaf: bytes | str) -> int:
        self._leaves.append(_coerce_leaf_bytes(leaf))
        return len(self._leaves) - 1

    def extend(self, leaves: Iterable[bytes | str]) -> None:
        for leaf in leaves:
            self.append(leaf)

    @property
    def tree_size(self) -> int:
        return len(self._leaves)

    @property
    def leaves(self) -> tuple[bytes, ...]:
        return tuple(self._leaves)

    def root_hash(self) -> bytes:
        return merkle_tree_hash(self._leaves)

    def root_hash_hex(self) -> str:
        return encode_sha256(self.root_hash())

    def inclusion_proof(self, index: int) -> tuple[bytes, ...]:
        return inclusion_path(index, self._leaves)

    def consistency_proof(self, old_size: int) -> tuple[bytes, ...]:
        return consistency_path(old_size, self._leaves)


def leaf_hash(data: bytes) -> bytes:
    return sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    _require_digest(left, "left")
    _require_digest(right, "right")
    return sha256(b"\x01" + left + right).digest()


def merkle_tree_hash(leaves: Sequence[bytes | str]) -> bytes:
    coerced = tuple(_coerce_leaf_bytes(leaf) for leaf in leaves)
    return _merkle_tree_hash(coerced)


def merkle_tree_hash_hex(leaves: Sequence[bytes | str]) -> str:
    return encode_sha256(merkle_tree_hash(leaves))


def record_hashes_root(record_hashes: Sequence[str]) -> str:
    return merkle_tree_hash_hex([decode_sha256(value, "record_hash") for value in record_hashes])


def inclusion_path(index: int, leaves: Sequence[bytes | str]) -> tuple[bytes, ...]:
    coerced = tuple(_coerce_leaf_bytes(leaf) for leaf in leaves)
    if index < 0 or index >= len(coerced):
        raise MerkleProofError("leaf index is outside the tree")
    return _inclusion_path(index, coerced)


def consistency_path(old_size: int, leaves: Sequence[bytes | str]) -> tuple[bytes, ...]:
    coerced = tuple(_coerce_leaf_bytes(leaf) for leaf in leaves)
    new_size = len(coerced)
    if old_size < 0 or old_size > new_size:
        raise MerkleProofError("old tree size must be between 0 and new tree size")
    if old_size in {0, new_size}:
        return ()
    return _consistency_subproof(old_size, coerced, complete=True)


def build_inclusion_proof(
    record_hashes: Sequence[str],
    index: int,
) -> JsonObject:
    proof = inclusion_path(index, [decode_sha256(value, "record_hash") for value in record_hashes])
    return {
        "schema_version": MERKLE_INCLUSION_PROOF_SCHEMA_VERSION,
        "tree_size": len(record_hashes),
        "leaf_index": index,
        "leaf_hash": record_hashes[index],
        "proof": [encode_sha256(item) for item in proof],
    }


def build_consistency_proof(
    old_record_hashes: Sequence[str],
    new_record_hashes: Sequence[str],
) -> JsonObject:
    old_size = len(old_record_hashes)
    new_size = len(new_record_hashes)
    if old_size > new_size:
        raise MerkleProofError("old tree cannot be larger than new tree")
    if list(old_record_hashes) != list(new_record_hashes[:old_size]):
        raise MerkleProofError("old record hashes are not a prefix of new record hashes")
    new_leaves = [decode_sha256(value, "record_hash") for value in new_record_hashes]
    proof = consistency_path(old_size, new_leaves)
    return {
        "schema_version": MERKLE_CONSISTENCY_PROOF_SCHEMA_VERSION,
        "old_tree_size": old_size,
        "new_tree_size": new_size,
        "old_root_hash": record_hashes_root(old_record_hashes),
        "new_root_hash": record_hashes_root(new_record_hashes),
        "proof": [encode_sha256(item) for item in proof],
    }


def verify_inclusion_proof(
    *,
    leaf: bytes | str,
    leaf_index: int,
    tree_size: int,
    root_hash: bytes | str,
    proof: Sequence[bytes | str],
) -> bool:
    try:
        if tree_size <= 0 or leaf_index < 0 or leaf_index >= tree_size:
            return False
        leaf_bytes = _coerce_leaf_bytes(leaf)
        expected_root = _coerce_digest(root_hash, "root_hash")
        proof_hashes = tuple(_coerce_digest(item, "proof") for item in proof)
        proof_iter = iter(proof_hashes)
        computed = _inclusion_root_from_path(
            leaf_index,
            tree_size,
            leaf_hash(leaf_bytes),
            proof_iter,
        )
        try:
            next(proof_iter)
            return False
        except StopIteration:
            return computed == expected_root
    except (MerkleProofError, ValueError, TypeError):
        return False


def verify_inclusion_proof_artifact(
    proof_artifact: dict[str, Any],
    *,
    root_hash: str,
) -> bool:
    if proof_artifact.get("schema_version") != MERKLE_INCLUSION_PROOF_SCHEMA_VERSION:
        return False
    return verify_inclusion_proof(
        leaf=cast(str, proof_artifact.get("leaf_hash", "")),
        leaf_index=int(proof_artifact.get("leaf_index", -1)),
        tree_size=int(proof_artifact.get("tree_size", -1)),
        root_hash=root_hash,
        proof=cast(Sequence[str], proof_artifact.get("proof", ())),
    )


def verify_consistency_proof(
    *,
    old_tree_size: int,
    new_tree_size: int,
    old_root_hash: bytes | str,
    new_root_hash: bytes | str,
    proof: Sequence[bytes | str],
) -> bool:
    try:
        if old_tree_size < 0 or new_tree_size < 0 or old_tree_size > new_tree_size:
            return False
        old_root = _coerce_digest(old_root_hash, "old_root_hash")
        new_root = _coerce_digest(new_root_hash, "new_root_hash")
        proof_hashes = tuple(_coerce_digest(item, "proof") for item in proof)
        if old_tree_size == 0:
            return not proof_hashes and old_root == EMPTY_TREE_HASH
        if old_tree_size == new_tree_size:
            return not proof_hashes and old_root == new_root
        proof_iter = iter(proof_hashes)
        computed_old, computed_new = _consistency_roots_from_path(
            old_tree_size,
            new_tree_size,
            old_root,
            proof_iter,
            complete=True,
        )
        try:
            next(proof_iter)
            return False
        except StopIteration:
            return computed_old == old_root and computed_new == new_root
    except (MerkleProofError, ValueError, TypeError):
        return False


def verify_consistency_proof_artifact(proof_artifact: dict[str, Any]) -> bool:
    if proof_artifact.get("schema_version") != MERKLE_CONSISTENCY_PROOF_SCHEMA_VERSION:
        return False
    return verify_consistency_proof(
        old_tree_size=int(proof_artifact.get("old_tree_size", -1)),
        new_tree_size=int(proof_artifact.get("new_tree_size", -1)),
        old_root_hash=cast(str, proof_artifact.get("old_root_hash", "")),
        new_root_hash=cast(str, proof_artifact.get("new_root_hash", "")),
        proof=cast(Sequence[str], proof_artifact.get("proof", ())),
    )


def decode_sha256(value: str, field_name: str = "hash") -> bytes:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise MerkleProofError(f"{field_name} must be a sha256:<hex> hash")
    digest = value.removeprefix("sha256:")
    if len(digest) != 64:
        raise MerkleProofError(f"{field_name} must be a sha256:<hex> hash")
    try:
        return bytes.fromhex(digest)
    except ValueError as error:
        raise MerkleProofError(f"{field_name} must be a sha256:<hex> hash") from error


def encode_sha256(value: bytes) -> str:
    _require_digest(value, "hash")
    return f"sha256:{value.hex()}"


def _merkle_tree_hash(leaves: Sequence[bytes]) -> bytes:
    size = len(leaves)
    if size == 0:
        return EMPTY_TREE_HASH
    if size == 1:
        return leaf_hash(leaves[0])
    split = _largest_power_of_two_less_than(size)
    return node_hash(_merkle_tree_hash(leaves[:split]), _merkle_tree_hash(leaves[split:]))


def _inclusion_path(index: int, leaves: Sequence[bytes]) -> tuple[bytes, ...]:
    size = len(leaves)
    if size == 1:
        return ()
    split = _largest_power_of_two_less_than(size)
    if index < split:
        return (*_inclusion_path(index, leaves[:split]), _merkle_tree_hash(leaves[split:]))
    return (*_inclusion_path(index - split, leaves[split:]), _merkle_tree_hash(leaves[:split]))


def _consistency_subproof(
    old_size: int,
    leaves: Sequence[bytes],
    *,
    complete: bool,
) -> tuple[bytes, ...]:
    size = len(leaves)
    if old_size == size:
        return () if complete else (_merkle_tree_hash(leaves),)
    split = _largest_power_of_two_less_than(size)
    if old_size <= split:
        return (
            *_consistency_subproof(old_size, leaves[:split], complete=complete),
            _merkle_tree_hash(leaves[split:]),
        )
    return (
        *_consistency_subproof(old_size - split, leaves[split:], complete=False),
        _merkle_tree_hash(leaves[:split]),
    )


def _inclusion_root_from_path(
    index: int,
    size: int,
    current: bytes,
    proof_iter: Iterable[bytes],
) -> bytes:
    if size == 1:
        return current
    split = _largest_power_of_two_less_than(size)
    proof_iterator = iter(proof_iter)
    if index < split:
        left = _inclusion_root_from_path(index, split, current, proof_iterator)
        right = next(proof_iterator)
        return node_hash(left, right)
    right = _inclusion_root_from_path(index - split, size - split, current, proof_iterator)
    left = next(proof_iterator)
    return node_hash(left, right)


def _consistency_roots_from_path(
    old_size: int,
    new_size: int,
    old_root: bytes,
    proof_iter: Iterable[bytes],
    *,
    complete: bool,
) -> tuple[bytes, bytes]:
    proof_iterator = iter(proof_iter)
    if old_size == new_size:
        if complete:
            return old_root, old_root
        proof_hash = next(proof_iterator)
        return proof_hash, proof_hash
    split = _largest_power_of_two_less_than(new_size)
    if old_size <= split:
        old, left_new = _consistency_roots_from_path(
            old_size,
            split,
            old_root,
            proof_iterator,
            complete=complete,
        )
        right = next(proof_iterator)
        return old, node_hash(left_new, right)
    right_old, right_new = _consistency_roots_from_path(
        old_size - split,
        new_size - split,
        old_root,
        proof_iterator,
        complete=False,
    )
    left = next(proof_iterator)
    return node_hash(left, right_old), node_hash(left, right_new)


def _largest_power_of_two_less_than(value: int) -> int:
    if value <= 1:
        raise MerkleProofError("value must be greater than 1")
    return 1 << ((value - 1).bit_length() - 1)


def _coerce_leaf_bytes(value: bytes | str) -> bytes:
    if isinstance(value, str):
        return decode_sha256(value, "leaf")
    if not isinstance(value, bytes):
        raise MerkleProofError("leaf must be bytes or sha256:<hex>")
    return bytes(value)


def _coerce_digest(value: bytes | str, field_name: str) -> bytes:
    if isinstance(value, str):
        return decode_sha256(value, field_name)
    if not isinstance(value, bytes):
        raise MerkleProofError(f"{field_name} must be bytes or sha256:<hex>")
    _require_digest(value, field_name)
    return bytes(value)


def _require_digest(value: bytes, field_name: str) -> None:
    if len(value) != 32:
        raise MerkleProofError(f"{field_name} must be a 32-byte SHA-256 digest")
