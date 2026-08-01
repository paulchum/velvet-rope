"""Third-party-verifiable evidence vault primitives for Velvet."""

from velvet.vault.merkle import (
    MerkleLog,
    build_consistency_proof,
    build_inclusion_proof,
    merkle_tree_hash,
    verify_consistency_proof,
    verify_inclusion_proof,
)
from velvet.vault.sth import (
    SIGNED_TREE_HEAD_SCHEMA_VERSION,
    build_signed_tree_head,
    signed_tree_head_hash,
    verify_signed_tree_head,
)

__all__ = [
    "MerkleLog",
    "SIGNED_TREE_HEAD_SCHEMA_VERSION",
    "build_consistency_proof",
    "build_inclusion_proof",
    "build_signed_tree_head",
    "merkle_tree_hash",
    "signed_tree_head_hash",
    "verify_consistency_proof",
    "verify_inclusion_proof",
    "verify_signed_tree_head",
]
