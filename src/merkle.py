import hashlib

import nacl.signing

from src.crypto import verify
from src.schema import DocumentRecord


def _hash_pair(left: str, right: str) -> str:
    return hashlib.sha256(bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def build_levels(leaf_hashes: list[str]) -> list[list[str]]:
    """Return all tree levels, leaves first (index 0) through root (index -1).

    Level 0 = leaf hashes (input).
    Level k = parent hashes of level k-1.
    Last level = [root].

    Odd-length levels are padded by duplicating the last element before hashing.
    """
    if not leaf_hashes:
        raise ValueError("Cannot build Merkle tree from empty leaf list")
    levels = [list(leaf_hashes)]
    while len(levels[-1]) > 1:
        current = levels[-1]
        if len(current) % 2 == 1:
            current = current + [current[-1]]
        levels.append(
            [_hash_pair(current[i], current[i + 1]) for i in range(0, len(current), 2)]
        )
    return levels


def compute_root(leaf_hashes: list[str]) -> str:
    """Return the Merkle root hex string for the given leaf hashes."""
    return build_levels(leaf_hashes)[-1][0]


def merkle_proof(leaf_hashes: list[str], merkle_index: int) -> list[str]:
    """Return the sibling-hash path from leaf to root (leaf→root order).

    Pass the full ordered leaf hash list and the 0-based index of the
    target leaf. The returned list is the input to verify_proof().
    """
    levels = build_levels(leaf_hashes)
    path: list[str] = []
    idx = merkle_index
    for level in levels[:-1]:          # every level except the root
        if len(level) % 2 == 1:
            effective = level + [level[-1]]   # replicate odd-padding from build_levels
        else:
            effective = level
        sibling = effective[idx + 1] if idx % 2 == 0 else effective[idx - 1]
        path.append(sibling)
        idx = idx // 2
    return path


def verify_proof(
    chunk_hash: str,
    merkle_path: list[str],
    root: str,
    merkle_index: int,
) -> bool:
    """Reconstruct the Merkle root from chunk_hash + proof and compare to root.

    merkle_index must match the index used when merkle_proof() generated
    merkle_path. Returns True iff the reconstructed root equals root.
    """
    current = chunk_hash
    idx = merkle_index
    for sibling in merkle_path:
        if idx % 2 == 0:
            current = _hash_pair(current, sibling)   # current is left child
        else:
            current = _hash_pair(sibling, current)   # current is right child
        idx = idx // 2
    return current == root


def verify_root_signature(record: DocumentRecord, vk: nacl.signing.VerifyKey) -> bool:
    """Return True iff record['root_signature'] is a valid Ed25519 signature
    over record['merkle_root'] (hex-decoded) under the given publisher key."""
    if not record.get("root_signature"):
        return False
    return verify(vk, bytes.fromhex(record["merkle_root"]), record["root_signature"])
