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


def verify_root_signature(record: DocumentRecord, vk: nacl.signing.VerifyKey) -> bool:
    """Return True iff record['root_signature'] is a valid Ed25519 signature
    over record['merkle_root'] (hex-decoded) under the given publisher key."""
    if not record.get("root_signature"):
        return False
    return verify(vk, bytes.fromhex(record["merkle_root"]), record["root_signature"])
