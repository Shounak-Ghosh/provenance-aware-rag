import hashlib

import nacl.signing

from src.crypto import verify
from src.schema import DocumentRecord


_LEAF_TAG = b"\x00"
_NODE_TAG = b"\x01"


def _leaf_hash(raw_hash: str) -> str:
    """Domain-separate a raw content hash into a tree leaf node.

    Tagging leaves distinctly from internal nodes (below) means a leaf hash
    can never be replayed as an internal-node hash, or vice versa -- the
    classic second-preimage weakness in untagged Merkle trees (CVE-2012-2459).
    """
    return hashlib.sha256(_LEAF_TAG + bytes.fromhex(raw_hash)).hexdigest()


def _hash_pair(left: str, right: str) -> str:
    return hashlib.sha256(_NODE_TAG + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def build_levels(leaf_hashes: list[str]) -> list[list[str]]:
    """Return all tree levels, leaves first (index 0) through root (index -1).

    Level 0 = domain-separated leaf hashes (see _leaf_hash).
    Level k = parent hashes of level k-1, domain-separated from leaves.
    Last level = [root] (before the leaf-count mix-in -- see compute_root).

    An unpaired trailing node at any level is promoted to the next level
    unchanged, rather than duplicated and re-hashed against itself. Duplicate-
    last-node padding lets two trees with different leaf counts collide on
    the same root; promotion removes that ambiguity structurally, and
    compute_root() additionally binds the leaf count into the final root so
    cardinality can never be forged even if a construction bug reintroduces
    it here.
    """
    if not leaf_hashes:
        raise ValueError("Cannot build Merkle tree from empty leaf list")
    levels = [[_leaf_hash(h) for h in leaf_hashes]]
    while len(levels[-1]) > 1:
        current = levels[-1]
        next_level = [
            _hash_pair(current[i], current[i + 1]) for i in range(0, len(current) - 1, 2)
        ]
        if len(current) % 2 == 1:
            next_level.append(current[-1])   # promote, don't duplicate
        levels.append(next_level)
    return levels


def compute_root(leaf_hashes: list[str]) -> str:
    """Return the Merkle root hex string for the given leaf hashes.

    The tree root is mixed with the leaf count before being returned, so a
    root can only ever validate against the exact number of leaves it was
    built from.
    """
    tree_root = build_levels(leaf_hashes)[-1][0]
    return hashlib.sha256(
        len(leaf_hashes).to_bytes(8, "big") + bytes.fromhex(tree_root)
    ).hexdigest()


def merkle_proof(leaf_hashes: list[str], merkle_index: int) -> list[str | None]:
    """Return the sibling-hash path from leaf to root (leaf→root order).

    Pass the full ordered leaf hash list and the 0-based index of the
    target leaf. Each entry is a sibling hash, or None where the target was
    promoted unpaired at that level (see build_levels) and so has no sibling
    to combine with. The returned list, together with len(leaf_hashes), is
    the input to verify_proof().
    """
    levels = build_levels(leaf_hashes)
    path: list[str | None] = []
    idx = merkle_index
    for level in levels[:-1]:          # every level except the root
        if idx == len(level) - 1 and len(level) % 2 == 1:
            path.append(None)          # promoted unpaired -- no sibling this level
        else:
            sibling = level[idx + 1] if idx % 2 == 0 else level[idx - 1]
            path.append(sibling)
        idx = idx // 2
    return path


def verify_proof(
    chunk_hash: str,
    merkle_path: list[str | None],
    root: str,
    merkle_index: int,
    leaf_count: int,
) -> bool:
    """Reconstruct the Merkle root from chunk_hash + proof and compare to root.

    merkle_index and leaf_count must match what merkle_proof()/compute_root()
    used when building the proof and signing the root. Returns True iff the
    reconstructed, leaf-count-bound root equals root.
    """
    current = _leaf_hash(chunk_hash)
    idx = merkle_index
    for sibling in merkle_path:
        if sibling is None:
            pass                                      # promoted unpaired; carries forward
        elif idx % 2 == 0:
            current = _hash_pair(current, sibling)     # current is left child
        else:
            current = _hash_pair(sibling, current)     # current is right child
        idx = idx // 2
    reconstructed_root = hashlib.sha256(
        leaf_count.to_bytes(8, "big") + bytes.fromhex(current)
    ).hexdigest()
    return reconstructed_root == root


def verify_root_signature(record: DocumentRecord, vk: nacl.signing.VerifyKey) -> bool:
    """Return True iff record['root_signature'] is a valid Ed25519 signature
    over record['merkle_root'] (hex-decoded) under the given publisher key."""
    if not record.get("root_signature"):
        return False
    return verify(vk, bytes.fromhex(record["merkle_root"]), record["root_signature"])


def check_tamper(chunk: dict, publisher_vk: nacl.signing.VerifyKey) -> tuple[bool, str]:
    """Run the read-hook integrity check on a retrieve()-bundled chunk.

    Checks, in order: content hash recompute, Merkle path membership, and
    root signature validity. Returns (tampered, reason) — reason names the
    first failed check, or "verified" if all three pass.
    """
    if not chunk.get("merkle_root"):
        return True, "no signed root for document"

    recomputed = hashlib.sha256(chunk["text"].encode()).hexdigest()
    if recomputed != chunk["sha256"]:
        return True, "content hash mismatch"

    if not verify_proof(
        chunk["sha256"],
        chunk["merkle_path"],
        chunk["merkle_root"],
        chunk["merkle_index"],
        len(chunk["doc_leaf_hashes"]),
    ):
        return True, "merkle proof failed"

    record: DocumentRecord = {
        "doc_id": chunk["doc_id"],
        "merkle_root": chunk["merkle_root"],
        "root_signature": chunk["root_signature"],
        "publisher_key_id": chunk["publisher_key_id"],
        "ingested_at": "",
    }
    if not verify_root_signature(record, publisher_vk):
        return True, "root signature invalid"

    return False, "verified"


def attach_provenance(
    chunk: dict,
    doc_leaf_hashes: list[str],
    doc_record: dict,
    publisher_vk: nacl.signing.VerifyKey,
) -> dict:
    """Enrich a bare chunk dict (chunk_id/doc_id/text/sha256/merkle_index) in place
    with merkle_path, doc_leaf_hashes, merkle_root, root_signature, publisher_key_id,
    tampered, and tamper_reason — then return it.

    Shared by retrieve() (query-time, chunk already in a list being built) and
    src/verifier.py (post-hoc, chunk looked up fresh by content hash) so both
    paths run the exact same bundling + check_tamper logic.
    """
    chunk["merkle_path"] = merkle_proof(doc_leaf_hashes, chunk["merkle_index"])
    chunk["doc_leaf_hashes"] = doc_leaf_hashes
    chunk["merkle_root"] = doc_record.get("merkle_root", "")
    chunk["root_signature"] = doc_record.get("root_signature", "")
    chunk["publisher_key_id"] = doc_record.get("publisher_key_id", "")
    chunk["tampered"], chunk["tamper_reason"] = check_tamper(chunk, publisher_vk)
    return chunk
