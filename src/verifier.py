import hashlib

import chromadb
import nacl.signing

from src.merkle import attach_provenance


def find_chunk_by_hash(chunk_hash: str, collection: chromadb.Collection) -> dict | None:
    """Look up the chunk currently stored under this exact content hash.

    This is the ONLY mechanism recovering which document/chunk a bare hash
    from Attestation.chunk_hashes belongs to — the schema carries no chunk_id
    or doc_id, by design (frozen Day 4). Returns None if no chunk in the
    CURRENT store carries this hash — itself a tamper signal: a sophisticated
    attacker who rewrites both a chunk's text and its stored hash (see
    src/store.py's corrupt_chunk(update_hash=True)) makes the original attested
    hash vanish from the store entirely, since nothing recomputes it.

    Uses collection.get() (flat result shape: metadatas/documents are plain
    lists), not collection.query() (nested per-query-batch shape used in
    retrieve.py) — do not index a spurious extra [0].
    """
    result = collection.get(where={"sha256": chunk_hash}, include=["metadatas", "documents"])
    if not result["ids"]:
        return None
    meta = result["metadatas"][0]
    return {
        "chunk_id": meta["chunk_id"],
        "doc_id": meta["doc_id"],
        "text": result["documents"][0],
        "sha256": meta["sha256"],
        "merkle_index": meta["merkle_index"],
    }


def verify_chunk(
    chunk_hash: str,
    collection: chromadb.Collection,
    roots: dict,
    publisher_vk: nacl.signing.VerifyKey,
    doc_leaf_cache: dict[str, list[str]],
) -> dict:
    """Independently re-verify one attested chunk hash against the CURRENT store
    state — never a cached/session tamper flag from a prior retrieve() call.

    doc_leaf_cache is caller-owned and reused across a whole attestation's
    chunk_hashes list, so documents shared by multiple cited chunks only cost
    one collection.get(where={"doc_id": ...}) call (same batching retrieve.py
    already does).
    """
    chunk = find_chunk_by_hash(chunk_hash, collection)
    if chunk is None:
        return {
            "chunk_hash": chunk_hash,
            "ok": False,
            "doc_id": None,
            "reason": "chunk hash not found in store (rewritten hash or fabricated attestation)",
        }

    doc_id = chunk["doc_id"]
    if doc_id not in doc_leaf_cache:
        doc_result = collection.get(where={"doc_id": doc_id}, include=["metadatas"])
        sorted_metas = sorted(doc_result["metadatas"], key=lambda m: m["merkle_index"])
        doc_leaf_cache[doc_id] = [m["sha256"] for m in sorted_metas]

    attach_provenance(chunk, doc_leaf_cache[doc_id], roots.get(doc_id, {}), publisher_vk)
    return {"chunk_hash": chunk_hash, "ok": not chunk["tampered"], "doc_id": doc_id, "reason": chunk["tamper_reason"]}


def verify_answer_hash(attestation: dict, answer_text: str | None) -> tuple[bool | None, str]:
    """Compare a supplied answer's SHA-256 against attestation['answer_sha256'].

    Returns (None, "skipped...") when no answer text is supplied — a bare
    attestation.json (e.g. from the UI's download button) doesn't carry the
    answer text, so this check is opt-in via --answer-file.
    """
    if answer_text is None:
        return None, "skipped — no --answer-file given"
    recomputed = hashlib.sha256(answer_text.encode()).hexdigest()
    if recomputed == attestation["answer_sha256"]:
        return True, "matches attested hash"
    return False, f"MISMATCH — recomputed {recomputed} != attested {attestation['answer_sha256']}"
