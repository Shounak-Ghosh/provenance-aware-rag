import hashlib

import chromadb

from src.config import CHROMA_PATH, COLLECTION_NAME


def get_collection() -> chromadb.Collection:
    """Return the persistent Chroma collection, creating it if it does not exist.

    The returned Collection holds an internal reference to its client, so the
    local ``client`` variable going out of scope here is safe.
    """
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    return client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )


def corrupt_chunk(
    collection: chromadb.Collection,
    chunk_id: str,
    new_text: str,
    update_hash: bool = False,
) -> None:
    """Mutate a stored chunk's text in place, for tamper-detection demos.

    update_hash=False simulates a naive attacker who edits content without
    recomputing the hash — caught by the read hook's SHA-256 recompute check.
    update_hash=True simulates a sophisticated attacker who also updates the
    stored hash to match the new text — the forged leaf no longer reconstructs
    the signed Merkle root, so it is instead caught by verify_proof().

    The original embedding is passed back unchanged on update — otherwise
    Chroma would silently re-embed the new text with its own default
    embedding function (not the pinned bge-small model), drifting the chunk
    out of similarity rankings. Embeddings are outside the trust boundary
    (see SPRINT.md); only the stored text and hash are meant to move here.
    """
    result = collection.get(ids=[chunk_id], include=["metadatas", "embeddings"])
    if not result["ids"]:
        raise ValueError(f"chunk_id {chunk_id!r} not found in store — cannot tamper a chunk that doesn't exist")
    metadata = result["metadatas"][0]
    embedding = result["embeddings"][0]
    if update_hash:
        metadata["sha256"] = hashlib.sha256(new_text.encode()).hexdigest()
    collection.update(
        ids=[chunk_id],
        documents=[new_text],
        metadatas=[metadata],
        embeddings=[embedding],
    )
