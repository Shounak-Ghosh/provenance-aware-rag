import json

import chromadb
from sentence_transformers import SentenceTransformer

from src.config import PUBLISHER_VERIFY_KEY_PATH, ROOTS_PATH
from src.crypto import load_verify_key
from src.merkle import attach_provenance


def retrieve(
    query: str,
    collection: chromadb.Collection,
    embed_model: SentenceTransformer,
    n_results: int = 5,
) -> list[dict]:
    """Embed query and return top-n_results chunks with provenance proof material.

    Each returned dict includes: chunk_id, doc_id, title, authors, published,
    text, distance, sha256, merkle_index, merkle_path, doc_leaf_hashes,
    merkle_root, root_signature, publisher_key_id, tampered, tamper_reason.
    """
    roots: dict = {}
    if ROOTS_PATH.exists():
        roots = json.loads(ROOTS_PATH.read_text())
    publisher_vk = load_verify_key(PUBLISHER_VERIFY_KEY_PATH)

    query_embedding = embed_model.encode([query], normalize_embeddings=True)[0].tolist()
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=n_results,
        include=["documents", "metadatas", "distances"],
    )

    chunks = [
        {
            "chunk_id":    results["metadatas"][0][i]["chunk_id"],
            "doc_id":      results["metadatas"][0][i]["doc_id"],
            "title":       results["metadatas"][0][i]["title"],
            "authors":     results["metadatas"][0][i].get("authors", ""),
            "published":   results["metadatas"][0][i].get("published", ""),
            "text":        results["documents"][0][i],
            "distance":    results["distances"][0][i],
            "sha256":      results["metadatas"][0][i]["sha256"],
            "merkle_index": results["metadatas"][0][i]["merkle_index"],
        }
        for i in range(len(results["ids"][0]))
    ]

    # One collection.get() per unique doc — batch, not per chunk
    doc_leaf_hashes: dict[str, list[str]] = {}
    for doc_id in {c["doc_id"] for c in chunks}:
        doc_result = collection.get(
            where={"doc_id": doc_id},
            include=["metadatas"],
        )
        sorted_metas = sorted(doc_result["metadatas"], key=lambda m: m["merkle_index"])
        doc_leaf_hashes[doc_id] = [m["sha256"] for m in sorted_metas]

    for chunk in chunks:
        doc_id = chunk["doc_id"]
        attach_provenance(chunk, doc_leaf_hashes[doc_id], roots.get(doc_id, {}), publisher_vk)

    return chunks
