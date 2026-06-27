import chromadb
from sentence_transformers import SentenceTransformer


def retrieve(
    query: str,
    collection: chromadb.Collection,
    embed_model: SentenceTransformer,
    n_results: int = 5,
) -> list[dict]:
    """Embed ``query`` and return the top-``n_results`` chunks by cosine similarity.

    Each returned dict contains: ``chunk_id``, ``doc_id``, ``title``, ``text``,
    ``distance`` (lower = more similar). The Day 5 read hook will extend this
    to also verify each chunk's SHA-256 and Merkle proof before returning.
    """
    query_embedding = embed_model.encode([query], normalize_embeddings=True)[0].tolist()
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=n_results,
        include=["documents", "metadatas", "distances"],
    )
    return [
        {
            "chunk_id": results["metadatas"][0][i]["chunk_id"],
            "doc_id": results["metadatas"][0][i]["doc_id"],
            "title": results["metadatas"][0][i]["title"],
            "text": results["documents"][0][i],
            "distance": results["distances"][0][i],
        }
        for i in range(len(results["ids"][0]))
    ]
