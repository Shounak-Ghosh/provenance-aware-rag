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
