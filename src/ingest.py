import hashlib
import json
import logging
from datetime import datetime, timezone

import arxiv
import chromadb
from langchain_text_splitters import RecursiveCharacterTextSplitter
from sentence_transformers import SentenceTransformer

from src.config import CHUNK_OVERLAP, CHUNK_SIZE, CORPUS_PATH, PUBLISHER_KEY_ID, ROOTS_PATH
from src.merkle import compute_root


def fetch_corpus() -> list[dict]:
    """Load the frozen arXiv corpus from disk, or fetch and freeze it on first run.

    The frozen snapshot is the provenance anchor — signing happens over this exact
    artifact set. Never re-fetch after the first run; doing so changes doc content
    and invalidates any existing chunk hashes.
    """
    if CORPUS_PATH.exists():
        logging.info("corpus.json exists — loading from disk (frozen)")
        with open(CORPUS_PATH) as f:
            return json.load(f)

    logging.info("Fetching arXiv corpus...")
    queries = [
        "cat:cs.LG AND (transformer OR attention mechanism OR foundation model)",
        "cat:cs.CL AND (large language model OR retrieval augmented generation OR instruction tuning)",
        "cat:cs.AI AND (agent OR tool use OR chain of thought OR reasoning)",
    ]

    client = arxiv.Client(page_size=20, delay_seconds=3.0)
    seen: dict[str, dict] = {}

    for query in queries:
        search = arxiv.Search(
            query=query,
            max_results=17,
            sort_by=arxiv.SortCriterion.SubmittedDate,
        )
        for result in client.results(search):
            if result.entry_id not in seen:
                seen[result.entry_id] = {
                    "doc_id": result.get_short_id(),
                    "entry_id": result.entry_id,
                    "title": result.title,
                    "authors": [a.name for a in result.authors],
                    "abstract": result.summary,
                    "published": result.published.isoformat(),
                    "updated": result.updated.isoformat(),
                    "primary_category": result.primary_category,
                    "categories": result.categories,
                    "pdf_url": result.pdf_url,
                }

    papers = list(seen.values())
    CORPUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CORPUS_PATH, "w") as f:
        json.dump(papers, f, indent=2)
    logging.info("Wrote %d papers to %s", len(papers), CORPUS_PATH)
    return papers


def ingest(
    papers: list[dict],
    collection: chromadb.Collection,
    embed_model: SentenceTransformer,
) -> None:
    """Chunk, embed, and store paper abstracts into Chroma. Idempotent — skips if collection is non-empty.

    Chunk IDs follow the scheme ``{doc_id}__chunk{j:03d}``. CHUNK_SIZE and
    CHUNK_OVERLAP are pinned in config and must never change after the first
    ingest run — the Day 5 SHA-256 hashes are computed over chunk text, so any
    splitter change would silently invalidate every stored hash.
    """
    if collection.count() > 0:
        first = collection.get(limit=1, include=["metadatas"])
        if first["metadatas"] and "sha256" in first["metadatas"][0]:
            logging.info(
                "Collection already has %d chunks with provenance — skipping ingest",
                collection.count(),
            )
            return
        logging.warning(
            "Collection exists without provenance fields. "
            "Delete data/chroma_db/ and re-run to backfill hashes."
        )
        return

    logging.info("Ingesting %d papers into Chroma...", len(papers))
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP
    )

    for i, paper in enumerate(papers):
        chunks = splitter.split_text(paper["abstract"])
        if not chunks:
            continue
        chunk_ids = [f"{paper['doc_id']}__chunk{j:03d}" for j in range(len(chunks))]
        embeddings = embed_model.encode(chunks, normalize_embeddings=True).tolist()

        # ── provenance write hook ─────────────────────────────────────────────
        chunk_hashes = [hashlib.sha256(c.encode()).hexdigest() for c in chunks]
        merkle_root_hex = compute_root(chunk_hashes)

        metadatas = [
            {
                "chunk_id":     chunk_ids[j],
                "doc_id":       paper["doc_id"],
                "title":        paper["title"],
                "authors":      ", ".join(paper["authors"]),
                "published":    paper["published"],
                "chunk_index":  j,
                "sha256":       chunk_hashes[j],
                "merkle_index": j,
            }
            for j in range(len(chunks))
        ]
        collection.add(
            ids=chunk_ids,
            documents=chunks,
            embeddings=embeddings,
            metadatas=metadatas,
        )

        roots: dict = {}
        if ROOTS_PATH.exists():
            roots = json.loads(ROOTS_PATH.read_text())
        roots[paper["doc_id"]] = {
            "doc_id":           paper["doc_id"],
            "merkle_root":      merkle_root_hex,
            "root_signature":   "",
            "publisher_key_id": PUBLISHER_KEY_ID,
            "ingested_at":      datetime.now(timezone.utc).isoformat(),
        }
        ROOTS_PATH.write_text(json.dumps(roots, indent=2))
        logging.info(
            "[%d/%d] '%s' → %d chunk(s): %s",
            i + 1,
            len(papers),
            paper["doc_id"],
            len(chunks),
            ", ".join(chunk_ids),
        )

    logging.info("Ingest complete: %d chunks stored", collection.count())
