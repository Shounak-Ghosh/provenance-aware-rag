import json
import logging
import os
from pathlib import Path

import arxiv
import chromadb
from dotenv import load_dotenv
from langchain_text_splitters import RecursiveCharacterTextSplitter
from openai import OpenAI
from sentence_transformers import SentenceTransformer

load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)

# -- Constants (NEVER change after first ingest; hashes are computed over chunk text) --
CORPUS_PATH = Path("data/corpus.json")
CHROMA_PATH = "data/chroma_db"
COLLECTION_NAME = "arxiv_chunks"
CHUNK_SIZE = 512
CHUNK_OVERLAP = 64
EMBED_MODEL_NAME = "BAAI/bge-small-en-v1.5"
LLM_MODEL = "gpt-4o-mini"
LLM_TEMPERATURE = 0

SYSTEM_PROMPT = (
    "You are a precise research assistant. "
    "Answer using only the provided context. Be concise."
)

USER_PROMPT_TEMPLATE = """\
Answer the following question using only the context passages below.
Cite the chunk IDs that support your answer in square brackets, e.g. [2307.03172v2__chunk000].

Question: {question}

Context:
{context_block}

Answer:"""


def fetch_corpus() -> list[dict]:
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
    if collection.count() > 0:
        logging.info(
            "Collection already has %d chunks — skipping ingest", collection.count()
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
        metadatas = [
            {
                "chunk_id": chunk_ids[j],
                "doc_id": paper["doc_id"],
                "title": paper["title"],
                "authors": ", ".join(paper["authors"]),
                "published": paper["published"],
                "chunk_index": j,
            }
            for j in range(len(chunks))
        ]
        collection.add(
            ids=chunk_ids,
            documents=chunks,
            embeddings=embeddings,
            metadatas=metadatas,
        )
        logging.info(
            "[%d/%d] '%s' → %d chunk(s): %s",
            i + 1,
            len(papers),
            paper["doc_id"],
            len(chunks),
            ", ".join(chunk_ids),
        )

    logging.info("Ingest complete: %d chunks stored", collection.count())


def retrieve(
    query: str,
    collection: chromadb.Collection,
    embed_model: SentenceTransformer,
    n_results: int = 5,
) -> list[dict]:
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


def generate(question: str, chunks: list[dict], client: OpenAI) -> str:
    context_block = "\n\n".join(
        f"[{c['chunk_id']}] (from: {c['title']})\n{c['text']}" for c in chunks
    )
    user_msg = USER_PROMPT_TEMPLATE.format(
        question=question, context_block=context_block
    )
    response = client.chat.completions.create(
        model=LLM_MODEL,
        temperature=LLM_TEMPERATURE,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
    )
    return response.choices[0].message.content


def main() -> None:
    papers = fetch_corpus()
    logging.info("Corpus: %d papers loaded", len(papers))

    logging.info("Loading embedding model: %s", EMBED_MODEL_NAME)
    embed_model = SentenceTransformer(EMBED_MODEL_NAME)

    chroma_client = chromadb.PersistentClient(path=CHROMA_PATH)
    collection = chroma_client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )

    ingest(papers, collection, embed_model)

    openai_client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    question = "What are the main techniques used to improve reasoning in large language models?"
    logging.info("QUERY: %s", question)

    chunks = retrieve(question, collection, embed_model, n_results=5)
    logging.info("Retrieved %d chunks:", len(chunks))
    for c in chunks:
        logging.info(
            "  chunk_id=%-35s  dist=%.4f  title=%s",
            c["chunk_id"],
            c["distance"],
            c["title"][:60],
        )

    answer = generate(question, chunks, openai_client)
    logging.info("ANSWER:\n%s", answer)


if __name__ == "__main__":
    main()
