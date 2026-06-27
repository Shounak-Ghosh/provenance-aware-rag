import os
from pathlib import Path

CORPUS_PATH = Path("data/corpus.json")
CHROMA_PATH = "data/chroma_db"
COLLECTION_NAME = "arxiv_chunks"
CHUNK_SIZE = 512  # NEVER change after first ingest; hashes are computed over chunk text
CHUNK_OVERLAP = 64  # NEVER change after first ingest
EMBED_MODEL_NAME = "BAAI/bge-small-en-v1.5"
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")  # set in .env; switch to gpt-4o for demo
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
