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
    "Prefer the provided context when it is relevant. "
    "If the context does not address the question, answer from your general knowledge "
    "and do not cite any chunk IDs. Be concise."
)

USER_PROMPT_TEMPLATE = """\
Answer the following question using the context passages below when they are relevant.
If the context is not relevant to the question, answer from your general knowledge instead.
Only cite chunk IDs (e.g. [2307.03172v2__chunk000]) when the context directly supports your answer.

Question: {question}

Context:
{context_block}

Answer:"""
