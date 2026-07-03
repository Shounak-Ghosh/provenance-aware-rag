import os

import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI
from sentence_transformers import SentenceTransformer

from src.config import EMBED_MODEL_NAME
from src.generate import generate, parse_citations
from src.ingest import fetch_corpus, ingest
from src.retrieve import retrieve
from src.store import corrupt_chunk, get_collection

load_dotenv()

# Must be the first Streamlit call in the script.
st.set_page_config(
    page_title="Provenance-Aware RAG",
    page_icon="🔍",
    layout="centered",
)


@st.cache_resource
def load_embed_model() -> SentenceTransformer:
    return SentenceTransformer(EMBED_MODEL_NAME)


@st.cache_resource
def load_collection():
    """Return the Chroma collection, ensuring the corpus is ingested (idempotent)."""
    embed_model = load_embed_model()
    papers = fetch_corpus()
    collection = get_collection()
    ingest(papers, collection, embed_model)
    return collection


@st.cache_resource
def load_openai_client() -> OpenAI:
    return OpenAI(api_key=os.environ["OPENAI_API_KEY"])


def _init_session_state() -> None:
    for key in (
        "answer",
        "chunks",
        "cited_ids",
        "chunks_by_id",
        "last_question",
        "original_text_by_id",
    ):
        if key not in st.session_state:
            st.session_state[key] = None


def _run_query(question: str) -> None:
    embed_model = load_embed_model()
    collection = load_collection()
    openai_client = load_openai_client()

    with st.spinner("Retrieving and generating…"):
        chunks = retrieve(question, collection, embed_model, n_results=5)
        answer = generate(question, chunks, openai_client)
        cited_ids = parse_citations(answer)

    # Write all keys atomically so reruns never see partial state.
    st.session_state.answer = answer
    st.session_state.chunks = chunks
    st.session_state.cited_ids = cited_ids
    st.session_state.chunks_by_id = {c["chunk_id"]: c for c in chunks}
    st.session_state.last_question = question
    st.session_state.original_text_by_id = {c["chunk_id"]: c["text"] for c in chunks}


def _refresh_chunks() -> None:
    """Re-run retrieve() only (not generate()) so the read hook re-checks every
    chunk's tamper status without changing the already-displayed answer text."""
    embed_model = load_embed_model()
    collection = load_collection()
    chunks = retrieve(st.session_state.last_question, collection, embed_model, n_results=5)
    st.session_state.chunks = chunks
    st.session_state.chunks_by_id = {c["chunk_id"]: c for c in chunks}


def _tamper_source(chunk_id: str) -> None:
    corrupt_chunk(
        load_collection(),
        chunk_id,
        "This text has been maliciously altered.",
        update_hash=False,
    )
    _refresh_chunks()


def _restore_source(chunk_id: str) -> None:
    original = st.session_state.original_text_by_id[chunk_id]
    corrupt_chunk(load_collection(), chunk_id, original, update_hash=True)
    _refresh_chunks()


def _render_chip(chunk: dict) -> None:
    if chunk["tampered"]:
        css_class, label = "chip-tampered", "🚫 tampered"
        tooltip = f"Failed check: {chunk['tamper_reason']}"
    else:
        css_class, label = "chip-verified", "✅ verified"
        tooltip = "Checked: content hash, Merkle path, root signature — all passed"
    st.markdown(
        f'<span class="chip {css_class}" title="{tooltip}">{label}</span>',
        unsafe_allow_html=True,
    )


def _format_expander_label(position: int, chunk: dict) -> str:
    title_short = chunk["title"][:55] + ("…" if len(chunk["title"]) > 55 else "")
    authors_str = chunk.get("authors", "")
    first_author = authors_str.split(",")[0].strip() if authors_str else "Unknown"
    author_label = f"{first_author} et al." if "," in authors_str else first_author
    published = chunk.get("published", "")[:10]
    return f"[{position}] {title_short} · {author_label} · {published}"


# ── UI ──────────────────────────────────────────────────────────────────────

_init_session_state()

st.title("Provenance-Aware RAG")
st.caption("Ask a question about recent AI/ML research. Cited sources expand on click.")

st.markdown(
    """<style>
    [data-testid='stFormSubmitButton']{display:none}
    .chip{display:inline-block;padding:2px 10px;border-radius:12px;font-size:0.85rem;font-weight:600;color:white;}
    .chip-verified{background:#1e7e34;}
    .chip-tampered{background:#c62828;}
    </style>""",
    unsafe_allow_html=True,
)

with st.form("query_form"):
    question = st.text_input(
        "Your question",
        placeholder="What are the main techniques used to improve reasoning in LLMs?",
    )
    submitted = st.form_submit_button()

if submitted and question.strip():
    _run_query(question)

# ── Results ─────────────────────────────────────────────────────────────────

if st.session_state.answer is not None:
    st.subheader("Answer")
    st.markdown(st.session_state.answer)

    cited_ids: list[str] = st.session_state.cited_ids or []
    chunks_by_id: dict = st.session_state.chunks_by_id or {}

    if cited_ids:
        st.subheader("Sources cited")
        for position, chunk_id in enumerate(cited_ids, start=1):
            chunk = chunks_by_id.get(chunk_id)
            if chunk is None:
                continue  # LLM cited a chunk_id not in the retrieved set
            _render_chip(chunk)
            label = _format_expander_label(position, chunk)
            with st.expander(label):
                st.markdown(f"**{chunk['title']}**")
                if chunk.get("authors"):
                    st.caption(chunk["authors"])
                if chunk.get("published"):
                    st.caption(f"Published: {chunk['published'][:10]}")
                st.divider()
                st.markdown(chunk["text"])
                similarity = 1.0 - chunk["distance"]
                st.caption(f"Similarity: {similarity:.1%}  ·  chunk `{chunk_id}`")

                col1, col2 = st.columns(2)
                with col1:
                    if st.button("🧪 Tamper this source", key=f"tamper_{chunk_id}"):
                        _tamper_source(chunk_id)
                        st.rerun()
                with col2:
                    if chunk["tampered"] and st.button(
                        "🧹 Restore this source", key=f"restore_{chunk_id}"
                    ):
                        _restore_source(chunk_id)
                        st.rerun()
    else:
        st.info("The model did not cite any specific sources for this answer.")

    with st.expander("All retrieved chunks (debug)", expanded=False):
        for chunk in (st.session_state.chunks or []):
            _render_chip(chunk)
            st.markdown(f"**{chunk['chunk_id']}** — {chunk['title'][:60]}")
            st.markdown(chunk["text"])
            st.caption(f"distance={chunk['distance']:.4f}")
            st.divider()
