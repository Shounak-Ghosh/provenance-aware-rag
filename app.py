import hashlib
import json
import os

import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI
from sentence_transformers import SentenceTransformer

from src.attestation import append_attestation, build_attestation, sign_attestation, verify_attestation
from src.config import (
    EMBED_MODEL_NAME,
    LLM_MODEL,
    SERVICE_KEY_ID,
    SERVICE_SIGNING_KEY_PATH,
    SERVICE_VERIFY_KEY_PATH,
)
from src.crypto import load_signing_key, load_verify_key
from src.generate import generate, parse_citations
from src.ingest import fetch_corpus, ingest
from src.merkle import build_levels
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
        "attestation",
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

        # ── provenance answer hook ──────────────────────────────────────────
        attestation = build_attestation(question, answer, chunks, LLM_MODEL)
        service_sk = load_signing_key(SERVICE_SIGNING_KEY_PATH)
        attestation = sign_attestation(attestation, service_sk, SERVICE_KEY_ID)
        append_attestation(attestation)

    # Write all keys atomically so reruns never see partial state.
    st.session_state.answer = answer
    st.session_state.chunks = chunks
    st.session_state.cited_ids = cited_ids
    st.session_state.chunks_by_id = {c["chunk_id"]: c for c in chunks}
    st.session_state.last_question = question
    st.session_state.original_text_by_id = {c["chunk_id"]: c["text"] for c in chunks}
    st.session_state.attestation = attestation


def _refresh_chunks() -> None:
    """Re-run retrieve() only (not generate()) so the read hook re-checks every
    chunk's tamper status without changing the already-displayed answer text."""
    embed_model = load_embed_model()
    collection = load_collection()
    chunks = retrieve(st.session_state.last_question, collection, embed_model, n_results=5)
    st.session_state.chunks = chunks
    st.session_state.chunks_by_id = {c["chunk_id"]: c for c in chunks}


def _tamper_source_naive(chunk_id: str) -> None:
    corrupt_chunk(
        load_collection(),
        chunk_id,
        "This text has been maliciously altered.",
        update_hash=False,
    )
    _refresh_chunks()


def _tamper_source_sophisticated(chunk_id: str) -> None:
    corrupt_chunk(
        load_collection(),
        chunk_id,
        "This text and its stored hash were both forged.",
        update_hash=True,
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


def _render_hash_diff(chunk: dict) -> None:
    stored = chunk["sha256"]
    recomputed = hashlib.sha256(chunk["text"].encode()).hexdigest()
    ok = stored == recomputed
    css = "chip-verified" if ok else "chip-tampered"
    st.markdown(
        f"**Layer 1 — Content hash** &nbsp; "
        f"<span class='chip {css}'>{'✅ match' if ok else '❌ mismatch'}</span>",
        unsafe_allow_html=True,
    )
    st.code(f"stored:     {stored}\nrecomputed: {recomputed}", language=None)


def _render_merkle_tree(chunk: dict) -> None:
    leaf_hashes = chunk["doc_leaf_hashes"]
    levels = build_levels(leaf_hashes)  # levels[0]=leaves ... levels[-1]=[root]
    recomputed_root = levels[-1][0]
    signed_root = chunk["merkle_root"]
    root_ok = recomputed_root == signed_root

    # Walk the target index up through levels, marking self + sibling at each level.
    idx = chunk["merkle_index"]
    path_indices: list[tuple[int, int, bool]] = []
    for level_i in range(len(levels) - 1):
        sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
        path_indices.append((level_i, idx, True))
        path_indices.append((level_i, sibling_idx, False))
        idx //= 2
    path_indices.append((len(levels) - 1, 0, False))  # root

    root_css = "chip-verified" if root_ok else "chip-tampered"
    st.markdown(
        f"**Layer 2 — Merkle proof / signed root** &nbsp; "
        f"<span class='chip {root_css}'>"
        f"{'✅ root matches' if root_ok else '❌ root mismatch'}</span>",
        unsafe_allow_html=True,
    )
    for level_i in range(len(levels) - 1, -1, -1):  # root at top, leaves at bottom
        level = levels[level_i]
        # An odd-length level (below the root) gets its last node duplicated by
        # build_levels() to form a pair — render that phantom duplicate as a
        # ghost box so the pairing is visible instead of implicit.
        is_padded = level_i < len(levels) - 1 and len(level) % 2 == 1
        display_hashes = list(level) + ([level[-1]] if is_padded else [])
        boxes = []
        for node_i, node_hash in enumerate(display_hashes):
            is_ghost = is_padded and node_i == len(level)
            hit = next(
                (t for (li, ni, t) in path_indices if li == level_i and ni == node_i),
                None,
            )
            if level_i == len(levels) - 1:
                cls = "mk-root-ok" if root_ok else "mk-root-bad"
            elif hit is True:
                cls = "mk-target"
            elif hit is False:
                cls = "mk-sibling"
            else:
                cls = ""
            if is_ghost:
                cls += " mk-ghost"
                label = f"{node_hash[:8]}…"
            else:
                label = f"{node_hash[:8]}…"
            boxes.append(f'<span class="mk-node {cls}">{label}</span>')
        st.markdown(f'<div class="mk-level">{"".join(boxes)}</div>', unsafe_allow_html=True)
    st.code(f"recomputed root: {recomputed_root}\nsigned root:     {signed_root}", language=None)


def _render_signature_status(chunk: dict) -> None:
    reason = chunk["tamper_reason"]
    if reason == "verified":
        status = f"✅ valid (publisher key: {chunk['publisher_key_id']})"
    elif reason == "root signature invalid":
        status = "❌ invalid"
    elif reason in ("content hash mismatch", "merkle proof failed"):
        status = "⏭️ not reached (short-circuited by an earlier layer)"
    else:
        status = "❌ no signed root for document"
    st.markdown(f"**Layer 3 — Root signature** &nbsp; {status}")


def _render_attestation(attestation: dict) -> None:
    service_vk = load_verify_key(SERVICE_VERIFY_KEY_PATH)
    valid = verify_attestation(attestation, service_vk)
    css_class, label = (
        ("chip-verified", "✅ answer attestation signed")
        if valid
        else ("chip-tampered", "❌ attestation signature invalid")
    )
    st.markdown(
        f'<span class="chip {css_class}" '
        f'title="Self-check only — see Day 11 standalone verifier for an independent check">'
        f"{label}</span>",
        unsafe_allow_html=True,
    )
    with st.expander("Attestation details"):
        st.code(json.dumps(attestation, indent=2), language="json")
        st.download_button(
            "Download attestation.json",
            data=json.dumps(attestation, indent=2),
            file_name=f"attestation_{attestation['timestamp']}.json",
            mime="application/json",
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
    .mk-level{display:flex;justify-content:center;gap:8px;margin:4px 0;flex-wrap:wrap;}
    .mk-node{padding:3px 8px;border-radius:6px;font-family:monospace;font-size:0.75rem;border:2px solid #999;background:#f0f0f0;color:#333;}
    .mk-target{border-color:#1565c0;font-weight:700;}
    .mk-sibling{border-color:#f9a825;}
    .mk-root-ok{background:#1e7e34;color:white;border-color:#1e7e34;}
    .mk-root-bad{background:#c62828;color:white;border-color:#c62828;}
    .mk-ghost{border-style:dashed;opacity:0.6;font-style:italic;}
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
    _render_attestation(st.session_state.attestation)

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

                st.divider()
                _render_hash_diff(chunk)
                _render_merkle_tree(chunk)
                _render_signature_status(chunk)
                st.divider()

                col1, col2, col3 = st.columns(3)
                with col1:
                    if st.button("🧪 Tamper (naive)", key=f"tamper_naive_{chunk_id}"):
                        _tamper_source_naive(chunk_id)
                        st.rerun()
                with col2:
                    if st.button(
                        "🧪🔧 Tamper (sophisticated)", key=f"tamper_sneaky_{chunk_id}"
                    ):
                        _tamper_source_sophisticated(chunk_id)
                        st.rerun()
                with col3:
                    if chunk["tampered"] and st.button(
                        "🧹 Restore", key=f"restore_{chunk_id}"
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
