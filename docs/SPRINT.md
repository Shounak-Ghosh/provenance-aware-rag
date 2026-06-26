# Provenance-Aware RAG — 2-Week Sprint Spec

## Goal

Build a RAG system where every generated answer carries a cryptographically signed, independently verifiable citation chain linking the answer back to the exact source chunks used to produce it — and where any post-ingestion alteration of a source is automatically detected and surfaced.

**The demo money-shot:** ask a question, get an answer with green "verified" citation chips. Click a "Tamper a source" button that mutates one indexed chunk. Re-ask. The affected citation flips to red, the tamper alert fires, and a standalone verifier (run from a separate process with only the public keys) independently confirms the answer is no longer trustworthy.

The one-liner for the showcase: *"You all built RAG. I built RAG you can audit."*

---

## Scope and the cut line

This is sequenced so a working system exists early and provenance is layered on top. If the bootcamp's own coursework eats the back half of the sprint, **Day 8 is the MVP cut line** — everything through Day 8 is a complete, demoable, on-thesis project on its own (signed sources + tamper detection at retrieval). Days 9–14 turn it from a feature into a small platform.

- **MVP (Days 1–8):** plain RAG + signed source corpus + tamper detection on retrieval.
- **Full (Days 9–13):** verification in the UI + answer attestation + standalone verifier.
- **Stretch (Day 12):** in-toto link format for the attestation — the direct bridge to the Cappos / Secure Systems Lab conversation. Cut first if time is short.

---

## Tech stack

Deliberately boring where it can be, so the novel part gets the time. Finalized:

- **Language:** Python 3.11+
- **Corpus:** arXiv API (via the `arxiv` package), ~20–50 papers in the AI/ML/NLP/agent space. Pull **abstracts + metadata** as the Day-1 corpus — guaranteed-clean text, zero PDF-parsing risk, and perfectly tamper-demoable. Full-text for a handful of papers is optional enrichment *after* the pipeline works end to end. Pull the set **once and freeze it to disk** as the working corpus (see design note below).
- **Chunking:** LangChain `RecursiveCharacterTextSplitter`, with size + overlap **pinned and versioned** — the hash is computed over chunk text, so changing splitter config after ingestion changes every hash. Don't churn the params.
- **Embeddings:** `sentence-transformers` local — `bge-small-en-v1.5` (slightly better retrieval) or `all-MiniLM-L6-v2` (faster). Embeddings sit *outside* the trust boundary; tampering one is a retrieval-selection attack (out of scope), and any chunk that is retrieved still gets its text integrity checked.
- **Vector store:** **Chroma**, local, on disk. At this scale FAISS's speed/scale edge is irrelevant, and Chroma stores documents + metadata + embeddings together — so `sha256`, `doc_id`, and `merkle_index` drop straight into the metadata dict instead of needing a hand-rolled sidecar store.
- **LLM:** OpenAI API — `gpt-4o-mini` during dev for cost, `gpt-4o` for the demo. Set `temperature=0` so demo runs are reproducible.
- **Crypto:** `cryptography` or `PyNaCl` for Ed25519 signing (PyNaCl is the gentler API); `hashlib` for SHA-256; a small hand-rolled Merkle tree (≈60 lines).
- **Demo UI:** **Streamlit** (new to the builder; worth learning). Manage the tamper-then-requery flow through `st.session_state`, and wrap the embedding model and Chroma client in `st.cache_resource` so they don't reload on every rerun. Gradio is the fallback if Streamlit's whole-script-rerun model fights the stateful tamper button.
- **Stretch:** `in-toto` (python) for link-format attestations.

### Two design notes

**Corpus as anchor.** Pulling the arXiv set once and freezing it to disk isn't just reproducibility hygiene — the frozen snapshot *is* the thing you sign. You're signing a specific, immutable artifact set, which is exactly the mental model TUF and in-toto operate on: the corpus freeze and the provenance anchor are the same act. Say this out loud in the README.

**Signed roots out of Chroma.** Per-chunk hashes living in Chroma metadata is fine — security rests on the signed Merkle root, not on the store's integrity (that's the whole point of the "sophisticated case" in the tamper example). But the **signed roots, the attestation log, and the public keys are the trust anchor**, so they must *not* sit in the same store an attacker would be tampering. Keep them in a separate file (e.g. `roots.json` + an append-only attestation log) that the verifier treats as authoritative. Keep the anchor out of the blast radius.

---

## Data model

Lock this on Day 4 and don't churn it.

**Chunk record**
- `chunk_id`, `doc_id`, `text`, `sha256` (of `text`), `embedding_ref`, `merkle_index`

**Document record**
- `doc_id`, `merkle_root`, `root_signature` (Ed25519, publisher key), `publisher_key_id`, `ingested_at`

**Attestation** (produced per answer)
- `answer_sha256`, `chunk_hashes` (the set actually placed in context), `query_sha256`, `model`, `timestamp`, `service_signature` (Ed25519, service key), `service_key_id`

Two keypairs: a **publisher** key (signs the source corpus at ingestion) and a **service** key (signs answers at generation). Keeping them distinct is what lets you reason about "was the source altered" separately from "was the answer forged."

**Storage split:** chunk records (text, `sha256`, `merkle_index`, embedding) live in Chroma metadata. The document records' **signed roots, the attestation log, and the public keys** live in a separate authoritative file set (`roots.json` + an append-only attestation log) — the trust anchor, deliberately outside the store an attacker would tamper.

---

## Where provenance slots into the pipeline

The layer wraps the standard pipeline at three points and never modifies retrieval logic itself:

1. **Write hook (ingestion).** After chunking, SHA-256 each chunk, build a per-document Merkle tree, and sign the root with the publisher key. The source corpus is now tamper-evident.
2. **Read hook (retrieval).** For each retrieved chunk: re-hash the stored text, compare to the recorded hash, verify the Merkle path against the signed root, and verify the root signature. Any failure flags that chunk as tampered.
3. **Answer hook (generation).** Collect the chunk hashes actually passed into the LLM context, bind them to the answer hash and query hash, and sign the bundle with the service key. That signed bundle is the citation chain.

A consumer holding only the two public keys can then verify, with no access to the system, that (a) each cited chunk is intact and belongs to its signed document, (b) the attestation signature is valid, and (c) the answer they're looking at matches the attested hash.

---

## Day-by-day

### Phase 0 — Foundations and vertical slice (Days 1–4)

**Day 1 — Scaffold + plain RAG skeleton.**
Repo, venv, deps. Pull the arXiv set and freeze it to disk. Implement ingest → chunk → embed → Chroma → retrieve → single LLM call.
*Done when:* a terminal query returns an answer with raw chunk IDs in the logs.

**Day 2 — Modularize + non-cryptographic citations.**
Refactor into `ingest.py`, `store.py`, `retrieve.py`, `generate.py`. Prompt the LLM to cite chunk IDs inline; parse and surface them.
*Done when:* the answer reports which chunk IDs it used.

**Day 3 — Minimal demo UI.**
Streamlit: query box, answer, citation chips that reveal source text on click. Cache the embedding model and Chroma client with `st.cache_resource`.
*Done when:* a non-technical person can ask a question and see cited sources in a browser.

**Day 4 — Vertical-slice checkpoint + provenance schema.**
Freeze the data model above, including the Chroma-vs-anchor storage split. Generate publisher + service keypairs (PyNaCl or `cryptography`). Stand up the `roots.json` + attestation-log files.
*Done when:* schema and keys are committed; the plain RAG demo works end to end.

### Phase 1 — Provenance write path (Days 5–7)

**Day 5 — Hashing + per-document Merkle tree at ingest.**
SHA-256 per chunk; build the Merkle tree per document; compute and store the root and each chunk's `merkle_index`.
*Done when:* every chunk has a stored hash and a derivable Merkle path to its document root.

**Day 6 — Sign the Merkle root (write hook).**
Ed25519-sign each document root at ingest with the publisher key; store signature + key id. Implement `verify_root_signature()`.
*Done when:* each document's root is signed and the signature verifies.

**Day 7 — Provenance store wiring + Merkle proofs.**
Implement `merkle_proof(chunk)` and `verify_proof(chunk_hash, path, root)`. Make retrieval return each chunk bundled with its hash, Merkle path, and signed root.
*Done when:* for any retrieved chunk you can prove membership in its signed document.

### Phase 2 — Verify and tamper detection (Days 8–10)

**Day 8 — Tamper detection at read (read hook) + MID-SPRINT CHECKPOINT.**
On retrieval, recompute the hash from stored text, compare to the recorded hash, verify the Merkle path and root signature. Mismatch → mark chunk tampered. Add a `corrupt_chunk()` helper for the demo.
**This is the MVP cut line** — if behind, stop here and polish.
*Done when:* altering a stored chunk causes a tamper flag on the next retrieval.

**Day 9 — Surface verification status in the UI.**
Citation chips render green (verified) / red (tampered) with a tooltip naming what was checked. Add a "Tamper a source" button that mutates one chunk and re-runs.
*Done when:* the demo visibly flips a citation to red when a source is altered.

**Day 10 — Answer attestation (answer hook).**
After generation, collect the chunk hashes actually used; build the attestation object; sign it with the service key; persist and expose it.
*Done when:* every answer produces a signed attestation.

### Phase 3 — Verifier, bridge, and ship (Days 11–14)

**Day 11 — Standalone verifier.**
A separate `verify.py` / CLI taking an attestation + the two public keys, verifying independently: answer hash matches, each cited chunk verifies and proves Merkle membership, attestation signature valid.
*Done when:* the verifier passes on a good answer and fails loudly on a tampered one.

**Day 12 — in-toto formatting (stretch / Cappos bridge) + hardening.**
Emit the attestation in in-toto link format; verify with python in-toto if time allows. Add error handling and key-management notes. Cut to "documented as next step" if short.
*Done when:* the attestation exports as an in-toto link, or the gap is clearly documented.

**Day 13 — Demo polish + recorded walkthrough.**
Tighten the UI. Script the 2-minute demo: ask → verified citations → tamper a source → detection → independent verifier. Record it.
*Done when:* a recorded 2-minute demo exists.

**Day 14 — Ship.**
README (problem, architecture, run instructions, threat model, what's verified, limitations), repo cleanup, LICENSE, and a drafted LinkedIn/showcase post.
*Done when:* a stranger can clone, run, and understand it; the post is drafted.

---

## Threat model and honest limitations

State these plainly in the README — the boundary is what makes the project credible.

**Defends against:**
- Post-ingestion alteration of source content (caught by the read hook).
- Forged or swapped citations (the attestation binds the answer to specific chunk hashes).
- Answer tampering after generation (answer hash is signed).

**Does not defend against:**
- A malicious or careless publisher signing bad content — this proves *provenance, not truth*.
- Compromise of either signing key.
- Prompt-injection of the generation step itself (that's the adversarial-eval project's job — a natural follow-on).

This honest scoping is the right instinct to carry into the Secure Systems Lab conversation: the system makes a precise, defensible claim and doesn't overstate it.

---

## What "shipped" looks like on Day 14

A public repo containing: the RAG pipeline, the provenance layer, the demo UI, the standalone verifier, a recorded 2-minute demo, and a README with the architecture and threat model. That artifact alone supports the showcase entry, the LinkedIn narrative, and the fall lab pitch — and the provenance proxy and adversarial-eval harness both bolt directly onto it as the next two builds.
