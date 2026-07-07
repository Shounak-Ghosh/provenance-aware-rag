# Provenance-Aware RAG
A retrieval-augmented generation system where every answer carries a cryptographically verifiable citation chain linking it back to the exact source chunks used — and where any post-ingestion alteration of a source is automatically detected.

**Demo:** Ask a question, get an answer with cited sources. Tamper a source chunk. Re-ask. The affected citation flips to a tamper alert, and a standalone verifier (run from a separate process with only the public keys) independently confirms the answer is no longer trustworthy.

---

## How it works

The provenance layer wraps the standard RAG pipeline at three points without touching retrieval logic itself:

```
Corpus (arXiv abstracts, frozen to disk)
  │
  ▼  [write hook — ingest]
  SHA-256 each chunk → build per-doc Merkle tree → sign root with publisher key
  Store sha256 + merkle_index in Chroma; write signed DocumentRecord to roots.json
  │
  ▼  [retrieval]
  Embed query → cosine similarity → top-N chunks
  [read hook] Re-hash stored text → compare to recorded sha256 → verify Merkle path → verify root sig
  │
  ▼  [generation]
  LLM generates answer with inline chunk citations
  [answer hook] Bind chunk hashes + answer hash + query hash → sign with service key → attestation
```

Two keypairs keep "was the source altered?" and "was the answer forged?" independently auditable:

- **Publisher key** — signs the Merkle root of each ingested document. A consumer with only the public key can verify source integrity without trusting the vector store.
- **Service key** — signs each answer attestation. Proves a specific answer was produced from specific, verified chunks.

The trust anchor (`data/roots.json`, `data/attestation_log.jsonl`, `data/keys/*.vk`) lives deliberately outside the Chroma store an attacker would tamper.

---

## Architecture

```
src/
  ingest.py    fetch + chunk + embed + hash + build Merkle tree → Chroma + roots.json
  store.py     Chroma client factory
  retrieve.py  embed query → top-N chunks (read hook: tamper detection, coming Day 8)
  generate.py  LLM call with citation prompt; parse cited chunk IDs
  merkle.py    build_levels(), compute_root() — hand-rolled binary Merkle tree (~35 lines)
  crypto.py    Ed25519 sign/verify via PyNaCl
  schema.py    TypedDicts: ChunkRecord, DocumentRecord, Attestation
  config.py    pinned constants (chunk size, model names, key paths, trust-anchor paths)
  attestation.py  build_attestation(), sign/verify/append/load — answer hook (Day 10)
  verifier.py     find_chunk_by_hash(), verify_chunk(), verify_answer_hash() — standalone verifier internals (Day 11)
  intoto.py       sign_real_ite6_statement()/verify_real_ite6_statement()/decode_ite6_payload() — genuine in-toto Attestation Framework (ITE-6) export, optional extra (Day 12)

scripts/
  generate_keys.py   one-time Ed25519 keygen

data/
  corpus.json          frozen arXiv corpus (36 papers; never re-fetch after first run)
  roots.json           per-doc DocumentRecords with Merkle roots + signatures
  attestation_log.jsonl  append-only answer attestation log (populated Day 10)
  keys/
    publisher.vk       publisher public key (committed — trust anchor)
    service.vk         service public key (committed — trust anchor)
    publisher.sk       publisher signing key (gitignored)
    service.sk         service signing key (gitignored)
  chroma_db/           local Chroma vector store (gitignored)

app.py    Streamlit web UI
main.py   CLI batch runner
```

### Data model

**Chunk record** (stored in Chroma metadata)
```
chunk_id      "{doc_id}__chunk{j:03d}"
doc_id        arXiv short ID (e.g. "2307.03172v2")
sha256        hex SHA-256 of chunk text
merkle_index  0-based position in the per-document Merkle tree
```

**Document record** (stored in `data/roots.json`)
```
doc_id           arXiv short ID
merkle_root      hex SHA-256 Merkle root of all chunk hashes
root_signature   base64 Ed25519 signature of root bytes (publisher key)
publisher_key_id "publisher_v1"
ingested_at      ISO-8601 timestamp
```

**Attestation** (appended to `data/attestation_log.jsonl`, Day 10)
```
answer_sha256      hex SHA-256 of answer text
chunk_hashes       ordered list of sha256 for chunks placed in LLM context
query_sha256       hex SHA-256 of query text
model              LLM model ID
timestamp          ISO-8601
service_signature  base64 Ed25519 signature (service key)
service_key_id     "service_v1"
```

---

## Setup

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- OpenAI API key

### Install

```bash
git clone <repo-url>
cd provenance-aware-rag
uv sync
```

### Configure

Create a `.env` file at the project root:

```
OPENAI_API_KEY=sk-...
# Optional: switch to gpt-4o for the demo
# LLM_MODEL=gpt-4o
```

### Generate keypairs (one-time)

```bash
uv run python scripts/generate_keys.py
```

This writes four files to `data/keys/`. The `.vk` public-key files are committed as the trust anchor; the `.sk` private-key files are gitignored and must never be committed.

### Ingest

The corpus is fetched from arXiv on first run and frozen to `data/corpus.json`. On subsequent runs the frozen file is loaded — never re-fetched. Re-ingesting after the first run would invalidate all stored chunk hashes.

Ingest runs automatically when you start the app or `main.py`. To force a clean re-ingest (e.g. after changing chunking config):

```bash
rm -rf data/chroma_db/
uv run python main.py
```

---

## Running

### Streamlit demo (recommended)

```bash
uv run streamlit run app.py
```

Opens at `http://localhost:8501`. Ask any question about recent AI/ML research; the UI shows the answer with expandable citation chips listing the source paper, author, date, and similarity score.

### CLI batch runner

```bash
uv run python main.py
```

Runs a single hardcoded query and logs the retrieved chunks, LLM answer, and cited chunk IDs.

### Standalone verifier

Independently re-checks a signed attestation using only the two **public**
verify keys — no private signing key, no OpenAI key. It does read the local
Chroma store and `data/roots.json` to recover Merkle proof material, since the
attestation itself intentionally carries only content hashes (see
`verify.py`'s docstring for why).

```bash
# Check the most recent answer generated by the app
uv run python verify.py --log-index -1

# Check a JSON file downloaded from the UI's "Download attestation.json" button
uv run python verify.py --attestation attestation_2026-07-05T....json

# Also check the answer text itself against answer_sha256
uv run python verify.py --log-index -1 --answer-file answer.txt
```

Exits `0` and prints ✅ on a fully verified answer; exits `1` and prints ❌
with the specific failing check(s) the moment a source has been tampered,
the attestation signature doesn't check out, or a cited chunk hash no longer
exists in the store.

### in-toto export

Alongside the native signed attestation, the app and verifier can also
produce a genuine **in-toto Attestation Framework (ITE-6)** Statement — a
step toward the in-toto/TUF/gittuf line of provenance tooling this project
is meant to bridge to, and the direct bridge to the Cappos / Secure Systems
Lab conversation.

`src/intoto.py::sign_real_ite6_statement()` / `verify_real_ite6_statement()`
build and DSSE-sign a Statement matching the
[in-toto attestation spec](https://github.com/in-toto/attestation/blob/main/spec/predicates/link.md)
exactly: `{"_type": "https://in-toto.io/Statement/v1", "subject": [...],
"predicateType": "https://in-toto.io/attestation/link/v0.3", "predicate":
{"name", "command", "materials": [<ResourceDescriptor>, ...], "byproducts",
"environment"}}`, using the `in-toto-attestation` package's protobuf-backed
`Statement`/`ResourceDescriptor` classes and `securesystemslib`'s DSSE
`Envelope` for signing — both reference implementations for their
respective specs (ITE-6 and [DSSE](https://github.com/secure-systems-lab/dsse)).
Confirmed working end-to-end (sign → verify → tamper → verify fails).

```bash
# In the Streamlit UI: "Download in-toto link"
# — signed with the same service private key already used for the
# ordinary attestation, at the same trust boundary (generation/render time).

# Independently verify it, using only the service PUBLIC key:
uv run python verify.py --verify-ite6-statement ite6_statement_....json
```

The downloaded file is a DSSE envelope — its actual Statement content sits
base64-encoded inside a `payload` field, which isn't demo-readable as-is.
`src/intoto.py::decode_ite6_payload()` decodes it (display only, not a
verification step — pair with `verify_real_ite6_statement()` for that). In
the UI, the decoded Statement is shown inline in an expander right below the
download button; from the CLI, add `--show-statement`:

```bash
uv run python verify.py --verify-ite6-statement ite6_statement_....json --show-statement
```

Requires the optional `intoto` extra:

```bash
uv sync --extra intoto
```

If it isn't installed, the UI shows only the "Download attestation.json"
button and a caption explaining how to enable the in-toto one.

### Error handling

`verify.py` and the Streamlit app fail with a clear, specific message (not a
raw traceback) on the failure modes most likely to come up in a demo: a
missing or malformed attestation file, a `--log-index` out of range, a
missing signing/verify key (with a pointer to `scripts/generate_keys.py`),
an empty or absent Chroma store, a missing `data/roots.json`, and a
truncated/corrupt line in `data/attestation_log.jsonl` (skipped with a
warning rather than crashing the whole log). See `docs/THREAT_MODEL.md` for
what is *not* handled (key compromise, rotation, revocation) and why.
