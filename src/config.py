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

# ── Provenance config (frozen; changing a key ID invalidates existing signatures) ──
PUBLISHER_KEY_ID = "publisher_v1"
SERVICE_KEY_ID   = "service_v1"

KEYS_DIR                   = Path("data/keys")
PUBLISHER_SIGNING_KEY_PATH = KEYS_DIR / "publisher.sk"
PUBLISHER_VERIFY_KEY_PATH  = KEYS_DIR / "publisher.vk"
SERVICE_SIGNING_KEY_PATH   = KEYS_DIR / "service.sk"
SERVICE_VERIFY_KEY_PATH    = KEYS_DIR / "service.vk"

ROOTS_PATH           = Path("data/roots.json")
ATTESTATION_LOG_PATH = Path("data/attestation_log.jsonl")

# ── OKF bundle config (parse/canonicalize/ingest, see src/okf.py) ────────────
OKF_COLLECTION_NAME = "okf_concepts"        # separate Chroma collection; same CHROMA_PATH
OKF_ROOTS_PATH       = Path("data/okf_roots.json")
OKF_BUNDLES_DIR      = Path("bundles")
OKF_CANON_VERSION    = "okf-concept/v1"     # domain separation + canonicalization version tag
OKF_PINS_VERSION     = "okf-pins/v1"

ACTOR_KEYS_DIR = KEYS_DIR / "actors"        # per-actor keyring

# ── Per-actor trust signatures (see src/trust.py) ─────────────────────────────
OKF_TRUST_VERSION   = "okf-trust/v1"
OKF_KEYRING_VERSION = "okf-keyring/v1"
ACTOR_KEYRING_PATH  = ACTOR_KEYS_DIR / "keyring.json"

# ── Attestation integrity at the run (see src/okf_attest.py) ─────────────────
OKF_RUNS_PATH           = Path("data/okf_runs.jsonl")
OKF_RUN_VERSION         = "okf-run/v1"                       # domain tag in the canonical run record
OKF_RUN_PREDICATE_NAME  = "okf-attested-computation-run"      # ITE-6 predicate `name` for a run statement

# ── Runtime enforcement: the admission gate (see src/enforce.py) ─────────────
# Separate from ATTESTATION_LOG_PATH on purpose: an OKF answer attestation signs
# concept hashes that live in the `okf_concepts` collection, so verify.py's
# --log-index mode (which resolves hashes against `arxiv_chunks`) must never see
# one. Same separation as okf_roots.json/roots.json and okf_concepts/arxiv_chunks.
OKF_ATTESTATION_LOG_PATH = Path("data/okf_attestation_log.jsonl")

OKF_TIER_ORDER = ("unverified", "machine-confirmed", "human-reviewed")  # SPEC §5.3 ladder, ascending
OKF_MIN_TIER   = "unverified"   # PERMISSIVE ON PURPOSE — see src/enforce.py's module docstring:
                                # a forged/unbacked trust claim is refused regardless of this floor,
                                # so the demo's refusals never depend on a hand-tuned policy.

OKF_SYSTEM_PROMPT = (
    "You are a careful data assistant answering from an organization's knowledge bundle. "
    "Every concept you were given has already passed cryptographic admission checks; "
    "concepts that failed were withheld from you entirely. "
    "Answer ONLY from the provided concepts. If they do not address the question, say so "
    "plainly rather than answering from general knowledge — an unsupported number is worse "
    "than no number here. Cite the concepts you used inline as [concept_id]."
)

OKF_USER_PROMPT_TEMPLATE = """\
Answer the question using ONLY the admitted concepts below.
Cite each concept you rely on inline by its exact id in square brackets, e.g. [metrics/revenue].
Never cite an id that does not appear below.

Question: {question}

Admitted concepts:
{context_block}

Answer:"""

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
