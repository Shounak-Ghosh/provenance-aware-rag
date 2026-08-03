from typing import TypedDict


class ChunkRecord(TypedDict):
    chunk_id:     str  # "{doc_id}__chunk{j:03d}"
    doc_id:       str
    text:         str
    sha256:       str  # hex SHA-256 of text; populated Day 5
    merkle_index: int  # 0-based position in per-doc Merkle tree; populated Day 5


class DocumentRecord(TypedDict):
    doc_id:           str
    merkle_root:      str  # hex SHA-256 Merkle root; populated Day 5
    root_signature:   str  # base64 Ed25519 signature of root bytes; populated Day 6
    publisher_key_id: str
    ingested_at:      str  # ISO-8601


class Attestation(TypedDict):
    answer_sha256:     str        # hex SHA-256 of answer text
    chunk_hashes:      list[str]  # ordered sha256 list for chunks placed in LLM context
    query_sha256:      str        # hex SHA-256 of query text
    model:             str
    timestamp:         str        # ISO-8601
    service_signature: str        # base64 Ed25519 sig of canonical payload; populated Day 10
    service_key_id:    str


# ── OKF (Open Knowledge Format) records ──────────────────────────────────────
# A "concept" is to a bundle what a chunk is to an arXiv paper (see src/okf.py).

class ConceptRecord(TypedDict):
    concept_id:       str   # bundle-relative path minus .md, e.g. "metrics/revenue" (SPEC §2)
    bundle_id:        str
    rel_path:         str   # "metrics/revenue.md" — resolves concept-relative body links
    type:             str   # OKF `type` (§4.1); "" if absent
    title:            str
    frontmatter:      dict  # parsed YAML, normalized (dates -> ISO strings, NFC; see okf.py)
    frontmatter_json: str   # canonical JSON of `frontmatter` — the exact bytes that were hashed
    body:             str   # verbatim text after the closing --- fence
    sha256:           str   # hex SHA-256 over okf.canonicalize_concept(frontmatter, body)
    merkle_index:     int   # 0-based position in the concept_id-sorted concept list


class BundleRecord(TypedDict):   # mirrors DocumentRecord field-for-field
    bundle_id:        str
    merkle_root:      str
    root_signature:   str        # base64 Ed25519 over bytes.fromhex(merkle_root), publisher key
    publisher_key_id: str
    signed_at:        str        # ISO-8601


class TrustSignature(TypedDict):  # one per authenticated verified/generated entry (Phase 3)
    concept_id: str
    actor:      str              # "human:jsmith@acme", "process:finance-nightly", "<producer>/<ver>"
    at:         str
    kind:       str              # "verified" | "generated"
    signature:  str              # base64 Ed25519 over (concept_sha256|actor|at|kind), actor key


class ComputationPins(TypedDict):  # signed at bundle-sign time; enables §10 hardening (Phase 5)
    concept_id:         str
    computation_sha256: str      # over the canonicalized `# Computation` fence or `computation:` file
    attester_sha256:    str      # over the raw attester resource bytes
    attester_resource:  str      # bundle-root-relative path, so verifiers can locate it
    pins_signature:     str      # base64 Ed25519 over the pins message, publisher key
