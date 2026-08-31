from typing import TypedDict


class ChunkRecord(TypedDict):
    chunk_id:     str  # "{doc_id}__chunk{j:03d}"
    doc_id:       str
    text:         str
    sha256:       str  # hex SHA-256 of text
    merkle_index: int  # 0-based position in per-doc Merkle tree


class DocumentRecord(TypedDict):
    doc_id:           str
    merkle_root:      str  # hex SHA-256 Merkle root
    root_signature:   str  # base64 Ed25519 signature of root bytes
    publisher_key_id: str
    ingested_at:      str  # ISO-8601


class Attestation(TypedDict):
    answer_sha256:     str        # hex SHA-256 of answer text
    chunk_hashes:      list[str]  # ordered sha256 list for chunks placed in LLM context
    query_sha256:      str        # hex SHA-256 of query text
    model:             str
    timestamp:         str        # ISO-8601
    service_signature: str        # base64 Ed25519 sig of canonical payload
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


class TrustSignature(TypedDict):  # one per authenticated verified/generated entry (see src/trust.py)
    bundle_id:  str
    concept_id: str
    actor:      str              # "human:jsmith@acme", "process:finance-nightly", "<producer>/<ver>"
    at:         str
    kind:       str              # "verified" | "generated"
    signature:  str              # base64 Ed25519 over trust_message(...), actor key


class ComputationPins(TypedDict):  # signed at bundle-sign time; enables §10 hardening (see src/okf_attest.py)
    concept_id:         str
    computation_sha256: str      # over the canonicalized `# Computation` fence or `computation:` file
    attester_sha256:    str      # over the raw attester resource bytes
    attester_resource:  str      # bundle-root-relative path, so verifiers can locate it
    pins_signature:     str      # base64 Ed25519 over the pins message, publisher key


class ActorKeyRecord(TypedDict):  # one entry per actor in data/keys/actors/keyring.json
    key_id:      str
    verify_key:  str             # base64 32-byte Ed25519 public key
    sk_file:     str             # filename under data/keys/actors/, gitignored
    kind:        str             # "human" | "team" | "process" | "agent" (§7 convention)


class TrustAssessment(TypedDict):  # per-concept output of trust.derive_authenticated_tier
    concept_id:    str
    claimed_tier:  str            # derived from the plaintext `verified` YAML alone (§5.3)
    tier:          str            # derived only from SIGNATURE-BACKED verified entries
    authenticated: list[str]      # actors whose verified entry carries a valid signature
    unbacked:      list[str]      # claimed verified actor with no signature at all
    unknown_actor: list[str]      # claimed actor absent from the keyring
    invalid:       list[str]      # signature present but does not verify
    downgraded:    bool           # tier != claimed_tier


# ── Attestation integrity at the run ──────────────────────────────────────────
# A "run" executes ONE Attested Computation concept under the digests that were
# PINNED (and publisher-signed) at bundle-sign time -- see src/okf_attest.py.

class RunReceipt(TypedDict):     # what an executor (e.g. skills/run-on-bq.md) returns
    job_id:       str
    executed_sql: str
    result:       list


class RunVerdict(TypedDict):     # what a concept's attester returns
    ok:      bool
    reason:  str | None
    details: dict


class AdmissionDecision(TypedDict):  # per-concept output of enforce.admit_concept
    concept_id:    str
    admitted:      bool
    reasons:       list[str]      # every failed check, not just the first (see src/enforce.py)
    warnings:      list[str]      # noted but non-blocking (e.g. a stale source, unparsable stale_after)
    checks:        dict           # check name -> {"ok": bool, "reason": str}, for ✅/❌ rendering
    trust:         TrustAssessment
    tier:          str            # trust["tier"], lifted for convenience
    claimed_tier:  str            # trust["claimed_tier"] — what a signal-trusting consumer would see


class OkfAnswerAttestation(TypedDict):  # one line of data/okf_attestation_log.jsonl
    answer_sha256:       str
    concept_hashes:      list[str]  # sha256 of every ADMITTED concept placed in the LLM's context
    concept_ids:         list[str]
    refused_concept_ids: list[str]  # signed: proves absence-by-policy, not absence-by-luck
    query_sha256:        str
    bundle_id:           str
    model:               str
    timestamp:           str
    service_signature:   str
    service_key_id:      str


class RunRecord(TypedDict):      # one line of data/okf_runs.jsonl, service-key signed
    run_version:          str    # OKF_RUN_VERSION
    bundle_id:            str
    concept_id:           str
    concept_sha256:        str   # the concept's content digest at run time
    merkle_root:           str   # bundle root this run was checked against
    computation_sha256:    str   # from ComputationPins -- what was authorized to execute
    attester_sha256:        str  # from ComputationPins -- what was authorized to judge
    attester_resource:      str
    executor_resource:      str
    runtime:                str
    params:                  dict
    params_sha256:           str
    receipt_sha256:          str
    verdict_ok:              bool
    verdict_reason:          str | None
    claimed_value:            object
    claimed_value_source:     str   # "receipt" | "caller" -- see okf_attest module docstring
    authenticated_tier:       str   # recorded, NOT gated on -- see src/okf_attest.py's module docstring
    status:                    str
    stale_after:               str
    timestamp:                  str  # ISO-8601
    run_sha256:                  str  # hex SHA-256 of the canonical payload above
    service_signature:           str  # base64 Ed25519 over run_sha256, service key
    service_key_id:               str
