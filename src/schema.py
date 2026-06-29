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
