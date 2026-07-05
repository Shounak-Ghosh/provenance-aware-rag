import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import nacl.signing

from src.config import ATTESTATION_LOG_PATH
from src.crypto import sign, verify
from src.schema import Attestation

_PAYLOAD_FIELDS = ("answer_sha256", "chunk_hashes", "query_sha256", "model", "timestamp")


def build_attestation(question: str, answer: str, chunks: list[dict], model: str) -> dict:
    """Build the unsigned attestation payload for one answer.

    chunk_hashes covers every chunk placed into the LLM's context (all of
    ``chunks``), not just the subset the model cited inline — this is the
    full trust surface the answer was generated against.
    """
    return {
        "answer_sha256": hashlib.sha256(answer.encode()).hexdigest(),
        "chunk_hashes": [c["sha256"] for c in chunks],
        "query_sha256": hashlib.sha256(question.encode()).hexdigest(),
        "model": model,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _canonical_payload(attestation: dict) -> bytes:
    payload = {field: attestation[field] for field in _PAYLOAD_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign_attestation(attestation: dict, sk: nacl.signing.SigningKey, key_id: str) -> Attestation:
    """Return a copy of ``attestation`` with service_signature/service_key_id set."""
    signature = sign(sk, _canonical_payload(attestation))
    return {**attestation, "service_signature": signature, "service_key_id": key_id}


def verify_attestation(attestation: dict, vk: nacl.signing.VerifyKey) -> bool:
    """Return True iff service_signature is a valid Ed25519 sig over the
    canonical payload under the given service key."""
    if not attestation.get("service_signature"):
        return False
    return verify(vk, _canonical_payload(attestation), attestation["service_signature"])


def append_attestation(attestation: dict, path: Path = ATTESTATION_LOG_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(attestation) + "\n")


def load_attestations(path: Path = ATTESTATION_LOG_PATH) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
