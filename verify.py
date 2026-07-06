#!/usr/bin/env python3
"""Standalone attestation verifier.

Runs independently of the RAG app: needs no private signing key and no OpenAI
key, only the two public verify keys. It DOES read the live Chroma store and
data/roots.json to recover Merkle proof material, because Attestation.chunk_hashes
(frozen Day 4) intentionally carries only content hashes, not full proofs or
chunk/doc IDs — so "only the public keys" means no private-key material, not
zero store access. A future in-toto-formatted attestation (Day 12 stretch)
could embed proof material directly and close this gap.
"""
import argparse
import json
import sys
from pathlib import Path

from src.attestation import load_attestations, verify_attestation
from src.config import (
    ATTESTATION_LOG_PATH,
    PUBLISHER_VERIFY_KEY_PATH,
    ROOTS_PATH,
    SERVICE_VERIFY_KEY_PATH,
)
from src.crypto import load_verify_key
from src.store import get_collection
from src.verifier import verify_answer_hash, verify_chunk


def _load_attestation(args: argparse.Namespace) -> tuple[dict, str]:
    if args.attestation:
        return json.loads(Path(args.attestation).read_text()), f"file {args.attestation}"
    entries = load_attestations(ATTESTATION_LOG_PATH)
    if not entries:
        sys.exit(f"No attestations found in {ATTESTATION_LOG_PATH}")
    return entries[args.log_index], f"{ATTESTATION_LOG_PATH} [entry {args.log_index}]"


def main() -> int:
    parser = argparse.ArgumentParser(description="Independently verify a signed answer attestation.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--attestation", help="Path to a downloaded attestation JSON file")
    source.add_argument("--log-index", type=int, help="Index into data/attestation_log.jsonl (e.g. -1 for latest)")
    parser.add_argument("--answer-file", help="Path to a text file with the answer, to check against answer_sha256")
    args = parser.parse_args()

    attestation, source_label = _load_attestation(args)
    answer_text = Path(args.answer_file).read_text() if args.answer_file else None

    publisher_vk = load_verify_key(PUBLISHER_VERIFY_KEY_PATH)
    service_vk = load_verify_key(SERVICE_VERIFY_KEY_PATH)
    collection = get_collection()
    roots = json.loads(ROOTS_PATH.read_text()) if ROOTS_PATH.exists() else {}

    print("=== Standalone Attestation Verifier ===")
    print(f"Source: {source_label}")
    print(f"Model: {attestation['model']}   Timestamp: {attestation['timestamp']}")
    print(f"Query hash:  {attestation['query_sha256']}")
    print(f"Answer hash: {attestation['answer_sha256']}\n")

    checks_passed: list[bool] = []

    sig_ok = verify_attestation(attestation, service_vk)
    checks_passed.append(sig_ok)
    print(f"[1] Attestation signature ({attestation['service_key_id']}) ... {'✅ VALID' if sig_ok else '❌ INVALID'}")

    answer_ok, answer_reason = verify_answer_hash(attestation, answer_text)
    if answer_ok is not None:
        checks_passed.append(answer_ok)
    answer_mark = "⏭️ " if answer_ok is None else ("✅" if answer_ok else "❌")
    print(f"[2] Answer hash ... {answer_mark} {answer_reason}")

    print(f"[3] Cited chunk integrity ({len(attestation['chunk_hashes'])} chunks)")
    doc_leaf_cache: dict[str, list[str]] = {}
    for h in attestation["chunk_hashes"]:
        result = verify_chunk(h, collection, roots, publisher_vk, doc_leaf_cache)
        checks_passed.append(result["ok"])
        mark = "✅" if result["ok"] else "❌"
        print(f"    {h[:12]}…  doc={result['doc_id'] or '?':<16} {mark} {result['reason']}")

    overall_ok = all(checks_passed)
    print()
    print("RESULT: " + ("✅ PASS — attestation and all cited sources verify" if overall_ok else "❌ FAIL — see failures above"))
    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
