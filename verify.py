#!/usr/bin/env python3
"""Standalone attestation verifier.

Runs independently of the RAG app: needs no private signing key and no OpenAI
key, only the two public verify keys. It DOES read the live Chroma store and
data/roots.json to recover Merkle proof material, because Attestation.chunk_hashes
(frozen Day 4) intentionally carries only content hashes, not full proofs or
chunk/doc IDs — so "only the public keys" means no private-key material, not
zero store access.

Day 12 added --verify-ite6-statement: a genuine signature check (still
public-key only) for the in-toto Attestation Framework (ITE-6) Statement
produced by app.py's "Download in-toto link" button — see
src/intoto.py::sign_real_ite6_statement.
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


def _verify_ite6_statement(path_str: str, show_statement: bool) -> int:
    """Independently verify a DSSE-enveloped ITE-6 Statement (produced by
    sign_real_ite6_statement / app.py's "Download in-toto link" button)
    using only the service PUBLIC key — mirrors this file's
    no-private-key-material principle. Requires the optional `intoto` extra.

    show_statement prints the decoded Statement payload (via
    decode_ite6_payload — display only, not itself a verification step) so
    the actual materials/products/environment content is visible without a
    separate manual base64 decode.
    """
    path = Path(path_str)
    if not path.exists():
        sys.exit(f"in-toto statement file not found: {path}")
    try:
        envelope = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        sys.exit(f"in-toto statement file {path} is not valid JSON: {e}")

    try:
        keyid = envelope["signatures"][0]["keyid"]
    except (KeyError, IndexError):
        sys.exit(f"{path} has no signatures[0].keyid — not an envelope produced by sign_real_ite6_statement")

    try:
        service_vk = load_verify_key(SERVICE_VERIFY_KEY_PATH)
    except FileNotFoundError as e:
        sys.exit(f"Missing verify key: {e}. Run `uv run python scripts/generate_keys.py` first.")

    try:
        from src.intoto import verify_real_ite6_statement
        ok = verify_real_ite6_statement(envelope, service_vk, keyid)
    except ImportError:
        sys.exit(
            "ITE-6 verification requires the optional `intoto` extra: uv sync --extra intoto"
        )

    print("=== ITE-6 Statement Verifier ===")
    print(f"Source: {path}")
    print(f"[1] DSSE envelope signature ({keyid}) ... {'✅ VALID' if ok else '❌ INVALID'}")

    if show_statement:
        from src.intoto import decode_ite6_payload
        print("\n--- Decoded statement (display only, not itself verified) ---")
        print(json.dumps(decode_ite6_payload(envelope), indent=2))

    return 0 if ok else 1


def _load_attestation(args: argparse.Namespace) -> tuple[dict, str]:
    if args.attestation:
        path = Path(args.attestation)
        if not path.exists():
            sys.exit(f"Attestation file not found: {path}")
        try:
            return json.loads(path.read_text()), f"file {path}"
        except json.JSONDecodeError as e:
            sys.exit(f"Attestation file {path} is not valid JSON: {e}")
    entries = load_attestations(ATTESTATION_LOG_PATH)
    if not entries:
        sys.exit(f"No attestations found in {ATTESTATION_LOG_PATH}")
    try:
        return entries[args.log_index], f"{ATTESTATION_LOG_PATH} [entry {args.log_index}]"
    except IndexError:
        sys.exit(f"--log-index {args.log_index} out of range (log has {len(entries)} entries)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Independently verify a signed answer attestation.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--attestation", help="Path to a downloaded attestation JSON file")
    source.add_argument("--log-index", type=int, help="Index into data/attestation_log.jsonl (e.g. -1 for latest)")
    parser.add_argument("--answer-file", help="Path to a text file with the answer, to check against answer_sha256")
    parser.add_argument(
        "--verify-ite6-statement",
        metavar="PATH",
        help="Verify a DSSE-enveloped ITE-6 Statement (from app.py's 'Download in-toto "
        "link' button) against the service public key. Standalone — ignores "
        "--attestation/--log-index/--answer-file if given.",
    )
    parser.add_argument(
        "--show-statement",
        action="store_true",
        help="With --verify-ite6-statement: also print the decoded Statement payload "
        "(materials/products/environment) — display only, not itself a verification step.",
    )
    args = parser.parse_args()

    if args.verify_ite6_statement:
        return _verify_ite6_statement(args.verify_ite6_statement, args.show_statement)

    if not args.attestation and args.log_index is None:
        parser.error("one of the arguments --attestation --log-index --verify-ite6-statement is required")

    attestation, source_label = _load_attestation(args)
    answer_text = Path(args.answer_file).read_text() if args.answer_file else None

    try:
        publisher_vk = load_verify_key(PUBLISHER_VERIFY_KEY_PATH)
        service_vk = load_verify_key(SERVICE_VERIFY_KEY_PATH)
    except FileNotFoundError as e:
        sys.exit(f"Missing verify key: {e}. Run `uv run python scripts/generate_keys.py` first.")

    collection = get_collection()
    if collection.count() == 0:
        print(
            f"WARNING: Chroma store at data/chroma_db is empty — every cited chunk below "
            f"will report 'not found in store', which will look identical to a tampered/"
            f"rewritten hash. Run the app or main.py once to ingest the corpus first.\n"
        )

    if not ROOTS_PATH.exists():
        print(
            f"WARNING: {ROOTS_PATH} not found — every chunk will fail root-signature "
            f"checks below with 'no signed root for document', which is NOT the same "
            f"signal as a tampered chunk. Run ingestion first.\n"
        )
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
