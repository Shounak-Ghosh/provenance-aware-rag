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

Day 5 (OKF) added three more standalone, public-key-only modes:
--okf-bundle, --okf-run, --okf-answer — see _verify_okf_bundle /
_verify_okf_run / _verify_okf_answer below. None of them touch the Chroma
store or a private key; src.store.get_collection is imported lazily inside
the arXiv branch of main() so these modes stay disk-only and fast.
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


def _verify_okf_bundle(bundle_path_str: str) -> int:
    """At-rest verification of an OKF bundle: signed root, per-concept
    integrity, authenticated trust tier, and computation pins — entirely via
    src.okf_verify.verify_bundle, rendered in this file's numbered ✅/❌ idiom.
    """
    from src.config import ACTOR_KEYRING_PATH, OKF_CANON_VERSION, OKF_ROOTS_PATH
    from src.okf_verify import verify_bundle
    from src.trust import load_keyring

    bundle_path = Path(bundle_path_str)
    if not bundle_path.is_dir():
        sys.exit(f"bundle path not found: {bundle_path}")
    bundle_id = bundle_path.name

    try:
        publisher_vk = load_verify_key(PUBLISHER_VERIFY_KEY_PATH)
    except FileNotFoundError as e:
        sys.exit(f"Missing verify key: {e}. Run `uv run python scripts/generate_keys.py` first.")

    if not OKF_ROOTS_PATH.exists():
        print(
            f"WARNING: {OKF_ROOTS_PATH} not found — every concept below will fail with "
            f"'no signed root for bundle', which is NOT the same signal as a tampered "
            f"concept. Run `uv run python -m src.okf_ingest {bundle_path}` first.\n"
        )
    roots = json.loads(OKF_ROOTS_PATH.read_text()) if OKF_ROOTS_PATH.exists() else {}

    if not ACTOR_KEYRING_PATH.exists():
        print(
            f"WARNING: {ACTOR_KEYRING_PATH} not found — every claimed actor below will "
            f"report 'unknown_actor', which is a key-distribution gap, NOT evidence of "
            f"forgery. Run `uv run python scripts/sign_trust.py {bundle_path} --mint-missing` first.\n"
        )
    keyring = load_keyring(ACTOR_KEYRING_PATH)

    report = verify_bundle(bundle_path, bundle_id, roots, publisher_vk, keyring)

    print("=== OKF Bundle Verifier ===")
    print(f"Bundle: {bundle_id}   ({report['bundle_path']})")

    if report.get("error"):
        print(f"\n❌ {report['error']}")
        return 1

    print(
        f"Signed: {report['signed_at'] or '(unknown)'}  by {report['publisher_key_id'] or '(unknown)'}"
        f"   canonicalization: {OKF_CANON_VERSION}"
    )

    checks_passed: list[bool] = []

    root_ok = report["root_matches"]
    checks_passed.append(root_ok)
    print(f"\n[1] Merkle root recomputation ... {'✅ MATCHES' if root_ok else '❌ MISMATCH'}  {report['recomputed_root'][:12]}…")

    sig_ok = report["root_signature_valid"]
    checks_passed.append(sig_ok)
    key_id = report["publisher_key_id"] or "unknown key"
    print(f"[2] Bundle root signature ({key_id}) ... {'✅ VALID' if sig_ok else '❌ INVALID'}")

    set_ok = not report["added_concepts"] and not report["removed_concepts"]
    checks_passed.append(set_ok)
    set_reason = "no additions or removals" if set_ok else f"added={report['added_concepts']} removed={report['removed_concepts']}"
    print(
        f"[3] Concept set ({report['signed_concept_count']} signed / {report['disk_concept_count']} on disk) "
        f"... {'✅' if set_ok else '❌'} {set_reason}"
    )

    if not root_ok:
        print(
            "\n    NOTE: the recomputed root differs from the signed root, so every concept's\n"
            "    Merkle proof is checked against a root that has moved — sibling concepts\n"
            "    report 'merkle proof failed' even though their own bytes are intact. The\n"
            "    concept reporting 'concept canonical-hash mismatch' is the edited one."
        )

    print(f"\n[4] Per-concept integrity + authenticated trust ({len(report['concepts'])} concepts)")
    for c in report["concepts"]:
        checks_passed.append(not c["tampered"])
        mark = "✅ verified" if not c["tampered"] else f"❌ {c['reason']}"
        trust = c["trust"]
        tier_str = trust["tier"] if trust["tier"] == trust["claimed_tier"] else f"{trust['tier']} (claimed: {trust['claimed_tier']})"
        downgrade_mark = "  ❌ DOWNGRADED" if trust["downgraded"] else ""
        print(f"    {c['concept_id']:<34} idx={c['merkle_index']:>2}  {mark:<38} trust: {tier_str}{downgrade_mark}")

    if report["pins"]:
        print(f"\n[5] Computation pins ({len(report['pins'])} Attested Computations)")
        for p in report["pins"]:
            checks_passed.append(p["ok"])
            mark = "✅ verified" if p["ok"] else f"❌ {p['reason']}"
            print(f"    {p['concept_id']:<40} {mark}")

    trust_ok = not report["trust_downgraded"]
    checks_passed.append(trust_ok)

    overall_ok = all(checks_passed)
    print()
    print("RESULT: " + ("✅ PASS — bundle integrity and authenticated trust verify" if overall_ok else "❌ FAIL — see failures above"))
    if report["ok"] and not trust_ok:
        print(
            "NOTE: bundle-integrity is green (verify_bundle's own `ok` is True); the FAIL "
            "above is a TRUST POLICY refusal this CLI applies on top — a downgraded tier is "
            "a policy question (src.enforce.admit_concept always refuses it), not a bundle "
            "integrity defect, so verify_bundle deliberately does not fold it into its own `ok`."
        )

    return 0 if overall_ok else 1


def _verify_okf_run(index: int) -> int:
    """Re-verify one logged Attested-Computation run: record hash + service
    signature, agreement with the publisher-signed computation/attester
    pins, and (if present) the DSSE ITE-6 envelope — src.okf_attest.verify_run."""
    from src.config import OKF_ROOTS_PATH, OKF_RUNS_PATH
    from src.okf_attest import load_runs, verify_run

    entries = load_runs(OKF_RUNS_PATH)
    if not entries:
        sys.exit(f"No runs found in {OKF_RUNS_PATH}")
    try:
        entry = entries[index]
    except IndexError:
        sys.exit(f"--okf-run {index} out of range (log has {len(entries)} entries)")

    try:
        service_vk = load_verify_key(SERVICE_VERIFY_KEY_PATH)
        publisher_vk = load_verify_key(PUBLISHER_VERIFY_KEY_PATH)
    except FileNotFoundError as e:
        sys.exit(f"Missing verify key: {e}. Run `uv run python scripts/generate_keys.py` first.")

    roots = json.loads(OKF_ROOTS_PATH.read_text()) if OKF_ROOTS_PATH.exists() else {}
    pins_index = {p["concept_id"]: p for p in roots.get(entry.get("bundle_id", ""), {}).get("computation_pins", [])}
    pins_rec = pins_index.get(entry.get("concept_id"))
    if pins_rec is None:
        print(
            f"WARNING: no publisher-signed pin found for {entry.get('concept_id')!r} in "
            f"{entry.get('bundle_id')!r} — pin-agreement checks below are SKIPPED, which "
            f"is not the same as passing them.\n"
        )

    ok, reasons = verify_run(entry, service_vk, publisher_vk, pins_rec)

    print("=== OKF Run Verifier ===")
    print(f"Source: {OKF_RUNS_PATH} [entry {index}]")
    print(f"Bundle: {entry.get('bundle_id')}   Concept: {entry.get('concept_id')}   Runtime: {entry.get('runtime')}")
    print(f"Claimed value: {entry.get('claimed_value')}   (source: {entry.get('claimed_value_source')})")
    print(f"Attester verdict: {'PASS' if entry.get('verdict_ok') else 'REFUSED'} — {entry.get('verdict_reason')}\n")

    print(f"[1] Run record integrity + service signature ({entry.get('service_key_id')}) ... {'✅ VALID' if ok else '❌ INVALID'}")
    for r in reasons:
        print(f"      - {r}")

    print()
    print("RESULT: " + ("✅ PASS — run record verifies" if ok else "❌ FAIL — see failures above"))
    return 0 if ok else 1


def _verify_okf_answer(index: int) -> int:
    """Re-verify one signed OKF answer attestation: the service signature
    over the admitted concept hashes AND the SIGNED refused_concept_ids —
    the property that proves an agent's refusal was absence-by-policy, not
    absence-by-luck. See src.enforce.build_okf_answer_attestation."""
    from src.config import OKF_ATTESTATION_LOG_PATH
    from src.enforce import load_okf_answers, verify_okf_answer

    entries = load_okf_answers(OKF_ATTESTATION_LOG_PATH)
    if not entries:
        sys.exit(f"No OKF answer attestations found in {OKF_ATTESTATION_LOG_PATH}")
    try:
        entry = entries[index]
    except IndexError:
        sys.exit(f"--okf-answer {index} out of range (log has {len(entries)} entries)")

    try:
        service_vk = load_verify_key(SERVICE_VERIFY_KEY_PATH)
    except FileNotFoundError as e:
        sys.exit(f"Missing verify key: {e}. Run `uv run python scripts/generate_keys.py` first.")

    sig_ok = verify_okf_answer(entry, service_vk)

    print("=== OKF Answer Attestation Verifier ===")
    print(f"Source: {OKF_ATTESTATION_LOG_PATH} [entry {index}]")
    print(f"Bundle: {entry.get('bundle_id')}   Model: {entry.get('model')}   Timestamp: {entry.get('timestamp')}")
    print(f"Query hash:  {entry.get('query_sha256')}")
    print(f"Answer hash: {entry.get('answer_sha256')}\n")

    print(f"[1] Attestation signature ({entry.get('service_key_id')}) ... {'✅ VALID' if sig_ok else '❌ INVALID'}")
    print(f"[2] Admitted concepts ({len(entry.get('concept_ids', []))}): {', '.join(entry.get('concept_ids', [])) or '(none)'}")
    print(
        f"[3] Refused concepts ({len(entry.get('refused_concept_ids', []))}, SIGNED — proves "
        f"absence-by-policy): {', '.join(entry.get('refused_concept_ids', [])) or '(none)'}"
    )

    print()
    print("RESULT: " + ("✅ PASS — signature valid over admitted AND refused concept ids" if sig_ok else "❌ FAIL — signature invalid"))
    return 0 if sig_ok else 1


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
    parser.add_argument(
        "--okf-bundle",
        metavar="PATH",
        help="At-rest verify an OKF bundle directory (e.g. bundles/acme_retail): signed "
        "root, per-concept integrity, authenticated trust, computation pins. "
        "Standalone — no Chroma, no private key.",
    )
    parser.add_argument(
        "--okf-run",
        type=int,
        metavar="INDEX",
        help="Verify entry INDEX of data/okf_runs.jsonl (e.g. -1 for latest): record hash, "
        "service signature, pin agreement, ITE-6 envelope if present. Standalone.",
    )
    parser.add_argument(
        "--okf-answer",
        type=int,
        metavar="INDEX",
        help="Verify entry INDEX of data/okf_attestation_log.jsonl: signature over the "
        "admitted concept hashes AND the signed refused_concept_ids. Standalone.",
    )
    args = parser.parse_args()

    if args.verify_ite6_statement:
        return _verify_ite6_statement(args.verify_ite6_statement, args.show_statement)

    if args.okf_bundle:
        return _verify_okf_bundle(args.okf_bundle)

    if args.okf_run is not None:
        return _verify_okf_run(args.okf_run)

    if args.okf_answer is not None:
        return _verify_okf_answer(args.okf_answer)

    if not args.attestation and args.log_index is None:
        parser.error("one of the arguments --attestation --log-index --verify-ite6-statement --okf-bundle --okf-run --okf-answer is required")

    attestation, source_label = _load_attestation(args)
    answer_text = Path(args.answer_file).read_text() if args.answer_file else None

    try:
        publisher_vk = load_verify_key(PUBLISHER_VERIFY_KEY_PATH)
        service_vk = load_verify_key(SERVICE_VERIFY_KEY_PATH)
    except FileNotFoundError as e:
        sys.exit(f"Missing verify key: {e}. Run `uv run python scripts/generate_keys.py` first.")

    from src.store import get_collection  # lazy: only the arXiv path needs Chroma

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
