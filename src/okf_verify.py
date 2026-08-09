"""At-rest verification of an OKF v0.2 bundle against its signed record.

Three independent checks, each localizing a different kind of tamper:

  * check_concept_tamper -- is THIS concept's content still what the
    publisher signed (canonical hash, Merkle membership, root signature)?
    REUSEs src.merkle.verify_proof / verify_root_signature verbatim.
  * derive_authenticated_tier (src.trust) -- is the trust tier THIS concept
    claims actually backed by the named actor's own signature?
  * check_pins -- for an Attested Computation, are the sanctioned SQL and
    the attester code still byte-identical to what was pinned at sign time?
    This is the ONLY coverage attesters/*.py has at all: it is not a `.md`
    file, so it is never a Merkle leaf.

Deliberately import-light (only okf.py/merkle.py/trust.py/crypto.py, all
pure-stdlib-plus-PyNaCl) -- no sentence_transformers, no chromadb -- so this
module can run standalone with only public key material, matching verify.py's
public-key-only verification ethos.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import nacl.signing

from src.crypto import verify
from src.merkle import compute_root, merkle_proof, verify_proof, verify_root_signature
from src.okf import attester_bytes, canonical_computation_bytes, canonicalize_from_parts, parse_bundle, pins_message
from src.schema import BundleRecord, ComputationPins, ConceptRecord
from src.trust import derive_authenticated_tier, index_trust_signatures, load_keyring  # noqa: F401 -- load_keyring re-exported for callers


def check_concept_tamper(
    concept: ConceptRecord,
    expected_sha256: str,
    merkle_index: int,
    leaf_hashes: list[str],
    bundle_rec: BundleRecord,
    publisher_vk: nacl.signing.VerifyKey,
) -> tuple[bool, str]:
    """Re-verify one concept against the SIGNED record, not against itself.

    `expected_sha256` MUST come from the signed okf_roots.json record, never
    from `concept["sha256"]` -- that field is recomputed fresh from disk on
    every parse_bundle() call, so comparing it to itself can never fail.
    `merkle_index`/`leaf_hashes` are re-derived by the caller from a fresh
    concept_id-sorted parse (see verify_bundle) on every call -- never
    trusted from stale/cached metadata, so a forged position cannot be used
    to smuggle a tampered leaf past a stale sibling set.

    Message style mirrors src.merkle.check_tamper (the arXiv-chunk analog):
    the four checks run in order, and the first failure names the reason.
    """
    if not bundle_rec.get("merkle_root"):
        return True, "no signed root for bundle"

    recomputed = hashlib.sha256(canonicalize_from_parts(concept["frontmatter_json"], concept["body"])).hexdigest()
    if recomputed != expected_sha256:
        return True, "concept canonical-hash mismatch"

    path = merkle_proof(leaf_hashes, merkle_index)  # REUSE merkle.merkle_proof
    if not verify_proof(expected_sha256, path, bundle_rec["merkle_root"], merkle_index):  # REUSE
        return True, "merkle proof failed"

    if not verify_root_signature(bundle_rec, publisher_vk):  # REUSE
        return True, "bundle root signature invalid"

    return False, "verified"


def check_pins(
    concept: ConceptRecord,
    bundle_path: Path,
    pins_rec: ComputationPins | None,
    bundle_id: str,
    publisher_vk: nacl.signing.VerifyKey,
) -> tuple[bool, str]:
    """At-rest half of the §12-deferred attestation-integrity layer: does the
    computation this concept would run, and the attester that would judge
    it, still match what was pinned (and publisher-signed) at ingest time?

    The run-time half -- actually executing the computation and emitting an
    ITE-6 statement over the run -- is future work; this only checks the
    bytes are undisturbed at rest, which is already enough to catch the
    headline attack: native OKF (§10.5) has the attester re-derive from the
    SAME in-bundle computation the executor ran, so a swapped `# Computation`
    fence passes native attestation. A pin fixed at sign time does not.
    """
    if pins_rec is None:
        return True, "no computation pins recorded for concept"

    comp_sha = pins_rec.get("computation_sha256", "")
    att_sha = pins_rec.get("attester_sha256", "")
    msg = pins_message(bundle_id, concept["concept_id"], comp_sha, att_sha)
    if not verify(publisher_vk, msg, pins_rec["pins_signature"]):  # REUSE crypto.verify
        return True, "pins signature invalid"

    try:
        comp = canonical_computation_bytes(concept, bundle_path)
    except FileNotFoundError:
        return True, "computation resource missing"
    comp_now_sha = hashlib.sha256(comp).hexdigest() if comp else ""
    if comp_now_sha != comp_sha:
        if not comp_sha and comp_now_sha:
            return True, "computation added after signing"
        return True, "computation tampered (pin mismatch)"

    try:
        att = attester_bytes(bundle_path, concept)
    except FileNotFoundError:
        return True, "attester resource missing"
    att_now_sha = hashlib.sha256(att[0]).hexdigest() if att else ""
    if att_now_sha != att_sha:
        return True, "attester tampered (pin mismatch)"

    return False, "verified"


def verify_bundle(
    bundle_path: Path,
    bundle_id: str,
    roots: dict,
    publisher_vk: nacl.signing.VerifyKey,
    keyring: dict[str, nacl.signing.VerifyKey],
    concepts: list[ConceptRecord] | None = None,
) -> dict:
    """Full at-rest verification report for one bundle. Library function --
    no printing; verify.py's --okf-bundle mode (a later pass) owns the
    ✅/❌ rendering.

    Re-parses the bundle from disk on every call by default (leaf order and
    merkle_index are always re-derived, per check_concept_tamper's
    docstring) and builds the Merkle proof from those CURRENT leaf hashes --
    the same live-state pattern src.retrieve/src.verifier already use for
    arXiv chunks (doc_leaf_hashes pulled fresh, not frozen at signing time),
    so a content edit anywhere in the bundle is expected to also break
    sibling concepts' proofs against the signed root, not just the edited
    concept's own hash check.

    `concepts` lets a caller that has ALREADY parsed the bundle (e.g.
    src.okf_attest.attest_run, which needs its own parse to build a run)
    pass that same list in, so the at-rest report and the run provably
    reason about one parse of the directory rather than two independent
    reads of state an attacker may be writing to concurrently.
    """
    bundle_entry = roots.get(bundle_id)
    if bundle_entry is None:
        return {"bundle_id": bundle_id, "bundle_path": str(bundle_path), "ok": False, "error": f"no signed record for bundle {bundle_id!r}"}

    bundle_rec: BundleRecord = bundle_entry["bundle"]
    signed_concepts = {c["concept_id"]: c["sha256"] for c in bundle_entry.get("concepts", [])}
    pins_index = {p["concept_id"]: p for p in bundle_entry.get("computation_pins", [])}
    sig_index = index_trust_signatures(bundle_entry.get("trust_signatures", []))

    if concepts is None:
        concepts = parse_bundle(bundle_path, bundle_id)  # fresh, concept_id-sorted, live disk state
    leaf_hashes = [c["sha256"] for c in concepts]
    recomputed_root = compute_root(leaf_hashes)  # REUSE merkle.compute_root
    signed_root = bundle_rec.get("merkle_root", "")

    disk_ids = {c["concept_id"] for c in concepts}
    signed_ids = set(signed_concepts)
    added_concepts = sorted(disk_ids - signed_ids)
    removed_concepts = sorted(signed_ids - disk_ids)

    concept_reports = []
    pin_reports = []
    for c in concepts:
        expected_sha256 = signed_concepts.get(c["concept_id"])
        if expected_sha256 is None:
            tampered, reason = True, "concept not present in signed bundle (added since signing)"
        else:
            tampered, reason = check_concept_tamper(c, expected_sha256, c["merkle_index"], leaf_hashes, bundle_rec, publisher_vk)

        trust = derive_authenticated_tier(bundle_id, c, sig_index, keyring)
        concept_reports.append(
            {"concept_id": c["concept_id"], "merkle_index": c["merkle_index"], "tampered": tampered, "reason": reason, "trust": trust}
        )

        pins_rec = pins_index.get(c["concept_id"])
        if pins_rec is not None:
            pin_ok_fail, pin_reason = check_pins(c, bundle_path, pins_rec, bundle_id, publisher_vk)
            pin_reports.append({"concept_id": c["concept_id"], "ok": not pin_ok_fail, "reason": pin_reason})

    ok = (
        recomputed_root == signed_root
        and verify_root_signature(bundle_rec, publisher_vk)
        and not added_concepts
        and not removed_concepts
        and all(not r["tampered"] for r in concept_reports)
        and all(p["ok"] for p in pin_reports)
    )

    return {
        "bundle_id": bundle_id,
        "bundle_path": str(bundle_path),
        "recomputed_root": recomputed_root,
        "signed_root": signed_root,
        "root_matches": recomputed_root == signed_root,
        "root_signature_valid": verify_root_signature(bundle_rec, publisher_vk),
        "concepts": concept_reports,
        "pins": pin_reports,
        "added_concepts": added_concepts,
        "removed_concepts": removed_concepts,
        # Derived, not folded into `ok`: a downgraded tier is a TRUST POLICY
        # question (src.enforce.admit_concept always refuses it), not a bundle
        # integrity question -- this report stays a pure at-rest integrity
        # verdict, per this function's own docstring. Callers that want the
        # policy view (verify.py's --okf-bundle CLI) read this list themselves.
        "trust_downgraded": [r["concept_id"] for r in concept_reports if r["trust"]["downgraded"]],
        "ok": ok,
    }
