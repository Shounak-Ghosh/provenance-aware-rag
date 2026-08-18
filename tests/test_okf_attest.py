"""Tests for src/okf_attest.py: attestation integrity at the run.

Reuses the `signed_fixture` fixture (tests/conftest.py): a copy of
bundles/acme_retail under tmp_path, signed with throwaway publisher + actor
keys exactly as production would. Every tamper test mutates that COPY --
never the committed bundle or the live data/okf_roots.json. A throwaway
service key stands in for data/keys/service.sk.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.crypto import generate_keypair, sign
from src.merkle import compute_root
from src.okf import parse_bundle
from src.okf_ingest import build_pins
from src.okf_attest import (
    AttesterLoadError,
    attest_run,
    load_attester,
    native_attest_run,
    verify_run,
)

SERVICE_KEY_ID = "test_service"


@pytest.fixture
def service_keys():
    return generate_keypair()  # (sk, vk)


def _pins_for(fixture, concept_id: str) -> dict:
    return next(p for p in fixture.roots[fixture.bundle_id]["computation_pins"] if p["concept_id"] == concept_id)


def _run(fixture, service_sk, concept_id="computations/revenue-ytd", params=None, tmp_path=None, **kwargs):
    log_path = (tmp_path or Path("/tmp")) / "runs.jsonl"
    if params is None:
        params = {"year": "2026"}
    return attest_run(
        fixture.bundle_path, fixture.bundle_id, concept_id, params,
        fixture.roots, fixture.publisher_vk, service_sk, SERVICE_KEY_ID, fixture.keyring,
        log_path=log_path, **kwargs,
    )


# ── the clean path ───────────────────────────────────────────────────────────
def test_clean_run_ok(signed_fixture, service_keys, tmp_path):
    service_sk, service_vk = service_keys
    result = _run(signed_fixture, service_sk, tmp_path=tmp_path)

    assert result["ok"] is True
    assert result["stage"] == 9
    receipt = result["receipt"]
    assert set(receipt) >= {"job_id", "executed_sql", "result"}
    assert result["trust"]["tier"] == "human-reviewed"

    pins_rec = _pins_for(signed_fixture, "computations/revenue-ytd")
    ok, reasons = verify_run(result["run"], service_vk, signed_fixture.publisher_vk, pins_rec)
    assert ok is True
    assert reasons == []

    ite6 = result["run"]["ite6"]
    if ite6 is not None:  # optional `intoto` extra
        from src.intoto import verify_real_ite6_statement

        assert verify_real_ite6_statement(ite6, service_vk, SERVICE_KEY_ID) is True


def test_clean_run_deterministic_receipt(signed_fixture, service_keys, tmp_path):
    service_sk, _ = service_keys
    r1 = _run(signed_fixture, service_sk, tmp_path=tmp_path)
    r2 = _run(signed_fixture, service_sk, tmp_path=tmp_path)
    assert r1["run"]["computation_sha256"] == r2["run"]["computation_sha256"]
    assert r1["run"]["receipt_sha256"] == r2["run"]["receipt_sha256"]
    assert r1["run"]["run_sha256"] != r2["run"]["run_sha256"]  # timestamp differs


# ── the headline: fence swap ─────────────────────────────────────────────────
def test_fence_swap_refused_before_execution(signed_fixture, service_keys, tmp_path):
    """The fence lives inside the concept BODY, so a swap is already caught
    at stage 1 (Merkle root) -- before pins are even consulted. The pin's
    unique coverage is the attester file and non-.md computation files (see
    test_attester_swap_refused_before_import); this test proves the
    refuse-before-execute ordering holds regardless of WHICH stage catches
    the tamper."""
    target = signed_fixture.bundle_path / "computations" / "revenue-ytd.md"
    text = target.read_text()
    assert "SUM(" in text
    target.write_text(text.replace("SUM(", "SUM(1.5 * "))

    called = []

    def spy_executor(sql, params, concept):
        called.append(sql)
        return {"job_id": "x", "executed_sql": sql, "result": [1]}

    service_sk, _ = service_keys
    result = _run(signed_fixture, service_sk, tmp_path=tmp_path, executor=spy_executor)

    assert result["ok"] is False
    assert result["stage"] == 1
    assert result["reason"] == "concept canonical-hash mismatch"
    assert called == []  # never reached the executor


def test_native_attestation_accepts_swapped_fence(signed_fixture, tmp_path):
    """THE FINDING, as a passing test. native_attest_run models SPEC §10.5
    literally: no pins, no root check, re-read-and-re-derive from whatever
    is on disk right now. Capture the clean value, swap the fence, and show
    native_attest_run PASSES with a DIFFERENT value while attest_run (tested
    above / below) refuses."""
    clean = native_attest_run(signed_fixture.bundle_path, signed_fixture.bundle_id, "computations/revenue-ytd", {"year": "2026"})
    assert clean["ok"] is True

    target = signed_fixture.bundle_path / "computations" / "revenue-ytd.md"
    text = target.read_text()
    target.write_text(text.replace("SUM(", "SUM(1.5 * "))

    tampered = native_attest_run(signed_fixture.bundle_path, signed_fixture.bundle_id, "computations/revenue-ytd", {"year": "2026"})
    assert tampered["ok"] is True  # native attestation is fooled
    assert tampered["receipt"]["result"] != clean["receipt"]["result"]  # ...over a DIFFERENT number


# ── the pin's unique coverage: the attester file ────────────────────────────
def test_attester_swap_refused_before_import(signed_fixture, service_keys, tmp_path):
    attester = signed_fixture.bundle_path / "attesters" / "sql_equality.py"
    attester.write_text(attester.read_text() + "\n# tampered: always return ok\n")

    concepts = parse_bundle(signed_fixture.bundle_path, signed_fixture.bundle_id)
    root_now = compute_root([c["sha256"] for c in concepts])
    assert root_now == signed_fixture.roots[signed_fixture.bundle_id]["bundle"]["merkle_root"]  # root UNAFFECTED

    before = {m for m in sys.modules if m.startswith("okf_attester_")}
    service_sk, _ = service_keys
    result = _run(signed_fixture, service_sk, tmp_path=tmp_path)
    after = {m for m in sys.modules if m.startswith("okf_attester_")}

    assert result["ok"] is False
    assert result["stage"] == 3
    assert result["reason"] == "attester tampered (pin mismatch)"
    assert after == before  # no attester module was ever imported


# ── other stage-1/2 refusals ─────────────────────────────────────────────────
def test_concept_value_edit_short_circuits(signed_fixture, service_keys, tmp_path):
    target = signed_fixture.bundle_path / "computations" / "revenue-ytd.md"
    target.write_text(target.read_text().replace("status: stable", "status: deprecated"))

    service_sk, _ = service_keys
    result = _run(signed_fixture, service_sk, tmp_path=tmp_path)
    assert result["ok"] is False
    assert result["stage"] == 1
    assert result["reason"] == "concept canonical-hash mismatch"


def test_executor_skill_tamper_refused(signed_fixture, service_keys, tmp_path):
    """Editing skills/run-on-bq.md on disk would ALSO break
    computations/revenue-ytd's own Merkle proof against the old signed root
    (any leaf change cascades to every sibling's proof -- see
    src.okf_verify.verify_bundle's docstring), so that path is already
    covered by stage 1 and can't isolate stage 2 on its own.

    Stage 2 earns its keep in a narrower scenario: the SIGNED RECORD's
    stored digest for the executor-skill concept is wrong (e.g. an
    attacker with write access to okf_roots.json's `concepts` array, but
    not to the bundle files or the publisher key -- the same threat model
    test_deleted_trust_signature_fails_closed already accepts for
    trust_signatures). The bundle files, Merkle root, and root signature
    are all untouched, so computations/revenue-ytd sails through stage 1;
    only the executor-skill's OWN concept report is tampered, and only
    stage 2 looks at that.
    """
    concepts_entry = signed_fixture.roots[signed_fixture.bundle_id]["concepts"]
    for c in concepts_entry:
        if c["concept_id"] == "skills/run-on-bq":
            c["sha256"] = "0" * 64

    service_sk, _ = service_keys
    result = _run(signed_fixture, service_sk, tmp_path=tmp_path)
    assert result["ok"] is False
    assert result["stage"] == 2
    assert "executor skill concept tampered" in result["reason"]
    assert "concept canonical-hash mismatch" in result["reason"]


# ── parameter binding (stage 4) ─────────────────────────────────────────────
def test_missing_required_param(signed_fixture, service_keys, tmp_path):
    service_sk, _ = service_keys
    result = _run(signed_fixture, service_sk, params={}, tmp_path=tmp_path)
    assert result["ok"] is False
    assert result["stage"] == 4
    assert "year" in result["reason"]


def test_unknown_param(signed_fixture, service_keys, tmp_path):
    service_sk, _ = service_keys
    result = _run(signed_fixture, service_sk, params={"year": "2026", "bogus": "x"}, tmp_path=tmp_path)
    assert result["ok"] is False
    assert result["stage"] == 4
    assert "bogus" in result["reason"]


def test_uncoercible_param(signed_fixture, service_keys, tmp_path):
    service_sk, _ = service_keys
    result = _run(signed_fixture, service_sk, params={"year": "not-a-year"}, tmp_path=tmp_path)
    assert result["ok"] is False
    assert result["stage"] == 4
    assert "year" in result["reason"]


# ── allow_exec=False stops after pins (stage 5) ─────────────────────────────
def test_allow_exec_false_stops_after_pins(signed_fixture, service_keys, tmp_path):
    service_sk, _ = service_keys
    result = _run(signed_fixture, service_sk, tmp_path=tmp_path, allow_exec=False)
    assert result["ok"] is True
    assert result["executed"] is False
    assert result["stage"] == 5
    assert "trust" in result


# ── receipt shape (stage 7) ──────────────────────────────────────────────────
def test_receipt_missing_declared_field(signed_fixture, service_keys, tmp_path):
    def bad_executor(sql, params, concept):
        return {"job_id": "x", "result": [1]}  # missing executed_sql

    service_sk, _ = service_keys
    result = _run(signed_fixture, service_sk, tmp_path=tmp_path, executor=bad_executor)
    assert result["ok"] is False
    assert result["stage"] == 7
    assert result["reason"] == "receipt missing declared field 'executed_sql'"


# ── minimal custom bundles: unknown runtime / attester ABI mismatch ────────
_ATTESTER_OK = '''
def attest(*, sanctioned_sql, receipt, claimed_value):
    return {"ok": True, "reason": None, "details": {}}
'''

_ATTESTER_NO_ATTEST_FN = '''
def not_attest(*, sanctioned_sql, receipt, claimed_value):
    return {"ok": True}
'''


def _minimal_bundle(tmp_path: Path, *, runtime: str, attester_src: str) -> tuple[Path, dict, object]:
    """A one-concept bundle, signed from scratch with a throwaway publisher
    key, for scenarios acme_retail's real bundle can't reach without also
    invalidating stage 1 (unknown runtime, a broken attester ABI)."""
    bundle_path = tmp_path / "mini_bundle"
    (bundle_path / "computations").mkdir(parents=True)
    (bundle_path / "attesters").mkdir(parents=True)
    (bundle_path / "skills").mkdir(parents=True)

    (bundle_path / "attesters" / "attester.py").write_text(attester_src)
    (bundle_path / "skills" / "run.md").write_text("---\ntype: Skill\ntitle: Run\nstatus: stable\n---\n\nExecutor skill.\n")
    (bundle_path / "computations" / "foo.md").write_text(
        f"""---
type: Attested Computation
title: Minimal
runtime: {runtime}
parameters: []
executor:
  resource: skills/run.md
  receipt: [job_id, executed_sql, result]
attester:
  resource: attesters/attester.py
status: stable
---

# Computation

```sql
SELECT 1 AS x
```
"""
    )

    bundle_id = "mini_bundle"
    publisher_sk, publisher_vk = generate_keypair()
    concepts = parse_bundle(bundle_path, bundle_id)
    root_hex = compute_root([c["sha256"] for c in concepts])
    bundle_rec = {
        "bundle_id": bundle_id,
        "merkle_root": root_hex,
        "root_signature": sign(publisher_sk, bytes.fromhex(root_hex)),
        "publisher_key_id": "test_publisher",
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }
    pins = build_pins(bundle_path, concepts, bundle_id, publisher_sk)
    roots = {
        bundle_id: {
            "bundle": bundle_rec,
            "concepts": [{"concept_id": c["concept_id"], "sha256": c["sha256"], "merkle_index": c["merkle_index"]} for c in concepts],
            "trust_signatures": [],
            "computation_pins": pins,
        }
    }
    return bundle_path, roots, publisher_vk


def test_unknown_runtime_refused(tmp_path, service_keys):
    bundle_path, roots, publisher_vk = _minimal_bundle(tmp_path, runtime="snowflake", attester_src=_ATTESTER_OK)
    service_sk, _ = service_keys
    result = attest_run(
        bundle_path, "mini_bundle", "computations/foo", {}, roots, publisher_vk, service_sk, SERVICE_KEY_ID, {},
        log_path=tmp_path / "runs.jsonl",
    )
    assert result["ok"] is False
    assert result["stage"] == 5
    assert "snowflake" in result["reason"]


def test_attester_abi_mismatch(tmp_path, service_keys):
    bundle_path, roots, publisher_vk = _minimal_bundle(tmp_path, runtime="bigquery", attester_src=_ATTESTER_NO_ATTEST_FN)
    service_sk, _ = service_keys
    result = attest_run(
        bundle_path, "mini_bundle", "computations/foo", {}, roots, publisher_vk, service_sk, SERVICE_KEY_ID, {},
        log_path=tmp_path / "runs.jsonl",
    )
    assert result["ok"] is False
    assert result["stage"] == 6
    assert result["reason"] == "attester ABI mismatch"

    # load_attester is also safe to call standalone, per its own docstring
    concepts = parse_bundle(bundle_path, "mini_bundle")
    concept = next(c for c in concepts if c["concept_id"] == "computations/foo")
    pins_rec = roots["mini_bundle"]["computation_pins"][0]
    with pytest.raises(AttesterLoadError, match="attester ABI mismatch"):
        load_attester(concept, bundle_path, pins_rec, "mini_bundle", publisher_vk)


# ── ITE-6 materials match the pins, not a fresh disk read ───────────────────
def test_ite6_materials_match_pins(signed_fixture, service_keys, tmp_path):
    pytest.importorskip("in_toto_attestation")
    from src.intoto import decode_ite6_payload

    service_sk, _ = service_keys
    result = _run(signed_fixture, service_sk, tmp_path=tmp_path)
    assert result["ok"] is True

    pins_rec = _pins_for(signed_fixture, "computations/revenue-ytd")
    payload = decode_ite6_payload(result["run"]["ite6"])
    materials_by_name = {m["name"]: m["digest"]["sha256"] for m in payload["predicate"]["materials"]}

    assert materials_by_name["computations/revenue-ytd#computation"] == pins_rec["computation_sha256"]
    assert materials_by_name[pins_rec["attester_resource"]] == pins_rec["attester_sha256"]
    assert materials_by_name["computations/revenue-ytd"] == result["run"]["concept_sha256"]


# ── verify_run detects a tampered log entry ─────────────────────────────────
def test_verify_run_detects_edited_record(signed_fixture, service_keys, tmp_path):
    service_sk, service_vk = service_keys
    result = _run(signed_fixture, service_sk, tmp_path=tmp_path)
    entry = dict(result["run"])
    entry["verdict_ok"] = not entry["verdict_ok"]  # flip after signing

    ok, reasons = verify_run(entry, service_vk)
    assert ok is False
    assert "run record hash mismatch" in reasons


# ── the answer-attestation ITE-6 path (src/intoto.py) is unaffected by the refactor ──
def test_answer_ite6_envelope_shape_unchanged():
    """src.intoto.sign_real_ite6_statement was refactored to share
    its envelope-signing tail with sign_run_ite6_statement. Ed25519
    signatures are deterministic given the same key+message, so calling it
    twice with fixed inputs must reproduce byte-identical output -- and the
    decoded shape must still match what app.py / verify.py expect."""
    pytest.importorskip("in_toto_attestation")
    from src.intoto import decode_ite6_payload, sign_real_ite6_statement, verify_real_ite6_statement

    sk, vk = generate_keypair()
    attestation = {
        "answer_sha256": "a" * 64,
        "chunk_hashes": ["b" * 64, "c" * 64],
        "query_sha256": "d" * 64,
        "model": "gpt-4o-mini",
        "timestamp": "2026-08-04T00:00:00+00:00",
    }

    envelope1 = sign_real_ite6_statement(attestation, None, sk, "test_service")
    envelope2 = sign_real_ite6_statement(attestation, None, sk, "test_service")
    assert envelope1 == envelope2  # deterministic

    assert verify_real_ite6_statement(envelope1, vk, "test_service") is True

    payload = decode_ite6_payload(envelope1)
    assert payload["_type"] == "https://in-toto.io/Statement/v1"
    assert payload["subject"][0]["name"] == "answer"
    assert payload["subject"][0]["digest"]["sha256"] == attestation["answer_sha256"]
    assert payload["predicateType"] == "https://in-toto.io/attestation/link/v0.3"
    predicate = payload["predicate"]
    assert set(predicate) == {"name", "command", "materials", "byproducts", "environment"}
    assert predicate["environment"]["model"] == "gpt-4o-mini"
    assert len(predicate["materials"]) == 2
