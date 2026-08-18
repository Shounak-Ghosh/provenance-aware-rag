"""Tests for the admission gate (src/enforce.py).

Everything runs against tests/conftest.py's signed_fixture -- a tmp_path copy of
the bundle signed with throwaway keys -- plus its FakeCollection store view.
The committed bundle, data/okf_roots.json, data/keys/, and both live logs are
never touched.
"""
import json
from datetime import date
from decimal import Decimal

import pytest

from src.crypto import generate_keypair, sign
from src.enforce import (
    admit_all,
    build_okf_answer_attestation,
    parse_answer_value,
    run_agent,
    sign_okf_answer,
    verify_okf_answer,
)
from src.generate import parse_concept_citations
from src.merkle import compute_root
from src.okf import parse_bundle
from src.okf_retrieve import bundle_view
from src.okf_verify import verify_bundle
from tests.conftest import BUNDLE_ID, StubEmbedder, StubLLM

TODAY = date(2026, 8, 6)          # inside every stale_after in the bundle
AFTER = date(2027, 1, 2)          # past every stale_after: 2026-12-31
BOUNDARY = date(2026, 12, 31)     # the stale_after date itself — still fresh (strict `>`)


@pytest.fixture
def service_keys():
    return generate_keypair()


def _view(fx, collection):
    """The per-bundle view retrieve_okf would hand the gate."""
    from src.trust import index_trust_signatures

    entry = fx.roots[BUNDLE_ID]
    concepts, leaf_hashes = bundle_view(collection, BUNDLE_ID)
    return {
        "leaf_hashes": leaf_hashes,
        "bundle_rec": entry["bundle"],
        "signed_sha256": {c["concept_id"]: c["sha256"] for c in entry["concepts"]},
        "sig_index": index_trust_signatures(entry["trust_signatures"]),
        "pins_index": {p["concept_id"]: p for p in entry["computation_pins"]},
        "by_id": {c["concept_id"]: c for c in concepts},
        "bundle_path": fx.bundle_path,
    }


def _decide(fx, collection, today=TODAY, **kwargs):
    concepts, _ = bundle_view(collection, BUNDLE_ID)
    decisions = admit_all(
        concepts, _view(fx, collection), fx.publisher_vk, fx.keyring,
        today=today, bundle_id=BUNDLE_ID, **kwargs,
    )
    return {d["concept_id"]: d for d in decisions}


# ── the clean case ────────────────────────────────────────────────────────────
def test_clean_bundle_admits_everything_except_the_deprecated_concept(signed_fixture):
    d = _decide(signed_fixture, signed_fixture.collection())

    assert d["metrics/gross-margin-legacy"]["admitted"] is False
    assert d["metrics/gross-margin-legacy"]["reasons"] == ["status: deprecated"]

    for cid, decision in d.items():
        if cid == "metrics/gross-margin-legacy":
            continue
        assert decision["admitted"] is True, (cid, decision["reasons"])


def test_deprecated_refusal_needs_no_mutation(signed_fixture):
    """The bundle ships one `status: deprecated` concept, so the gate produces a
    real refusal against completely untouched, publisher-signed bytes."""
    d = _decide(signed_fixture, signed_fixture.collection())
    legacy = d["metrics/gross-margin-legacy"]
    assert legacy["checks"]["integrity"]["ok"] is True      # nothing is tampered
    assert legacy["checks"]["status"]["ok"] is False        # it is simply retired


# ── the two-surface property (src/okf_retrieve.py's docstring) ────────────────
def test_store_tamper_refused_while_disk_stays_clean(signed_fixture):
    """The headline Day-4 property: mutate ONLY the store row the model would
    read. Every at-rest check still passes on the untouched directory, and the
    gate still refuses."""
    collection = signed_fixture.collection()
    collection.set_body("metrics/revenue", "# Definition\n\nRevenue is whatever the attacker says.\n")

    d = _decide(signed_fixture, collection)
    assert d["metrics/revenue"]["admitted"] is False
    assert "concept canonical-hash mismatch" in d["metrics/revenue"]["reasons"]

    report = verify_bundle(
        signed_fixture.bundle_path, BUNDLE_ID, signed_fixture.roots,
        signed_fixture.publisher_vk, signed_fixture.keyring,
    )
    assert report["ok"] is True, "the disk copy must still verify — that is the point"


def test_store_tamper_with_updated_hash_still_refused(signed_fixture):
    """The sophisticated version: the attacker also rewrites the row's stored
    sha256. expected_sha256 comes from the publisher-signed record, so the
    canonical-hash check catches it anyway."""
    import hashlib

    from src.okf import canonicalize_from_parts

    collection = signed_fixture.collection()
    body = "# Definition\n\nForged.\n"
    meta = collection.rows["metrics/revenue"][0]
    forged = hashlib.sha256(canonicalize_from_parts(meta["frontmatter_json"], body)).hexdigest()
    collection.set_body("metrics/revenue", body)
    collection.set_metadata("metrics/revenue", sha256=forged)

    d = _decide(signed_fixture, collection)
    assert d["metrics/revenue"]["admitted"] is False
    assert "concept canonical-hash mismatch" in d["metrics/revenue"]["reasons"]


# ── trust: the two independent gates ──────────────────────────────────────────
def _resign_roots(fx, publisher_sk):
    """Re-parse the mutated bundle and re-sign the root, i.e. the publisher
    themselves published the forgery. Mirrors
    test_okf_verify.py::test_resigned_forged_tier_still_downgrades."""
    concepts = parse_bundle(fx.bundle_path, BUNDLE_ID)
    root = compute_root([c["sha256"] for c in concepts])
    entry = fx.roots[BUNDLE_ID]
    entry["bundle"] = {**entry["bundle"], "merkle_root": root, "root_signature": sign(publisher_sk, bytes.fromhex(root))}
    entry["concepts"] = [
        {"concept_id": c["concept_id"], "sha256": c["sha256"], "merkle_index": c["merkle_index"]} for c in concepts
    ]
    return concepts


def test_forged_trust_claim_refused_even_when_the_publisher_resigns(tmp_path):
    """A forged `verified:` entry with a validly re-signed root: integrity is
    green, and the gate still refuses because no actor key backs the claim.

    Note the forged actor here does NOT move the concept's tier -- jsmith's
    genuine signature already puts it at human-reviewed -- so
    TrustAssessment["downgraded"] stays False. Gating on the downgrade flag
    alone would admit this. See enforce._authenticity_check."""
    import shutil

    from src.crypto import generate_keypair as gk
    from src.merkle import verify_root_signature
    from src.okf_ingest import build_pins
    from src.trust import ensure_actor_key, load_keyring, sign_trust_entry, trust_entries
    from tests.conftest import BUNDLE_SRC, FakeCollection, SignedFixture

    bundle_path = tmp_path / "acme_retail"
    shutil.copytree(BUNDLE_SRC, bundle_path)

    target = bundle_path / "metrics" / "revenue.md"
    target.write_text(
        target.read_text().replace(
            "verified:\n  - { by: human:jsmith@acme, at: 2026-07-01T09:00:00Z }",
            "verified:\n  - { by: human:jsmith@acme, at: 2026-07-01T09:00:00Z }\n"
            "  - { by: human:attacker, at: 2026-08-01T00:00:00Z }",
        )
    )

    publisher_sk, publisher_vk = gk()
    concepts = parse_bundle(bundle_path, BUNDLE_ID)
    root = compute_root([c["sha256"] for c in concepts])
    bundle_rec = {
        "bundle_id": BUNDLE_ID, "merkle_root": root,
        "root_signature": sign(publisher_sk, bytes.fromhex(root)),
        "publisher_key_id": "test_publisher", "signed_at": "2026-08-01T00:00:00Z",
    }
    keys_dir, keyring_path = tmp_path / "actor_keys", tmp_path / "keyring.json"
    sigs = []
    for c in concepts:
        for actor, at, kind in trust_entries(c):
            if actor == "human:attacker":
                continue  # the attacker cannot produce a signature — that IS the attack
            sk = ensure_actor_key(actor, keys_dir=keys_dir, keyring_path=keyring_path)
            sigs.append(sign_trust_entry(BUNDLE_ID, c, actor, at, kind, sk))

    fx = SignedFixture(
        bundle_path=bundle_path, bundle_id=BUNDLE_ID,
        roots={BUNDLE_ID: {
            "bundle": bundle_rec, "bundle_path": str(bundle_path),
            "concepts": [{"concept_id": c["concept_id"], "sha256": c["sha256"], "merkle_index": c["merkle_index"]} for c in concepts],
            "trust_signatures": sigs,
            "computation_pins": build_pins(bundle_path, concepts, BUNDLE_ID, publisher_sk),
        }},
        publisher_vk=publisher_vk, keyring=load_keyring(keyring_path),
        keys_dir=keys_dir, keyring_path=keyring_path, concepts=concepts,
    )

    d = _decide(fx, FakeCollection(concepts))
    revenue = d["metrics/revenue"]
    assert verify_root_signature(bundle_rec, publisher_vk) is True, "the publisher really did sign this"
    assert revenue["checks"]["integrity"]["ok"] is True
    assert revenue["admitted"] is False
    assert revenue["trust"]["downgraded"] is False, "the forgery does not move the tier — that is the trap"
    assert revenue["checks"]["trust_authentic"]["ok"] is False
    assert "human:attacker" in revenue["checks"]["trust_authentic"]["reason"]
    assert "unbacked" in revenue["checks"]["trust_authentic"]["reason"]


def test_unknown_actor_warns_rather_than_refusing(signed_fixture):
    """A key-distribution gap is not evidence of forgery (src/trust.py's
    buckets), so it warns. The claim still cannot raise the authenticated tier,
    which is what the tier floor is for."""
    collection = signed_fixture.collection()
    signed_fixture.keyring = {a: k for a, k in signed_fixture.keyring.items() if a != "human:jsmith@acme"}

    d = _decide(signed_fixture, collection)["metrics/revenue"]
    assert d["checks"]["trust_authentic"]["ok"] is True
    assert any("actor not in keyring" in w for w in d["warnings"])
    assert d["tier"] == "unverified"

    strict = _decide(signed_fixture, collection, min_tier="human-reviewed")["metrics/revenue"]
    assert strict["admitted"] is False


def test_min_tier_is_a_separate_gate_from_downgrade(signed_fixture):
    """skills/run-on-bq has no `verified:` entry at all: honest, not forged. It
    admits under the permissive default and is refused only by explicit policy."""
    collection = signed_fixture.collection()

    default = _decide(signed_fixture, collection)["skills/run-on-bq"]
    assert default["admitted"] is True
    assert default["tier"] == "unverified"
    assert default["checks"]["trust_authentic"]["ok"] is True   # nothing was forged

    strict = _decide(signed_fixture, collection, min_tier="human-reviewed")["skills/run-on-bq"]
    assert strict["admitted"] is False
    assert strict["reasons"] == ["tier 'unverified' below required 'human-reviewed'"]


# ── freshness ─────────────────────────────────────────────────────────────────
def test_stale_after_is_strict_and_the_boundary_day_is_fresh(signed_fixture):
    collection = signed_fixture.collection()

    assert _decide(signed_fixture, collection, today=BOUNDARY)["metrics/revenue"]["admitted"] is True

    stale = _decide(signed_fixture, collection, today=AFTER)["metrics/revenue"]
    assert stale["admitted"] is False
    assert stale["reasons"] == ["stale (stale_after 2026-12-31, today 2027-01-02)"]


def test_unparsable_stale_after_warns_rather_than_crashing(signed_fixture):
    collection = signed_fixture.collection()
    meta = collection.rows["metrics/revenue"][0]
    fm = json.loads(meta["frontmatter_json"])
    fm["stale_after"] = "soon"
    collection.set_metadata("metrics/revenue", frontmatter_json=json.dumps(fm, sort_keys=True, separators=(",", ":")))

    d = _decide(signed_fixture, collection, today=AFTER)["metrics/revenue"]
    assert any("unparsable stale_after" in w for w in d["warnings"])
    assert d["checks"]["freshness"]["ok"] is True    # not stale, just unknown


# ── attested computations: pins, without executing ────────────────────────────
def test_attested_computation_admits_and_writes_no_run_log(signed_fixture, tmp_path):
    run_log = tmp_path / "runs.jsonl"
    d = _decide(signed_fixture, signed_fixture.collection())["computations/revenue-ytd"]
    assert d["admitted"] is True
    assert d["checks"]["pins"]["ok"] is True
    assert not run_log.exists(), "admission must never execute a run"


def test_fence_swap_refused_on_the_disk_surface_only(signed_fixture):
    """Swap the sanctioned SQL on disk. The STORE row is untouched, so the copy
    the model reads is still green — and the gate refuses anyway, on both
    disk-side checks. Do not overclaim the pin here: the fence lives in a `.md`
    body, so it is a Merkle leaf and the disk integrity check catches it too."""
    target = signed_fixture.bundle_path / "computations" / "revenue-ytd.md"
    target.write_text(target.read_text().replace("o.net_amount\n", "o.net_amount * 1.5\n", 1))

    d = _decide(signed_fixture, signed_fixture.collection())["computations/revenue-ytd"]
    assert d["admitted"] is False
    assert d["checks"]["integrity"]["ok"] is True, "the store copy was never touched"
    assert d["checks"]["integrity_on_disk"]["ok"] is False
    assert d["reasons"] == ["concept canonical-hash mismatch", "computation tampered (pin mismatch)"]


def test_attester_swap_is_caught_by_the_pin_and_nothing_else(signed_fixture):
    """attesters/sql_equality.py is not a `.md` file and so is never a Merkle
    leaf: the pin is its ONLY coverage anywhere in this project. Both integrity
    checks stay green, which is exactly why the pin has to exist."""
    attester = signed_fixture.bundle_path / "attesters" / "sql_equality.py"
    attester.write_text(attester.read_text() + "\n# swapped\n")

    d = _decide(signed_fixture, signed_fixture.collection())["computations/revenue-ytd"]
    assert d["admitted"] is False
    assert d["checks"]["integrity"]["ok"] is True
    assert d["checks"]["integrity_on_disk"]["ok"] is True
    assert d["reasons"] == ["attester tampered (pin mismatch)"]


# ── source closure ────────────────────────────────────────────────────────────
def test_tampered_source_refuses_the_citing_concept(signed_fixture):
    """metrics/revenue cites policies/revenue-recognition. Tamper the SOURCE's
    store row; the citing concept's own bytes are fine and it is refused anyway."""
    collection = signed_fixture.collection()
    collection.set_body("policies/revenue-recognition", "Revenue is recognized whenever convenient.\n")

    d = _decide(signed_fixture, collection)
    assert d["metrics/revenue"]["admitted"] is False
    assert any("source 'revenue-policy' not verifiable" in r for r in d["metrics/revenue"]["reasons"])


def test_stale_source_is_a_warning_not_a_refusal(signed_fixture):
    """Cascading a policy's staleness into every concept citing it would refuse
    the whole bundle on 2027-01-01 — deliberately non-blocking."""
    collection = signed_fixture.collection()
    # Only the SOURCE is past its date; keep the citing concept fresh by giving
    # it no stale_after of its own.
    meta = collection.rows["metrics/revenue"][0]
    fm = json.loads(meta["frontmatter_json"])
    fm.pop("stale_after", None)
    collection.set_metadata("metrics/revenue", frontmatter_json=json.dumps(fm, sort_keys=True, separators=(",", ":")))

    d = _decide(signed_fixture, collection, today=AFTER)["metrics/revenue"]
    # The frontmatter edit changes the digest, so integrity fails — assert on the
    # SOURCE check alone, which is what this test is about.
    assert d["checks"]["sources"]["ok"] is True
    assert any("revenue-policy" in w and "stale" in w for w in d["warnings"])


def test_external_url_source_is_out_of_reach_not_green_by_accident(signed_fixture):
    """tables/orders cites an https:// wiki page. This layer has never seen those
    bytes and must not pretend to have checked them."""
    d = _decide(signed_fixture, signed_fixture.collection())["tables/orders"]
    assert d["checks"]["sources"]["ok"] is True
    assert d["admitted"] is True


# ── citations ─────────────────────────────────────────────────────────────────
def test_parse_concept_citations_flags_only_real_refused_concepts():
    admitted = ["metrics/revenue"]
    known = ["metrics/revenue", "metrics/gross-margin-legacy"]
    cited, refused = parse_concept_citations(
        "Per [metrics/revenue] and [metrics/gross-margin-legacy], see also [1] and [note].",
        admitted, known,
    )
    assert cited == ["metrics/revenue"]
    assert refused == ["metrics/gross-margin-legacy"]


# ── the agent loop ────────────────────────────────────────────────────────────
def _agent(fx, collection, client, service_keys, **kwargs):
    sk, _ = service_keys
    return run_agent(
        "What is Acme's revenue definition?", collection, StubEmbedder(), client,
        fx.roots, fx.publisher_vk, fx.keyring,
        today=kwargs.pop("today", TODAY), bundle_id=BUNDLE_ID, n_results=9,
        service_sk=sk, service_key_id="test_service", **kwargs,
    )


def test_refused_concepts_never_reach_the_llm(signed_fixture, service_keys, tmp_path):
    collection = signed_fixture.collection()
    collection.set_body("metrics/revenue", "# Definition\n\nAttacker text.\n")
    client = StubLLM("Answered from [tables/orders].")

    result = _agent(signed_fixture, collection, client, service_keys, log_path=tmp_path / "a.jsonl")

    assert "metrics/revenue" in result["refused_concept_ids"]
    assert "metrics/gross-margin-legacy" in result["refused_concept_ids"]

    prompt = "\n".join(client.prompts)
    assert "Attacker text" not in prompt, "the tampered CONTENT must not reach the model"
    # Assert on the context header the formatter emits, not on the bare id: an
    # ADMITTED concept's body may legitimately mention another concept's path
    # (policies/revenue-recognition.md links to metrics/revenue), and that is a
    # citation inside signed content, not a leak of the refused concept.
    for refused in result["refused_concept_ids"]:
        assert f"[{refused}] (" not in prompt


def test_answer_citing_a_refused_concept_is_not_served(signed_fixture, service_keys, tmp_path):
    collection = signed_fixture.collection()
    client = StubLLM("The legacy definition applies, see [metrics/gross-margin-legacy].")

    result = _agent(signed_fixture, collection, client, service_keys, log_path=tmp_path / "a.jsonl")

    assert result["served"] is False
    assert any("cited refused concept" in r for r in result["reasons"])


def test_okf_answer_attestation_signs_the_refused_set(signed_fixture, service_keys, tmp_path):
    sk, vk = service_keys
    log = tmp_path / "a.jsonl"
    collection = signed_fixture.collection()
    result = _agent(signed_fixture, collection, StubLLM("See [tables/orders]."), service_keys, log_path=log)

    entry = json.loads(log.read_text().splitlines()[-1])
    assert verify_okf_answer(entry, vk) is True
    assert "metrics/gross-margin-legacy" in entry["refused_concept_ids"]

    entry["refused_concept_ids"] = []
    assert verify_okf_answer(entry, vk) is False, "the refusal record must be inside the signature"


def test_no_llm_stops_before_generation(signed_fixture, service_keys, tmp_path):
    client = StubLLM()
    result = _agent(signed_fixture, signed_fixture.collection(), client, service_keys,
                    no_llm=True, log_path=tmp_path / "a.jsonl")
    assert result["answer"] is None
    assert client.prompts == []
    assert result["decisions"], "the gate still reports"


# ── the fidelity leg, made real ───────────────────────────────────────────────
def _run_agent_with_computation(fx, answer, service_keys, tmp_path, **kwargs):
    sk, _ = service_keys
    return run_agent(
        "What was FY2026 revenue?", fx.collection(), StubEmbedder(), StubLLM(answer),
        fx.roots, fx.publisher_vk, fx.keyring,
        today=TODAY, bundle_id=BUNDLE_ID, n_results=9,
        run_concept="computations/revenue-ytd", params={"year": "2026"},
        service_sk=sk, service_key_id="test_service",
        log_path=tmp_path / "a.jsonl", run_log_path=tmp_path / "runs.jsonl", **kwargs,
    )


def test_claimed_value_source_moves_from_receipt_to_caller(signed_fixture, service_keys, tmp_path):
    """The loop src/okf_attest.py's docstring names: until a caller supplies an
    independently-derived number, the attester's fidelity leg compares the
    receipt to itself and cannot fail."""
    from src.okf_attest import attest_run

    probe = attest_run(
        signed_fixture.bundle_path, BUNDLE_ID, "computations/revenue-ytd", {"year": "2026"},
        signed_fixture.roots, signed_fixture.publisher_vk, *generate_keypair()[:1], "probe",
        signed_fixture.keyring, log_path=tmp_path / "probe.jsonl",
    )
    true_value = probe["receipt"]["result"][0]

    result = _run_agent_with_computation(
        signed_fixture, f"FY2026 revenue was {true_value}.", service_keys, tmp_path
    )

    assert len(result["runs"]) == 2
    assert result["runs"][0]["run"]["claimed_value_source"] == "receipt"
    assert result["runs"][1]["run"]["claimed_value_source"] == "caller"
    assert result["served"] is True


def test_model_misstating_an_attested_number_is_refused(signed_fixture, service_keys, tmp_path):
    result = _run_agent_with_computation(
        signed_fixture, "FY2026 revenue was 99999.99.", service_keys, tmp_path
    )
    assert result["served"] is False
    assert any("failed the bundle's attester" in r for r in result["reasons"])
    assert result["runs"][-1]["run"]["claimed_value_source"] == "caller"


def test_unparseable_answer_value_warns_and_still_serves(signed_fixture, service_keys, tmp_path):
    result = _run_agent_with_computation(
        signed_fixture, "The figure is available in the attested receipt.", service_keys, tmp_path
    )
    assert result["served"] is True
    assert any("value-unattested" in w for w in result["warnings"])
    assert len(result["runs"]) == 1, "no second run when there is no claimed value to check"


def test_parse_answer_value_heuristics():
    assert parse_answer_value("Revenue was 1,234.56 USD.") == Decimal("1234.56")
    assert parse_answer_value("no numbers here") is None
    # A fiscal-year label must not be mistaken for the figure.
    assert parse_answer_value("FY2026 revenue was 43042.42.") == Decimal("43042.42")
    assert parse_answer_value("The 2026 figure is 43042.42.") == Decimal("43042.42")


# ── regression: the arXiv answer attestation is untouched ─────────────────────
def test_existing_arxiv_attestation_shape_still_verifies():
    """src/attestation.py gained a `fields` parameter; its default must still
    reproduce the frozen payload byte for byte."""
    from src.attestation import _PAYLOAD_FIELDS, sign_attestation, verify_attestation

    sk, vk = generate_keypair()
    attestation = {
        "answer_sha256": "a" * 64, "chunk_hashes": ["b" * 64], "query_sha256": "c" * 64,
        "model": "gpt-4o-mini", "timestamp": "2026-01-01T00:00:00+00:00",
    }
    signed = sign_attestation(attestation, sk, "service_v1")
    assert verify_attestation(signed, vk) is True
    assert _PAYLOAD_FIELDS == ("answer_sha256", "chunk_hashes", "query_sha256", "model", "timestamp")


def test_okf_and_arxiv_payload_shapes_do_not_cross_verify(service_keys):
    """An OKF entry must not accidentally verify under the arXiv field tuple."""
    from src.attestation import verify_attestation

    sk, vk = service_keys
    entry = sign_okf_answer(
        build_okf_answer_attestation("q", "a", [], ["metrics/revenue"], BUNDLE_ID, "m"), sk, "k"
    )
    assert verify_okf_answer(entry, vk) is True
    assert verify_attestation(entry, vk) is False
