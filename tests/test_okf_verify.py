"""Tests for src/okf_verify.py, driven through the full verify_bundle() report.

Uses the `signed_fixture` fixture (tests/conftest.py): a copy of
bundles/acme_retail under tmp_path, signed with throwaway publisher + actor
keys exactly as production would. Every tamper test mutates that COPY --
never the committed bundle or the live data/okf_roots.json.
"""
from src.okf_verify import verify_bundle


def test_clean_bundle_verifies(signed_fixture):
    report = verify_bundle(
        signed_fixture.bundle_path, signed_fixture.bundle_id, signed_fixture.roots, signed_fixture.publisher_vk, signed_fixture.keyring
    )
    assert report["ok"] is True
    assert report["root_matches"] is True
    assert report["root_signature_valid"] is True
    assert report["added_concepts"] == []
    assert report["removed_concepts"] == []
    assert len(report["concepts"]) == 9
    assert all(not c["tampered"] for c in report["concepts"])
    assert len(report["pins"]) == 2
    assert all(p["ok"] for p in report["pins"])

    tiers = {c["concept_id"]: c["trust"]["tier"] for c in report["concepts"]}
    assert tiers["skills/run-on-bq"] == "unverified"
    assert all(t == "human-reviewed" for cid, t in tiers.items() if cid != "skills/run-on-bq")
    assert all(not c["trust"]["downgraded"] for c in report["concepts"])


def test_value_edit_named(signed_fixture):
    target = signed_fixture.bundle_path / "metrics" / "revenue.md"
    text = target.read_text()
    target.write_text(text.replace("status: stable", "status: deprecated"))

    report = verify_bundle(
        signed_fixture.bundle_path, signed_fixture.bundle_id, signed_fixture.roots, signed_fixture.publisher_vk, signed_fixture.keyring
    )
    by_id = {c["concept_id"]: c for c in report["concepts"]}
    assert by_id["metrics/revenue"]["tampered"] is True
    assert by_id["metrics/revenue"]["reason"] == "concept canonical-hash mismatch"
    assert report["ok"] is False


def test_added_concept_detected(signed_fixture):
    new_file = signed_fixture.bundle_path / "metrics" / "new-metric.md"
    new_file.write_text("---\ntype: Metric\ntitle: New\n---\n\n# Body\n")

    report = verify_bundle(
        signed_fixture.bundle_path, signed_fixture.bundle_id, signed_fixture.roots, signed_fixture.publisher_vk, signed_fixture.keyring
    )
    assert report["added_concepts"] == ["metrics/new-metric"]
    assert report["root_matches"] is False
    assert report["ok"] is False


def test_removed_concept_detected(signed_fixture):
    (signed_fixture.bundle_path / "metrics" / "gross-margin-legacy.md").unlink()

    report = verify_bundle(
        signed_fixture.bundle_path, signed_fixture.bundle_id, signed_fixture.roots, signed_fixture.publisher_vk, signed_fixture.keyring
    )
    assert report["removed_concepts"] == ["metrics/gross-margin-legacy"]
    assert report["root_matches"] is False
    assert report["ok"] is False


def test_attester_swap_caught_by_pins(signed_fixture):
    attester = signed_fixture.bundle_path / "attesters" / "sql_equality.py"
    attester.write_text(attester.read_text() + "\n# tampered: always return ok\n")

    report = verify_bundle(
        signed_fixture.bundle_path, signed_fixture.bundle_id, signed_fixture.roots, signed_fixture.publisher_vk, signed_fixture.keyring
    )
    # the Merkle root is UNAFFECTED -- attesters/*.py is not a .md file, never a leaf.
    # The pin is the only coverage this file has at all.
    assert report["root_matches"] is True
    pins_by_id = {p["concept_id"]: p for p in report["pins"]}
    assert all(not p["ok"] for p in pins_by_id.values())
    assert all(p["reason"] == "attester tampered (pin mismatch)" for p in pins_by_id.values())
    assert report["ok"] is False


def test_computation_fence_swap_caught_by_pins(signed_fixture):
    """The headline demo attack: native OKF §10.5 has the attester re-derive
    from the SAME in-bundle computation the executor ran, so a swapped fence
    passes native attestation. The pin (fixed at sign time) catches it."""
    target = signed_fixture.bundle_path / "computations" / "revenue-ytd.md"
    text = target.read_text()
    assert "SUM(" in text
    target.write_text(text.replace("SUM(", "SUM(1.5 * "))  # inflate the reported revenue

    report = verify_bundle(
        signed_fixture.bundle_path, signed_fixture.bundle_id, signed_fixture.roots, signed_fixture.publisher_vk, signed_fixture.keyring
    )
    pins_by_id = {p["concept_id"]: p for p in report["pins"]}
    assert pins_by_id["computations/revenue-ytd"]["ok"] is False
    assert pins_by_id["computations/revenue-ytd"]["reason"] == "computation tampered (pin mismatch)"
    # the OTHER computation's pin, untouched, still verifies
    assert pins_by_id["computations/gross-margin-period"]["ok"] is True


def test_benign_round_trip_still_verifies(signed_fixture):
    """The signed-okf-beats-me proof: reordered frontmatter keys + CRLF +
    trailing whitespace must NOT change the digest, the root, or any check."""
    import yaml

    from src.okf import _split_frontmatter

    target = signed_fixture.bundle_path / "policies" / "margin-standard.md"
    fm, body = _split_frontmatter(target.read_text())
    reordered_fm = dict(reversed(list(fm.items())))
    rt_text = (
        "---\n"
        + yaml.safe_dump(reordered_fm, sort_keys=False, allow_unicode=True)
        + "---\n\n"
        + "\n".join(line + "   " for line in body.split("\n"))  # trailing whitespace
        + "\n\n\n"  # extra trailing blank lines
    ).replace("\n", "\r\n")  # CRLF
    target.write_text(rt_text)

    report = verify_bundle(
        signed_fixture.bundle_path, signed_fixture.bundle_id, signed_fixture.roots, signed_fixture.publisher_vk, signed_fixture.keyring
    )
    assert report["ok"] is True
    assert report["root_matches"] is True
    by_id = {c["concept_id"]: c for c in report["concepts"]}
    assert by_id["policies/margin-standard"]["tampered"] is False


def test_resigned_forged_tier_still_downgrades(signed_fixture):
    """THE HEADLINE TEST: forge an unsigned `verified` entry, then RE-SIGN
    the Merkle root over the forged bundle (simulating a publisher who signs
    without checking, or an attacker who also controls the publisher key at
    signing time but not any individual actor's key). The root signature
    comes back valid and the concept is not flagged as tampered -- proving
    this module is not redundant with the Day-1 Merkle root -- but the
    authenticated tier still refuses to rise, because no one holding
    human:attacker's key ever signed the claim."""
    from src.crypto import sign
    from src.merkle import compute_root
    from src.okf import parse_bundle

    target = signed_fixture.bundle_path / "skills" / "run-on-bq.md"
    text = target.read_text()
    assert "verified" not in text  # this concept starts with NO verified entry at all
    forged = text.replace(
        "status: stable",
        "verified:\n  - { by: human:attacker, at: 2026-08-03T00:00:00Z }\nstatus: stable",
    )
    target.write_text(forged)

    # Re-sign: a NEW publisher key, standing in for "publisher re-signs the
    # bundle as it now stands", exactly like `okf_ingest --force --resign`.
    from src.crypto import generate_keypair

    concepts = parse_bundle(signed_fixture.bundle_path, signed_fixture.bundle_id)
    new_root = compute_root([c["sha256"] for c in concepts])
    new_sk, new_vk = generate_keypair()
    signed_fixture.roots[signed_fixture.bundle_id]["bundle"] = {
        "bundle_id": signed_fixture.bundle_id,
        "merkle_root": new_root,
        "root_signature": sign(new_sk, bytes.fromhex(new_root)),
        "publisher_key_id": "test_publisher_v2",
        "signed_at": "2026-08-03T00:00:00+00:00",
    }
    signed_fixture.roots[signed_fixture.bundle_id]["concepts"] = [
        {"concept_id": c["concept_id"], "sha256": c["sha256"], "merkle_index": c["merkle_index"]} for c in concepts
    ]
    # trust_signatures deliberately left as-is: nobody ever signed the forged entry

    report = verify_bundle(signed_fixture.bundle_path, signed_fixture.bundle_id, signed_fixture.roots, new_vk, signed_fixture.keyring)

    assert report["root_matches"] is True
    assert report["root_signature_valid"] is True
    by_id = {c["concept_id"]: c for c in report["concepts"]}
    forged_concept = by_id["skills/run-on-bq"]
    assert forged_concept["tampered"] is False  # the root check alone sees nothing wrong

    trust = forged_concept["trust"]
    assert trust["claimed_tier"] == "human-reviewed"  # what a signal-trusting consumer would act on
    assert trust["tier"] == "unverified"  # what an agent using this module actually acts on
    assert trust["downgraded"] is True
    assert "human:attacker" in trust["unbacked"]


def test_deleted_trust_signature_fails_closed(signed_fixture):
    """An attacker with write access to okf_roots.json can DELETE a
    signature (downgrade -> refusal) but cannot forge one without the
    actor's key. Downgrade-on-deletion is the correct failure direction."""
    sigs = signed_fixture.roots[signed_fixture.bundle_id]["trust_signatures"]
    kept = [s for s in sigs if not (s["concept_id"] == "metrics/revenue" and s["kind"] == "verified")]
    assert len(kept) == len(sigs) - 1
    signed_fixture.roots[signed_fixture.bundle_id]["trust_signatures"] = kept

    report = verify_bundle(
        signed_fixture.bundle_path, signed_fixture.bundle_id, signed_fixture.roots, signed_fixture.publisher_vk, signed_fixture.keyring
    )
    by_id = {c["concept_id"]: c for c in report["concepts"]}
    trust = by_id["metrics/revenue"]["trust"]
    assert trust["tier"] == "unverified"
    assert trust["claimed_tier"] == "human-reviewed"
    assert trust["downgraded"] is True
    assert trust["unbacked"] == ["human:jsmith@acme"]
    assert by_id["metrics/revenue"]["tampered"] is False  # content itself is untouched
