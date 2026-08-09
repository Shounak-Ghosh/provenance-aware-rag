"""Tests for scripts/tamper_okf.py: the four attack demos + backup/restore.

Every test operates on tests/conftest.py::signed_fixture -- a tmp_path copy
of bundles/acme_retail signed with throwaway publisher + actor keys -- so
the committed bundle and the live data/okf_roots.json are NEVER touched.
`backup_root=tmp_path / "backups"` is passed to every call that touches the
tamper-backup manifest, so tests never write into the real data/tamper_backups/
directory either (which additionally would collide across tests: every
signed_fixture shares the literal bundle_id "acme_retail").

Where a test needs a roots.json FILE (forge_tier reads/writes one; the
in-memory signed_fixture.roots dict is not a file), _write_roots() writes
fixture.roots to a tmp_path json file first.
"""
import json
from pathlib import Path

import pytest

from src.crypto import generate_keypair
from src.okf_attest import attest_run, native_attest_run
from src.okf_verify import verify_bundle

from scripts.tamper_okf import (
    TamperError,
    benign_round_trip,
    forge_tier,
    restore,
    status,
    swap_attester,
    swap_fence,
)

SERVICE_KEY_ID = "test_service"


def _write_roots(fixture, tmp_path: Path) -> Path:
    path = tmp_path / "okf_roots.json"
    path.write_text(json.dumps(fixture.roots, indent=2))
    return path


def _verify(fixture) -> dict:
    return verify_bundle(fixture.bundle_path, fixture.bundle_id, fixture.roots, fixture.publisher_vk, fixture.keyring)


# ── benign-round-trip: the canonicalization win ──────────────────────────────
def test_benign_round_trip_preserves_digest_root_and_pins(signed_fixture, tmp_path):
    before = _verify(signed_fixture)
    result = benign_round_trip(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "computations/revenue-ytd",
        backup_root=tmp_path / "backups",
    )

    assert result["sha256_before"] == result["sha256_after"]
    assert result["root_before"] == result["root_after"]
    assert result["computation_pin_before"] == result["computation_pin_after"]
    assert result["raw_before"] != result["raw_after"]  # the raw bytes DID move

    after = _verify(signed_fixture)
    assert after["ok"] is True
    assert after == before  # not just ok=True: the WHOLE report is byte-for-byte unchanged


def test_benign_round_trip_preserves_trust_signatures(signed_fixture, tmp_path):
    """Targets metrics/revenue (no computation pins), so this isolates trust-
    signature survival: the `verified[].at` re-spelling PyYAML's round-trip
    introduces (an ISO timestamp -> "2026-07-01 09:00:00+00:00") must not
    break human:jsmith@acme's signature."""
    before = _verify(signed_fixture)
    by_id_before = {c["concept_id"]: c for c in before["concepts"]}
    assert by_id_before["metrics/revenue"]["trust"]["tier"] == "human-reviewed"

    benign_round_trip(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "metrics/revenue",
        backup_root=tmp_path / "backups",
    )

    after = _verify(signed_fixture)
    by_id_after = {c["concept_id"]: c for c in after["concepts"]}
    assert by_id_after["metrics/revenue"]["tampered"] is False
    assert by_id_after["metrics/revenue"]["trust"]["tier"] == "human-reviewed"
    assert by_id_after["metrics/revenue"]["trust"]["downgraded"] is False


# ── swap-fence: the headline attack ───────────────────────────────────────────
def test_fence_swap_native_passes_but_pinned_refuses(signed_fixture, tmp_path):
    """The fence lives inside the concept BODY, so attest_run refuses it at
    stage 1 (Merkle/canonical-hash, via verify_bundle) before pins are even
    consulted -- check_pins's unique coverage is the attester file and any
    non-.md computation file (see test_attester_swap_leaves_every_integrity_
    check_green for the case pins uniquely catch). What matters for the
    headline claim is refuse-before-execute holding regardless of WHICH
    stage catches it, contrasted with native_attest_run's blind PASS."""
    service_sk, _ = generate_keypair()
    swap_fence(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "computations/revenue-ytd",
        backup_root=tmp_path / "backups",
    )

    native = native_attest_run(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "computations/revenue-ytd", {"year": "2026"}
    )
    assert native["ok"] is True  # SPEC §10.5: the attester re-derives from the SAME swapped fence

    pinned = attest_run(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "computations/revenue-ytd", {"year": "2026"},
        signed_fixture.roots, signed_fixture.publisher_vk, service_sk, SERVICE_KEY_ID, signed_fixture.keyring,
        log_path=tmp_path / "runs.jsonl",
    )
    assert pinned["ok"] is False
    assert pinned["stage"] == 1
    assert pinned["reason"] == "concept canonical-hash mismatch"


def test_fence_swap_sibling_reason_is_merkle_not_hash(signed_fixture, tmp_path):
    """Pins the (documented) noise property behind verify.py's NOTE: after
    ONE concept's content changes, the root moves, so every OTHER concept's
    Merkle proof fails too -- with a DIFFERENT reason than the edited one."""
    swap_fence(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "computations/revenue-ytd",
        backup_root=tmp_path / "backups",
    )
    report = _verify(signed_fixture)

    by_id = {c["concept_id"]: c for c in report["concepts"]}
    assert by_id["computations/revenue-ytd"]["reason"] == "concept canonical-hash mismatch"
    siblings = [c for cid, c in by_id.items() if cid != "computations/revenue-ytd"]
    assert len(siblings) == len(report["concepts"]) - 1
    assert all(c["reason"] == "merkle proof failed" for c in siblings)


# ── swap-attester: sharper than swap-fence ───────────────────────────────────
def test_attester_swap_leaves_every_integrity_check_green(signed_fixture, tmp_path):
    """attesters/sql_equality.py is not a `.md` concept file, so it is never
    a Merkle leaf: swapping it must leave root/signature/every concept digest
    GREEN, and be caught ONLY by the pin -- for BOTH Attested Computations
    that share this one attester file."""
    swap_attester(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "computations/revenue-ytd",
        backup_root=tmp_path / "backups",
    )
    report = _verify(signed_fixture)

    assert report["root_matches"] is True
    assert report["root_signature_valid"] is True
    assert all(not c["tampered"] for c in report["concepts"])
    pins_by_id = {p["concept_id"]: p for p in report["pins"]}
    assert pins_by_id["computations/revenue-ytd"]["ok"] is False
    assert pins_by_id["computations/gross-margin-period"]["ok"] is False
    assert report["ok"] is False  # pins alone sink verify_bundle's ok


def test_attester_swap_native_still_passes(signed_fixture, tmp_path):
    swap_attester(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "computations/revenue-ytd",
        backup_root=tmp_path / "backups",
    )
    native = native_attest_run(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "computations/revenue-ytd", {"year": "2026"}
    )
    assert native["ok"] is True  # native attestation is blind to a non-.md file swap


# ── forge-tier: naive vs. re-signed ───────────────────────────────────────────
def test_forge_tier_naive_caught_by_hash(signed_fixture, tmp_path):
    roots_path = _write_roots(signed_fixture, tmp_path)
    forge_tier(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "metrics/revenue", "human:attacker",
        roots_path=roots_path, backup_root=tmp_path / "backups",
    )

    report = _verify(signed_fixture)
    by_id = {c["concept_id"]: c for c in report["concepts"]}
    assert by_id["metrics/revenue"]["tampered"] is True
    assert by_id["metrics/revenue"]["reason"] == "concept canonical-hash mismatch"


def test_forge_tier_resigned_caught_only_by_trust(signed_fixture, tmp_path):
    """THE headline trust demo: root recomputed AND re-signed with the
    publisher key models a write-capable adversary who is also the
    re-publisher. Root/signature/hash all verify -- only
    trust.derive_authenticated_tier's per-actor signature check catches it,
    because human:attacker never signed anything."""
    roots_path = _write_roots(signed_fixture, tmp_path)
    publisher_sk, publisher_vk = generate_keypair()  # signed_fixture only exposes the verify key

    forge_tier(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "metrics/revenue", "human:attacker",
        resign=True, roots_path=roots_path, publisher_sk=publisher_sk, backup_root=tmp_path / "backups",
    )

    roots = json.loads(roots_path.read_text())
    report = verify_bundle(signed_fixture.bundle_path, signed_fixture.bundle_id, roots, publisher_vk, signed_fixture.keyring)

    assert report["root_matches"] is True
    assert report["root_signature_valid"] is True
    by_id = {c["concept_id"]: c for c in report["concepts"]}
    assert by_id["metrics/revenue"]["tampered"] is False
    trust = by_id["metrics/revenue"]["trust"]
    assert trust["downgraded"] is True
    assert "human:attacker" in trust["unbacked"]
    assert report["trust_downgraded"] == ["metrics/revenue"]
    assert report["ok"] is True  # D6: the at-rest report stays green; POLICY is what refuses


# ── restore ──────────────────────────────────────────────────────────────────
def test_restore_returns_bundle_to_pristine(signed_fixture, tmp_path):
    backup_root = tmp_path / "backups"
    roots_path = _write_roots(signed_fixture, tmp_path)
    before = _verify(signed_fixture)
    pristine_root = before["recomputed_root"]

    swap_fence(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "computations/revenue-ytd",
        backup_root=backup_root,
    )
    swap_attester(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "computations/revenue-ytd",
        backup_root=backup_root,
    )
    forge_tier(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "metrics/revenue", "human:attacker",
        roots_path=roots_path, backup_root=backup_root,
    )
    benign_round_trip(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "policies/margin-standard",
        backup_root=backup_root,
    )

    restored = restore(signed_fixture.bundle_path, signed_fixture.bundle_id, backup_root)
    assert set(restored) == {
        "computations/revenue-ytd.md",
        "attesters/sql_equality.py",
        "metrics/revenue.md",
        "policies/margin-standard.md",
    }

    after = _verify(signed_fixture)
    assert after["recomputed_root"] == pristine_root
    assert after == before

    st = status(signed_fixture.bundle_path, signed_fixture.bundle_id, backup_root)
    assert st["files"] == []


def test_restore_with_no_backups_is_a_noop(signed_fixture, tmp_path):
    assert restore(signed_fixture.bundle_path, signed_fixture.bundle_id, tmp_path / "backups") == []


# ── self-check discipline ─────────────────────────────────────────────────────
def test_tamper_self_check_refuses_to_lie(signed_fixture, tmp_path, monkeypatch):
    """If a tamper function's own before/after invariant does not hold, it
    MUST raise TamperError and leave the file byte-identical to before --
    never write a mutation that doesn't have the effect it claims. Simulated
    by freezing canonical_computation_bytes to a constant, so the pin digest
    looks unchanged regardless of what swap_fence actually wrote -- exactly
    what a canonicalizer regression would look like from this script's side."""
    import scripts.tamper_okf as tamper_okf

    target = signed_fixture.bundle_path / "computations" / "revenue-ytd.md"
    raw_before = target.read_bytes()

    monkeypatch.setattr(tamper_okf, "canonical_computation_bytes", lambda *a, **k: b"frozen")

    with pytest.raises(TamperError, match="self-check failed"):
        swap_fence(
            signed_fixture.bundle_path, signed_fixture.bundle_id, "computations/revenue-ytd",
            backup_root=tmp_path / "backups",
        )

    assert target.read_bytes() == raw_before
