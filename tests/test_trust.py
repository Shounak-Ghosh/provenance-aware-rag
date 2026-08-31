"""Tests for src/trust.py -- per-actor authenticated trust signatures.

Where a test needs a fully signed bundle (real Merkle root + real trust
signatures under throwaway keys), it uses the `signed_fixture` fixture from
tests/conftest.py, which operates entirely under tmp_path. Tests that only
need to reason about one concept's trust claims work directly against the
real vendored bundles/acme_retail (read-only) plus in-memory mutations --
see _forge_verified_entry below, which mimics what parse_bundle() would
produce if the file itself had been edited on disk.
"""
import copy
import hashlib
import json
from pathlib import Path

import pytest

from src.crypto import generate_keypair
from src.okf import canonical_frontmatter_json, canonicalize_from_parts, parse_bundle
from src.schema import ConceptRecord
from src.trust import (
    actor_kind,
    claimed_tier,
    derive_authenticated_tier,
    index_trust_signatures,
    sign_trust_entry,
    trust_entries,
    trust_message,
    verify_trust_entry,
)

BUNDLE_PATH = Path(__file__).parent.parent / "bundles" / "acme_retail"


def _forge_verified_entry(concept: ConceptRecord, actor: str, at: str) -> ConceptRecord:
    """Return a COPY of concept with an extra unsigned `verified` entry
    appended, and frontmatter_json/sha256 recomputed exactly the way
    parse_bundle() would if the file on disk had actually been edited this
    way. Lets trust-derivation tests exercise a forgery without touching disk."""
    c = copy.deepcopy(concept)
    fm = c["frontmatter"]
    existing = fm.get("verified")
    entries = list(existing) if isinstance(existing, list) else ([existing] if existing else [])
    entries.append({"by": actor, "at": at})
    fm["verified"] = entries
    fm_json = canonical_frontmatter_json(fm)
    c["frontmatter"] = json.loads(fm_json)
    c["frontmatter_json"] = fm_json
    c["sha256"] = hashlib.sha256(canonicalize_from_parts(fm_json, c["body"])).hexdigest()
    return c


@pytest.fixture(scope="module")
def concepts_by_id():
    return {c["concept_id"]: c for c in parse_bundle(BUNDLE_PATH, "acme_retail")}


def test_claimed_tier_matches_reference_viz(concepts_by_id):
    """Interop, not self-consistency: bundles/acme_retail/viz.html embeds
    Google's own reference renderer's precomputed trust_tier per node. Our
    claimed_tier() (the plaintext-YAML ladder) must agree with it exactly."""
    text = (BUNDLE_PATH / "viz.html").read_text()
    i = text.index("window.BUNDLE = ") + len("window.BUNDLE = ")
    bundle_json, _ = json.JSONDecoder().raw_decode(text, i)
    reference_tiers = {n["data"]["id"]: n["data"]["trust_tier"] for n in bundle_json["nodes"]}

    checked = 0
    for concept_id, concept in concepts_by_id.items():
        if concept_id not in reference_tiers:
            continue  # reserved files (e.g. "log") appear in the viz but are never concepts
        assert claimed_tier(concept) == reference_tiers[concept_id], concept_id
        checked += 1
    assert checked == 9


def test_trust_entries_counts(concepts_by_id):
    all_entries = [e for c in concepts_by_id.values() for e in trust_entries(c)]
    assert len(all_entries) == 17
    verified = [e for e in all_entries if e[2] == "verified"]
    generated = [e for e in all_entries if e[2] == "generated"]
    assert len(verified) == 8
    assert len(generated) == 9
    actors = {e[0] for e in all_entries}
    assert actors == {"human:jsmith@acme", "human:kliu@acme", "reference_agent/gemini-2.5-pro"}


def test_actor_kind():
    assert actor_kind("human:jsmith@acme") == "human"
    assert actor_kind("team:data-platform") == "team"
    assert actor_kind("process:finance-nightly") == "process"
    assert actor_kind("reference_agent/gemini-2.5-pro") == "agent"


def test_sign_and_verify_roundtrip(concepts_by_id, tmp_path):
    from src.trust import ensure_actor_key, load_keyring

    keys_dir = tmp_path / "actors"
    keyring_path = tmp_path / "keyring.json"
    concept = concepts_by_id["metrics/revenue"]
    actor, at = "human:jsmith@acme", "2026-07-01T09:00:00Z"

    sk = ensure_actor_key(actor, keys_dir=keys_dir, keyring_path=keyring_path)
    sig = sign_trust_entry("acme_retail", concept, actor, at, "verified", sk)
    keyring = load_keyring(keyring_path)

    assert verify_trust_entry(sig, concept["sha256"], keyring) is True
    assert verify_trust_entry(sig, "0" * 64, keyring) is False  # wrong digest -> invalid


def test_forged_tier_on_unverified_concept_does_not_rise(concepts_by_id):
    """skills/run-on-bq has no `verified` entry in the real bundle -- the
    sharpest forgery target, since adding one RAISES the claimed tier."""
    forged = _forge_verified_entry(concepts_by_id["skills/run-on-bq"], "human:attacker", "2026-08-03T00:00:00Z")
    assert claimed_tier(forged) == "human-reviewed"  # what a signal-trusting consumer would see

    sig_index: dict = {}  # attacker's entry was never signed by anyone
    keyring: dict = {}
    ta = derive_authenticated_tier("acme_retail", forged, sig_index, keyring)
    assert ta["tier"] == "unverified"
    assert ta["claimed_tier"] == "human-reviewed"
    assert ta["downgraded"] is True
    assert ta["unbacked"] == ["human:attacker"]
    assert ta["authenticated"] == []


def test_edit_revokes_existing_trust_signatures(concepts_by_id, tmp_path):
    """The property that falls out for free: because trust_message binds
    concept_sha256, editing a VERIFIED concept invalidates its existing
    signature too, not just failing to authenticate the new forged entry."""
    from src.trust import ensure_actor_key, load_keyring

    keys_dir = tmp_path / "actors"
    keyring_path = tmp_path / "keyring.json"
    concept = concepts_by_id["metrics/revenue"]
    actor, at = "human:jsmith@acme", "2026-07-01T09:00:00Z"
    sk = ensure_actor_key(actor, keys_dir=keys_dir, keyring_path=keyring_path)
    genuine_sig = sign_trust_entry("acme_retail", concept, actor, at, "verified", sk)
    keyring = load_keyring(keyring_path)

    forged = _forge_verified_entry(concept, "human:attacker", "2026-08-03T00:00:00Z")
    sig_index = index_trust_signatures([genuine_sig])  # keyed by (concept_id, actor, at, kind) -- still found

    ta = derive_authenticated_tier("acme_retail", forged, sig_index, keyring)
    assert ta["claimed_tier"] == "human-reviewed"  # jsmith's `by:` entry is still textually present
    assert ta["tier"] == "unverified"  # but jsmith's signature no longer matches the edited digest
    assert "human:jsmith@acme" in ta["invalid"]
    assert "human:attacker" in ta["unbacked"]
    assert ta["downgraded"] is True


def test_unknown_actor_is_not_authenticated(concepts_by_id):
    forged = _forge_verified_entry(concepts_by_id["skills/run-on-bq"], "human:ghost@nowhere", "2026-08-03T00:00:00Z")
    fake_sig = {
        "bundle_id": "acme_retail",
        "concept_id": forged["concept_id"],
        "actor": "human:ghost@nowhere",
        "at": "2026-08-03T00:00:00Z",
        "kind": "verified",
        "signature": "not-a-real-signature",
    }
    sig_index = index_trust_signatures([fake_sig])
    ta = derive_authenticated_tier("acme_retail", forged, sig_index, keyring={})  # actor absent from keyring
    assert ta["unknown_actor"] == ["human:ghost@nowhere"]
    assert ta["invalid"] == []  # NOT the same bucket as a signature that fails to verify
    assert ta["tier"] == "unverified"


def test_trust_signature_does_not_replay_across_concepts():
    """concept_id is bound into trust_message() precisely because
    okf.canonicalize_concept does not hash the path -- a signature for one
    concept must not verify against a different concept with identical content."""
    sk, vk = generate_keypair()
    sha256 = "ab" * 32
    sig = sign_trust_entry(
        "acme_retail",
        {"concept_id": "metrics/a", "sha256": sha256},
        "human:x",
        "2026-01-01T00:00:00Z",
        "verified",
        sk,
    )
    keyring = {"human:x": vk}
    assert verify_trust_entry(sig, sha256, keyring) is True

    replayed = {**sig, "concept_id": "metrics/b"}  # same content digest, different path
    assert verify_trust_entry(replayed, sha256, keyring) is False


def test_trust_message_rejects_delimiter_in_field():
    with pytest.raises(ValueError, match="reserved delimiter"):
        trust_message("acme_retail", "metrics/rev|enue", "ab" * 32, "human:x", "2026-01-01T00:00:00Z", "verified")


def test_index_trust_signatures_rejects_duplicates():
    sig = {"bundle_id": "b", "concept_id": "c", "actor": "human:x", "at": "t", "kind": "verified", "signature": "s"}
    with pytest.raises(ValueError, match="duplicate trust signature"):
        index_trust_signatures([sig, dict(sig)])
