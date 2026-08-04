"""Shared fixtures for the OKF test suite.

signed_fixture() copies bundles/acme_retail into a tmp_path, signs it exactly
the way src.okf_ingest / scripts.sign_trust would in production, and returns
everything a test needs to call src.okf_verify.verify_bundle -- entirely
under tmp_path, with a throwaway publisher key and throwaway actor keys.
Nothing here ever writes into the committed bundle or the live
data/okf_roots.json / data/keys/actors/.
"""
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import nacl.signing
import pytest

from src.crypto import generate_keypair, sign
from src.merkle import compute_root
from src.okf import parse_bundle
from src.okf_ingest import build_pins
from src.schema import BundleRecord, ConceptRecord
from src.trust import ensure_actor_key, load_keyring, sign_trust_entry, trust_entries

BUNDLE_SRC = Path(__file__).parent.parent / "bundles" / "acme_retail"
BUNDLE_ID = "acme_retail"


@dataclass
class SignedFixture:
    bundle_path: Path
    bundle_id: str
    roots: dict
    publisher_vk: nacl.signing.VerifyKey
    keyring: dict[str, nacl.signing.VerifyKey]
    keys_dir: Path
    keyring_path: Path


@pytest.fixture
def signed_fixture(tmp_path) -> SignedFixture:
    bundle_path = tmp_path / "acme_retail"
    shutil.copytree(BUNDLE_SRC, bundle_path)

    publisher_sk, publisher_vk = generate_keypair()
    concepts: list[ConceptRecord] = parse_bundle(bundle_path, BUNDLE_ID)
    root_hex = compute_root([c["sha256"] for c in concepts])
    bundle_rec: BundleRecord = {
        "bundle_id": BUNDLE_ID,
        "merkle_root": root_hex,
        "root_signature": sign(publisher_sk, bytes.fromhex(root_hex)),
        "publisher_key_id": "test_publisher",
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }
    pins = build_pins(bundle_path, concepts, BUNDLE_ID, publisher_sk)

    keys_dir = tmp_path / "actor_keys"
    keyring_path = tmp_path / "keyring.json"
    trust_signatures = []
    for c in concepts:
        for actor, at, kind in trust_entries(c):
            actor_sk = ensure_actor_key(actor, keys_dir=keys_dir, keyring_path=keyring_path)
            trust_signatures.append(sign_trust_entry(BUNDLE_ID, c, actor, at, kind, actor_sk))

    roots = {
        BUNDLE_ID: {
            "bundle": bundle_rec,
            "bundle_path": str(bundle_path),
            "concepts": [
                {"concept_id": c["concept_id"], "sha256": c["sha256"], "merkle_index": c["merkle_index"]}
                for c in concepts
            ],
            "trust_signatures": trust_signatures,
            "computation_pins": pins,
        }
    }
    keyring = load_keyring(keyring_path)

    return SignedFixture(
        bundle_path=bundle_path,
        bundle_id=BUNDLE_ID,
        roots=roots,
        publisher_vk=publisher_vk,
        keyring=keyring,
        keys_dir=keys_dir,
        keyring_path=keyring_path,
    )
