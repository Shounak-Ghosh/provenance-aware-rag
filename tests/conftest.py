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
import numpy
import pytest

from src.crypto import generate_keypair, sign
from src.merkle import compute_root
from src.okf import parse_bundle
from src.okf_ingest import _metadata, build_pins
from src.schema import BundleRecord, ConceptRecord
from src.trust import ensure_actor_key, load_keyring, sign_trust_entry, trust_entries

BUNDLE_SRC = Path(__file__).parent.parent / "bundles" / "acme_retail"
BUNDLE_ID = "acme_retail"


class FakeCollection:
    """In-memory stand-in for the `okf_concepts` Chroma collection.

    Rows are built by feeding real parsed concepts through
    src.okf_ingest._metadata VERBATIM, so the test store cannot drift from the
    production store's shape -- a field the gate reads but ingest never writes
    would fail here exactly as it would in production. No chromadb client, no
    embedding model, no network.

    `query()` ignores the embedding and returns rows in insertion order (or the
    explicitly staged `next_hits`): relevance ranking is not what any test in
    this file is about, and a fixed order keeps the assertions about ADMISSION
    rather than about retrieval quality.
    """

    def __init__(self, concepts: list[ConceptRecord]):
        self.rows = {c["concept_id"]: [_metadata(c), c["body"]] for c in concepts}
        self.next_hits: list[str] | None = None

    def _select(self, ids: list[str]) -> list[list[str]]:
        return [self.rows[i] for i in ids]

    def query(self, query_embeddings=None, n_results=5, where=None, include=None) -> dict:
        ids = self.next_hits if self.next_hits is not None else list(self.rows)
        if where and "bundle_id" in where:
            ids = [i for i in ids if self.rows[i][0]["bundle_id"] == where["bundle_id"]]
        ids = ids[:n_results]
        selected = self._select(ids)
        return {
            "ids": [ids],
            "metadatas": [[m for m, _ in selected]],
            "documents": [[d for _, d in selected]],
            "distances": [[0.1 * i for i in range(len(ids))]],
        }

    def get(self, where=None, include=None, ids=None) -> dict:
        keys = ids if ids is not None else list(self.rows)
        if where and "bundle_id" in where:
            keys = [k for k in keys if self.rows[k][0]["bundle_id"] == where["bundle_id"]]
        selected = self._select(keys)
        return {
            "ids": keys,
            "metadatas": [m for m, _ in selected],
            "documents": [d for _, d in selected],
        }

    def count(self) -> int:
        return len(self.rows)

    # ── tamper helpers: mutate the STORE only, never the bundle on disk ──
    def set_body(self, concept_id: str, body: str) -> None:
        self.rows[concept_id][1] = body

    def set_metadata(self, concept_id: str, **fields) -> None:
        self.rows[concept_id][0].update(fields)


class StubEmbedder:
    """Stands in for SentenceTransformer. FakeCollection ignores the vector, so
    it only has to be ndarray-shaped -- callers do `.encode(...)[0].tolist()`."""

    def encode(self, texts, normalize_embeddings=True):
        return numpy.zeros((len(texts), 4), dtype=numpy.float32)


class StubLLM:
    """Minimal OpenAI-client shape. Records every prompt it was given, which is
    how test_refused_concepts_never_reach_the_llm proves the negative."""

    def __init__(self, answer: str = "No numeric claim here."):
        self.answer = answer
        self.prompts: list[str] = []
        self.chat = self  # client.chat.completions.create(...)
        self.completions = self

    def create(self, model=None, temperature=None, messages=None):
        self.prompts.append("\n".join(m["content"] for m in messages))
        text = self.answer

        class _Msg:
            content = text

        class _Choice:
            message = _Msg()

        class _Response:
            choices = [_Choice()]

        return _Response()


@dataclass
class SignedFixture:
    bundle_path: Path
    bundle_id: str
    roots: dict
    publisher_vk: nacl.signing.VerifyKey
    keyring: dict[str, nacl.signing.VerifyKey]
    keys_dir: Path
    keyring_path: Path
    concepts: list[ConceptRecord]

    def collection(self) -> FakeCollection:
        return FakeCollection(self.concepts)


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
        concepts=concepts,
    )
