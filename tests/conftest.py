"""Shared fixtures for the OKF test suite.

signed_fixture() copies bundles/acme_retail into a tmp_path, signs it exactly
the way src.okf_ingest / scripts.sign_trust would in production, and returns
everything a test needs to call src.okf_verify.verify_bundle -- entirely
under tmp_path, with a throwaway publisher key and throwaway actor keys.
Nothing here ever writes into the committed bundle or the live
data/okf_roots.json / data/keys/actors/.

e2e_sandbox() goes one step further: it lays the same signed material out at
the paths src.config expects, inside a tmp_path that becomes the CWD of real
subprocesses. src.config resolves every path relative to the CWD
(Path("data/okf_roots.json"), CHROMA_PATH = "data/chroma_db") with no env
override, so running a CLI with cwd=<sandbox> and PYTHONPATH=<repo root>
puts the entire trust anchor inside tmp_path. That is what lets
tests/test_demo_e2e.py drive the SHIPPED command lines -- the exact thing a
reviewer types -- without any risk to the committed bundle or the live data/.

Both entry points share one signing implementation (sign_bundle_into) so the
at-rest fixture and the subprocess sandbox can never drift apart.
"""
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import nacl.signing
import numpy
import pytest

from src.crypto import generate_keypair, save_keypair, sign
from src.merkle import compute_root
from src.okf import parse_bundle
from src.okf_ingest import _metadata, build_pins
from src.schema import BundleRecord, ConceptRecord
from src.trust import ensure_actor_key, load_keyring, sign_trust_entry, trust_entries

REPO_ROOT = Path(__file__).parent.parent
BUNDLE_SRC = REPO_ROOT / "bundles" / "acme_retail"
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


def sign_bundle_into(
    bundle_path: Path,
    bundle_id: str,
    keys_dir: Path,
    keyring_path: Path,
    publisher_sk: nacl.signing.SigningKey,
    publisher_key_id: str = "test_publisher",
) -> tuple[dict, list[ConceptRecord]]:
    """Sign a bundle on disk the way production does, and return the
    okf_roots.json-shaped dict plus the parsed concepts.

    Deliberately assembles the record from the SAME primitives
    src.okf_ingest.ingest_bundle uses -- parse_bundle, merkle.compute_root,
    crypto.sign, build_pins, trust.sign_trust_entry -- rather than calling
    ingest_bundle itself, because ingest_bundle also needs a Chroma
    collection and an embedding model, and every consumer of this helper is
    testing the CRYPTO surface, not retrieval. Actor keys are minted into
    keys_dir on demand, exactly as scripts/sign_trust.py --mint-missing does.
    """
    concepts: list[ConceptRecord] = parse_bundle(bundle_path, bundle_id)
    root_hex = compute_root([c["sha256"] for c in concepts])
    bundle_rec: BundleRecord = {
        "bundle_id": bundle_id,
        "merkle_root": root_hex,
        "root_signature": sign(publisher_sk, bytes.fromhex(root_hex)),
        "publisher_key_id": publisher_key_id,
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }
    pins = build_pins(bundle_path, concepts, bundle_id, publisher_sk)

    trust_signatures = []
    for c in concepts:
        for actor, at, kind in trust_entries(c):
            actor_sk = ensure_actor_key(actor, keys_dir=keys_dir, keyring_path=keyring_path)
            trust_signatures.append(sign_trust_entry(bundle_id, c, actor, at, kind, actor_sk))

    roots = {
        bundle_id: {
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
    return roots, concepts


@pytest.fixture
def signed_fixture(tmp_path) -> SignedFixture:
    bundle_path = tmp_path / "acme_retail"
    shutil.copytree(BUNDLE_SRC, bundle_path)

    publisher_sk, publisher_vk = generate_keypair()
    keys_dir = tmp_path / "actor_keys"
    keyring_path = tmp_path / "keyring.json"

    roots, concepts = sign_bundle_into(bundle_path, BUNDLE_ID, keys_dir, keyring_path, publisher_sk)
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


# ── subprocess sandbox: drive the SHIPPED CLIs, never the real data/ ─────────


@dataclass
class E2ESandbox:
    """A throwaway CWD that looks exactly like the repo's runtime state.

    Layout mirrors src.config's CWD-relative constants one for one:

        <root>/bundles/acme_retail/      copy of the committed bundle
        <root>/data/okf_roots.json       OKF_ROOTS_PATH
        <root>/data/keys/publisher.{sk,vk}, service.{sk,vk}
        <root>/data/keys/actors/keyring.json + per-actor keys
        <root>/data/tamper_backups/      written by scripts/tamper_okf.py
        <root>/data/okf_runs.jsonl       written by src.okf_attest
    """

    root: Path
    bundle_path: Path
    bundle_arg: str  # bundle path as a CLI argument, relative to the sandbox
    bundle_id: str
    repo_root: Path
    env: dict

    def run(self, *argv: str) -> subprocess.CompletedProcess:
        """Run a shipped entrypoint as a real subprocess inside the sandbox.

        The first token is either "-m" (module form, e.g. run("-m",
        "src.okf_attest", ...)) or a repo-relative script path (e.g.
        run("verify.py", ...)). Everything after it is passed through
        verbatim, so a call site here reads like the command a user types --
        which is the whole point of this fixture: these tests fail if the
        argument NAMES change, not just if the library behaviour does.
        """
        head = [*argv] if argv[0] == "-m" else [str(self.repo_root / argv[0]), *argv[1:]]
        return subprocess.run(
            [sys.executable, *head],
            cwd=self.root,
            env=self.env,
            capture_output=True,
            text=True,
        )

    def read(self, rel: str) -> bytes:
        return (self.root / rel).read_bytes()


@pytest.fixture
def e2e_sandbox(tmp_path) -> E2ESandbox:
    root = tmp_path / "sandbox"
    bundle_path = root / "bundles" / BUNDLE_ID
    bundle_path.parent.mkdir(parents=True)
    shutil.copytree(BUNDLE_SRC, bundle_path)
    # A stale __pycache__ copied from the committed bundle would shadow the
    # attester source that swap-attester rewrites; drop it so every run
    # imports from the bytes actually on disk.
    shutil.rmtree(bundle_path / "attesters" / "__pycache__", ignore_errors=True)

    keys_dir = root / "data" / "keys"
    actor_keys_dir = keys_dir / "actors"
    keyring_path = actor_keys_dir / "keyring.json"

    publisher_sk, _ = generate_keypair()
    save_keypair(publisher_sk, keys_dir / "publisher.sk", keys_dir / "publisher.vk")
    service_sk, _ = generate_keypair()
    save_keypair(service_sk, keys_dir / "service.sk", keys_dir / "service.vk")

    roots, _ = sign_bundle_into(bundle_path, BUNDLE_ID, actor_keys_dir, keyring_path, publisher_sk)
    (root / "data" / "okf_roots.json").write_text(json.dumps(roots, indent=2))

    env = {
        **os.environ,
        "PYTHONPATH": str(REPO_ROOT),  # `import src` works from any CWD
        "PYTHONIOENCODING": "utf-8",  # the ✅/❌ output must survive capture
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    env.pop("OPENAI_API_KEY", None)  # nothing in this suite may reach the network

    return E2ESandbox(
        root=root,
        bundle_path=bundle_path,
        bundle_arg=f"bundles/{BUNDLE_ID}",
        bundle_id=BUNDLE_ID,
        repo_root=REPO_ROOT,
        env=env,
    )
