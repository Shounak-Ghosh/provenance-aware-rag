"""Ingest an OKF v0.2 bundle: parse -> canonicalize -> Merkle -> sign -> Chroma + okf_roots.json.

Per-bundle mirror of src/ingest.py::ingest. Reuses merkle.compute_root and
crypto.sign verbatim; the only new machinery is okf.canonicalize_concept
feeding the same SHA-256 leaves that fed the arXiv chunk tree.

    uv run python -m src.okf_ingest bundles/acme_retail --bundle-id acme_retail
"""
import argparse
import hashlib
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from sentence_transformers import SentenceTransformer

from src.config import (
    EMBED_MODEL_NAME,
    OKF_CANON_VERSION,
    OKF_COLLECTION_NAME,
    OKF_ROOTS_PATH,
    PUBLISHER_KEY_ID,
    PUBLISHER_SIGNING_KEY_PATH,
)
from src.crypto import load_signing_key, sign
from src.merkle import compute_root
from src.okf import _as_list, attester_bytes, canonical_computation_bytes, parse_bundle, pins_message
from src.schema import BundleRecord, ComputationPins, ConceptRecord
from src.store import get_collection


def build_pins(bundle_path: Path, concepts: list[ConceptRecord], bundle_id: str, publisher_sk) -> list[ComputationPins]:
    """Pin the sanctioned computation + attester of every concept that carries one.

    Emitted HERE, at bundle-sign time, not deferred to run time: this is the
    only place the publisher secret key is loaded. attesters/*.py is not a
    `.md` file, so it is never a Merkle leaf -- without these pins, nothing in
    the bundle signature covers the attester at all, and an in-place swap of
    it would go undetected by everything built in this pass.
    """
    pins: list[ComputationPins] = []
    for c in concepts:
        comp = canonical_computation_bytes(c, bundle_path)
        att = attester_bytes(bundle_path, c)
        if comp is None and att is None:
            continue
        comp_sha = hashlib.sha256(comp).hexdigest() if comp else ""
        att_sha, att_ref = (hashlib.sha256(att[0]).hexdigest(), att[1]) if att else ("", "")
        pins.append(
            {
                "concept_id": c["concept_id"],
                "computation_sha256": comp_sha,
                "attester_sha256": att_sha,
                "attester_resource": att_ref,
                "pins_signature": sign(
                    publisher_sk, pins_message(bundle_id, c["concept_id"], comp_sha, att_sha)
                ),
            }
        )
    return pins


def _embed_text(c: ConceptRecord) -> str:
    """Text handed to the embedding model: title + description + body.

    Safe to differ from the stored `documents` text only because
    src/store.py::get_collection registers no embedding function -- Chroma
    never re-embeds on its own, so embeddings are always exactly what we pass
    (see src/ingest.py, same pattern). The stored document must stay
    byte-exact for re-hashing; the embedding input can be richer.
    """
    desc = str(c["frontmatter"].get("description", ""))
    return "\n".join(x for x in (c["title"], desc, c["body"]) if x)


def _metadata(c: ConceptRecord) -> dict:
    """Chroma metadata for one concept: scalars only (no nested dicts/lists).

    `frontmatter_json` carries the FULL frontmatter losslessly, so a later
    tamper check can rebuild the exact hashed bytes via
    okf.canonicalize_from_parts -- Chroma scalar metadata alone could not.
    The flattened fields below duplicate values already inside that JSON and
    exist only for cheap `where=` filtering; verification should never read
    them instead of frontmatter_json.
    """
    fm = c["frontmatter"]
    verified = [str(e.get("by", "")) for e in _as_list(fm.get("verified")) if isinstance(e, dict)]
    generated = fm.get("generated") if isinstance(fm.get("generated"), dict) else {}
    executor = fm.get("executor") if isinstance(fm.get("executor"), dict) else {}
    attester = fm.get("attester") if isinstance(fm.get("attester"), dict) else {}
    return {
        "concept_id": c["concept_id"],
        "bundle_id": c["bundle_id"],
        "rel_path": c["rel_path"],
        "type": c["type"],
        "title": c["title"],
        "sha256": c["sha256"],
        "merkle_index": c["merkle_index"],
        "status": str(fm.get("status", "")),
        "stale_after": str(fm.get("stale_after", "")),  # already normalized to an ISO string
        "generated_by": str(generated.get("by", "")),
        "generated_at": str(generated.get("at", "")),
        "verified_by": ",".join(verified),
        "verified_count": len(verified),
        "runtime": str(fm.get("runtime", "")),
        "executor_resource": str(executor.get("resource", "")),
        "attester_resource": str(attester.get("resource", "")),
        "tags": ",".join(str(t) for t in _as_list(fm.get("tags"))),
        "has_computation": bool(canonical_computation_bytes(c)),
        "frontmatter_json": c["frontmatter_json"],
    }


def _load_roots() -> dict:
    return json.loads(OKF_ROOTS_PATH.read_text()) if OKF_ROOTS_PATH.exists() else {}


def ingest_bundle(
    bundle_path: Path,
    bundle_id: str,
    collection,
    embed_model: SentenceTransformer,
    *,
    force: bool = False,
    resign: bool = False,
) -> BundleRecord:
    """Parse, hash, Merkle-sign, and store a bundle's concepts. Idempotent per bundle_id.

    On --force, existing Chroma rows for this bundle are replaced, but the
    SIGNED ROOT IS NEVER SILENTLY RE-SIGNED: if the recomputed root differs
    from what's already signed in okf_roots.json, that is the expected signal
    after a tamper-demo mutation, not something to launder by re-publishing.
    Re-signing requires the explicit --resign flag.
    """
    concepts = parse_bundle(bundle_path, bundle_id)
    logging.info("Parsed %d concept(s) from %s", len(concepts), bundle_path)

    existing = collection.get(where={"bundle_id": bundle_id}, include=[])
    if existing["ids"]:
        if not force:
            logging.info(
                "bundle %r already ingested (%d concepts) — use --force to replace",
                bundle_id,
                len(existing["ids"]),
            )
            return _load_roots().get(bundle_id, {}).get("bundle", {})
        collection.delete(ids=existing["ids"])  # per-bundle delete, never the whole collection

    leaf_hashes = [c["sha256"] for c in concepts]  # already concept_id-sorted
    root_hex = compute_root(leaf_hashes)  # REUSE merkle.compute_root

    roots = _load_roots()
    prior = roots.get(bundle_id, {}).get("bundle")
    if prior and not resign:
        if prior["merkle_root"] != root_hex:
            logging.warning(
                "MERKLE ROOT CHANGED for %r (signed %s… → recomputed %s…) — keeping the "
                "ORIGINAL signed record. This is the expected signal after a tamper. "
                "Pass --resign only when you intend to re-publish.",
                bundle_id,
                prior["merkle_root"][:12],
                root_hex[:12],
            )
        bundle_rec = prior
        pins = roots[bundle_id].get("computation_pins", [])
    else:
        publisher_sk = load_signing_key(PUBLISHER_SIGNING_KEY_PATH)
        bundle_rec: BundleRecord = {
            "bundle_id": bundle_id,
            "merkle_root": root_hex,
            "root_signature": sign(publisher_sk, bytes.fromhex(root_hex)),  # REUSE crypto.sign
            "publisher_key_id": PUBLISHER_KEY_ID,
            "signed_at": datetime.now(timezone.utc).isoformat(),
        }
        pins = build_pins(bundle_path, concepts, bundle_id, publisher_sk)
        roots[bundle_id] = {
            "bundle": bundle_rec,
            "bundle_path": str(bundle_path),
            "canonicalization": OKF_CANON_VERSION,
            "concept_count": len(concepts),
            "concepts": [
                {"concept_id": c["concept_id"], "sha256": c["sha256"], "merkle_index": c["merkle_index"]}
                for c in concepts
            ],
            "trust_signatures": roots.get(bundle_id, {}).get("trust_signatures", []),  # Phase 3
            "computation_pins": pins,
        }
        OKF_ROOTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        OKF_ROOTS_PATH.write_text(json.dumps(roots, indent=2))

    collection.add(
        ids=[f"{bundle_id}::{c['concept_id']}" for c in concepts],
        documents=[c["body"] for c in concepts],
        embeddings=embed_model.encode([_embed_text(c) for c in concepts], normalize_embeddings=True).tolist(),
        metadatas=[_metadata(c) for c in concepts],
    )
    logging.info(
        "Ingested %d concept(s) into %r; merkle_root=%s, computation_pins=%d",
        len(concepts),
        collection.name,
        root_hex,
        len(pins),
    )
    return bundle_rec


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest an OKF v0.2 bundle into Chroma + okf_roots.json")
    parser.add_argument("bundle_path", help="path to the bundle root, e.g. bundles/acme_retail")
    parser.add_argument("--bundle-id", help="defaults to the bundle directory name")
    parser.add_argument("--force", action="store_true", help="replace this bundle's concepts in Chroma")
    parser.add_argument(
        "--resign",
        action="store_true",
        help="re-sign the Merkle root (re-publish); WITHOUT this, an existing "
        "signed root is preserved so tampering cannot be laundered",
    )
    parser.add_argument("--dry-run", action="store_true", help="parse + hash only; no writes")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s", datefmt="%H:%M:%S")
    bundle_path = Path(args.bundle_path)
    if not bundle_path.is_dir():
        sys.exit(f"bundle path not found: {bundle_path}")
    bundle_id = args.bundle_id or bundle_path.name

    if args.dry_run:
        concepts = parse_bundle(bundle_path, bundle_id)
        for c in concepts:
            print(f"{c['merkle_index']:>2}  {c['concept_id']:<32} {c['type']:<22} {c['sha256']}")
        print(f"\nconcepts: {len(concepts)}")
        print(f"merkle_root: {compute_root([c['sha256'] for c in concepts])}")
        return

    if not PUBLISHER_SIGNING_KEY_PATH.exists():
        sys.exit("missing publisher key — run `uv run python scripts/generate_keys.py` first")
    embed_model = SentenceTransformer(EMBED_MODEL_NAME)
    collection = get_collection(OKF_COLLECTION_NAME)
    ingest_bundle(bundle_path, bundle_id, collection, embed_model, force=args.force, resign=args.resign)


if __name__ == "__main__":
    main()
