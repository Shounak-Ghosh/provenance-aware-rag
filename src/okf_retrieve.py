"""Retrieve OKF concepts from the store, carrying the material the gate needs.

Structural twin of src/retrieve.py: embed the query, ask the collection for the
top-n, then do ONE batched collection.get() per unique parent (there: per
doc_id; here: per bundle_id) to recover the sibling leaf hashes a Merkle proof
needs. Separate module rather than a branch inside retrieve.py, which is
hardwired to ROOTS_PATH, merkle.attach_provenance, and the arXiv metadata field
names -- the arXiv path stays untouched.

WHY THIS MODULE REBUILDS CONCEPTS FROM THE STORE, NOT FROM DISK
---------------------------------------------------------------
There are two copies of every concept, and until the admission gate existed
only one of them was ever verified:

    copy    lives in                       is what                      verified by
    -----   ----------------------------   --------------------------   ------------------------
    disk    bundles/<id>/**.md             what src.okf_attest EXECUTES  src.okf_verify.verify_bundle
    store   the `okf_concepts` collection  what the agent puts in the    (nothing, before src/enforce.py)
                                            LLM's CONTEXT

src.okf_verify.verify_bundle re-parses the directory (src.okf.parse_bundle);
the retrieval path serves Chroma rows. An attacker who edits the store -- the
OKF analog of src.store.corrupt_chunk -- changes what the model reads while
every at-rest check stays green. So _concept_from_row() rebuilds the
ConceptRecord from the STORED bytes and never touches the file, and
src.enforce.admit_concept hashes that. src.okf_attest keeps verifying the disk
copy, because that is the copy it executes. A divergence between the two means
one of them is refused.

This works with no new hashing logic because src.okf_ingest._metadata stores
`frontmatter_json` verbatim and the body as the Chroma document, and
src.okf_verify.check_concept_tamper already hashes exactly
okf.canonicalize_from_parts(frontmatter_json, body).
"""
from __future__ import annotations

import json
from pathlib import Path

from src.schema import ConceptRecord
from src.trust import index_trust_signatures


def _concept_from_row(metadata: dict, document: str) -> ConceptRecord:
    """Rebuild a ConceptRecord from one stored row -- the seam of this module.

    `frontmatter_json` is the exact canonical JSON that fed the concept's
    signed digest (src.okf_ingest._metadata), so json.loads of it reproduces
    the normalized frontmatter without re-running YAML. The flattened metadata
    fields (`status`, `stale_after`, `verified_by`, ...) are NOT read here:
    they exist only for cheap `where=` filtering and an attacker can move them
    independently of the frontmatter they duplicate. Everything the gate
    decides on must come from `frontmatter_json` + the document body, because
    those two are what the digest covers.
    """
    fm_json = metadata["frontmatter_json"]
    return {
        "concept_id": metadata["concept_id"],
        "bundle_id": metadata["bundle_id"],
        "rel_path": metadata.get("rel_path", f"{metadata['concept_id']}.md"),
        "type": metadata.get("type", ""),
        "title": metadata.get("title", ""),
        "frontmatter": json.loads(fm_json),
        "frontmatter_json": fm_json,
        "body": document,
        "sha256": metadata["sha256"],          # AS STORED -- attacker-mutable, never trusted as
                                                # expected_sha256; see check_concept_tamper's docstring
        "merkle_index": int(metadata["merkle_index"]),
    }


def bundle_rows(collection, bundle_id: str) -> list[tuple[dict, str]]:
    """Every stored (metadata, document) pair for one bundle, merkle_index-ordered.

    One collection.get() per bundle -- batch, not per concept, exactly as
    src/retrieve.py batches per doc_id. Ordering by merkle_index (not by
    concept_id) is what makes the returned sha256 list usable as a Merkle leaf
    list: src.okf_ingest assigned those indices from a concept_id sort, and
    re-deriving the order from the stored index rather than re-sorting keeps a
    hostile row from smuggling itself into a different tree position than the
    one its proof is checked at.
    """
    result = collection.get(where={"bundle_id": bundle_id}, include=["metadatas", "documents"])
    pairs = list(zip(result["metadatas"], result["documents"]))
    pairs.sort(key=lambda p: int(p[0]["merkle_index"]))
    return pairs


def bundle_view(collection, bundle_id: str) -> tuple[list[ConceptRecord], list[str]]:
    """(every concept of a bundle as stored, leaf hashes in merkle_index order).

    The leaf list comes from the STORED sha256 values, mirroring
    src/retrieve.py's doc_leaf_hashes. Those values are attacker-mutable, which
    is the point: a mutated sibling makes the reconstructed root differ from the
    publisher-signed one, so check_concept_tamper reports "merkle proof failed"
    for the whole bundle rather than silently proving membership in a tree
    nobody signed.
    """
    rows = bundle_rows(collection, bundle_id)
    concepts = [_concept_from_row(m, d) for m, d in rows]
    return concepts, [m["sha256"] for m, _ in rows]


def retrieve_okf(
    query: str,
    collection,
    embed_model,
    roots: dict,
    n_results: int = 5,
    bundle_id: str | None = None,
) -> dict:
    """Embed the query, return the top-n concepts plus per-bundle proof material.

    Returns everything src.enforce needs and nothing it has to go back to the
    store for:

        {"hits": [ConceptRecord, ...],                       # ranked, best first
         "distances": {concept_id: float},
         "bundles": {bundle_id: {"leaf_hashes", "bundle_rec", "signed_sha256",
                                 "sig_index", "pins_index", "by_id",
                                 "bundle_path"}}}

    `signed_sha256` (concept_id -> digest from okf_roots.json) is the ONLY
    acceptable source of expected_sha256: it is covered by the publisher's root
    signature, whereas the store's own `sha256` metadata is not.
    """
    where = {"bundle_id": bundle_id} if bundle_id else None
    query_embedding = embed_model.encode([query], normalize_embeddings=True)[0].tolist()
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=n_results,
        where=where,
        include=["documents", "metadatas", "distances"],
    )

    hits = [
        _concept_from_row(results["metadatas"][0][i], results["documents"][0][i])
        for i in range(len(results["ids"][0]))
    ]
    distances = {
        results["metadatas"][0][i]["concept_id"]: results["distances"][0][i]
        for i in range(len(results["ids"][0]))
    }

    bundles: dict[str, dict] = {}
    for bid in {c["bundle_id"] for c in hits}:
        concepts, leaf_hashes = bundle_view(collection, bid)
        entry = roots.get(bid, {})
        bundles[bid] = {
            "leaf_hashes": leaf_hashes,
            "bundle_rec": entry.get("bundle", {}),
            "signed_sha256": {c["concept_id"]: c["sha256"] for c in entry.get("concepts", [])},
            "sig_index": index_trust_signatures(entry.get("trust_signatures", [])),
            "pins_index": {p["concept_id"]: p for p in entry.get("computation_pins", [])},
            "by_id": {c["concept_id"]: c for c in concepts},
            "bundle_path": Path(entry["bundle_path"]) if entry.get("bundle_path") else None,
        }

    return {"hits": hits, "distances": distances, "bundles": bundles}


def load_okf_roots(path: Path) -> dict:
    return json.loads(path.read_text()) if path.exists() else {}
