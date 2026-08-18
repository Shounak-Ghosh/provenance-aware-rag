#!/usr/bin/env python3
"""Issue per-actor trust signatures over a bundle's verified/generated entries.

The production side of src/trust.py: for every `verified`/
`generated` entry in a bundle's concepts, sign a claim binding (concept
digest, actor, timestamp, kind) under that actor's own key, and write the
result into data/okf_roots.json[bundle_id]["trust_signatures"] -- the field
src/okf_ingest.py already reserves and never overwrites.

    uv run python scripts/sign_trust.py bundles/acme_retail --mint-missing --dry-run
    uv run python scripts/sign_trust.py bundles/acme_retail --mint-missing

Requires the bundle to already be ingested (src/okf_ingest) so a signed root
exists to compare against -- see the --force note below.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import ACTOR_KEYRING_PATH, OKF_ROOTS_PATH
from src.merkle import compute_root
from src.okf import parse_bundle
from src.trust import ensure_actor_key, load_actor_signing_key, sign_trust_entry, trust_entries


def _collect_rows(bundle_path: Path, bundle_id: str, kinds: set[str]) -> tuple[list, list[dict]]:
    concepts = parse_bundle(bundle_path, bundle_id)
    rows = [
        (c, actor, at, kind)
        for c in concepts
        for actor, at, kind in trust_entries(c)
        if kind in kinds
    ]
    return concepts, rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle_path", help="path to the bundle root, e.g. bundles/acme_retail")
    parser.add_argument("--bundle-id", help="defaults to the bundle directory name")
    parser.add_argument("--mint-missing", action="store_true", help="mint a keypair for any actor not yet in the keyring")
    parser.add_argument("--kinds", default="verified,generated", help="comma-separated entry kinds to sign (default: both)")
    parser.add_argument(
        "--skip-actor",
        action="append",
        default=[],
        metavar="ACTOR",
        help="leave this actor's entries unsigned (repeatable) -- demonstrates the "
        "'unbacked' path without tampering anything",
    )
    parser.add_argument("--dry-run", action="store_true", help="print the entry table and actor summary; no writes")
    parser.add_argument(
        "--force",
        action="store_true",
        help="sign even if the recomputed root does not match the signed root in "
        "okf_roots.json (normally refused: don't issue trust signatures over an "
        "already-tampered bundle)",
    )
    args = parser.parse_args()

    bundle_path = Path(args.bundle_path)
    if not bundle_path.is_dir():
        sys.exit(f"bundle path not found: {bundle_path}")
    bundle_id = args.bundle_id or bundle_path.name
    kinds = {k.strip() for k in args.kinds.split(",") if k.strip()}

    concepts, rows = _collect_rows(bundle_path, bundle_id, kinds)

    if args.dry_run:
        for c, actor, at, kind in rows:
            skip = "  (SKIPPED)" if actor in args.skip_actor else ""
            print(f"{c['concept_id']:<34} {actor:<28} {at:<24} {kind:<10}{skip}")
        actors = sorted({actor for _, actor, _, _ in rows})
        print(f"\nentries: {len(rows)}   actors: {len(actors)}")
        for a in actors:
            print(f"  {a}")
        return

    if not OKF_ROOTS_PATH.exists():
        sys.exit(f"{OKF_ROOTS_PATH} not found -- run `uv run python -m src.okf_ingest {bundle_path}` first")
    roots = json.loads(OKF_ROOTS_PATH.read_text())
    bundle_rec = roots.get(bundle_id)
    if bundle_rec is None:
        sys.exit(f"{bundle_id!r} has no entry in {OKF_ROOTS_PATH} -- run src.okf_ingest first")

    recomputed_root = compute_root([c["sha256"] for c in concepts])
    signed_root = bundle_rec["bundle"]["merkle_root"]
    if recomputed_root != signed_root and not args.force:
        sys.exit(
            f"recomputed root {recomputed_root[:12]}… != signed root {signed_root[:12]}… "
            f"-- bundle changed since it was signed. Re-ingest/--resign first, or pass "
            f"--force to sign trust entries over the bundle as it is on disk right now."
        )

    actors = sorted({actor for _, actor, _, _ in rows if actor not in args.skip_actor})
    missing = [a for a in actors if _actor_key_missing(a)]
    if missing and not args.mint_missing:
        sys.exit("missing actor key(s) for: " + ", ".join(missing) + " -- pass --mint-missing to mint them")

    signatures = []
    for c, actor, at, kind in rows:
        if actor in args.skip_actor:
            continue
        sk = ensure_actor_key(actor) if args.mint_missing else load_actor_signing_key(actor)
        signatures.append(sign_trust_entry(bundle_id, c, actor, at, kind, sk))

    roots[bundle_id]["trust_signatures"] = signatures
    OKF_ROOTS_PATH.write_text(json.dumps(roots, indent=2))
    print(
        f"signed {len(signatures)} trust entries for {len(actors)} actor(s) in {bundle_id!r}; "
        f"keyring: {ACTOR_KEYRING_PATH}, roots: {OKF_ROOTS_PATH}"
    )
    if args.skip_actor:
        print(f"skipped (left unbacked): {', '.join(args.skip_actor)}")


def _actor_key_missing(actor: str) -> bool:
    try:
        load_actor_signing_key(actor)
        return False
    except KeyError:
        return True


if __name__ == "__main__":
    main()
