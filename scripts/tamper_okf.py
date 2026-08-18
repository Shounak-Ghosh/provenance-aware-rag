#!/usr/bin/env python3
"""Malicious-bundle generator: the four OKF attack demos, plus backup/restore.

Every attack mutates real files under a bundle directory (never a copy) and
self-checks its own before/after digest invariant before it will leave the
mutation on disk -- see TamperError. First mutation of any file snapshots it
to data/tamper_backups/<bundle_id>/; `restore` puts everything back,
including data/okf_roots.json if `forge-tier --resign` touched it.

    uv run python scripts/tamper_okf.py swap-fence bundles/acme_retail computations/revenue-ytd
    uv run python scripts/tamper_okf.py swap-attester bundles/acme_retail computations/revenue-ytd
    uv run python scripts/tamper_okf.py forge-tier bundles/acme_retail metrics/revenue human:attacker
    uv run python scripts/tamper_okf.py forge-tier bundles/acme_retail metrics/revenue human:attacker --resign
    uv run python scripts/tamper_okf.py benign-round-trip bundles/acme_retail computations/revenue-ytd
    uv run python scripts/tamper_okf.py status bundles/acme_retail
    uv run python scripts/tamper_okf.py restore bundles/acme_retail

After swap-fence / swap-attester / forge-tier (no --resign), re-check with:
    uv run python verify.py --okf-bundle bundles/acme_retail

Escape hatch that does NOT depend on this script's own bookkeeping:
    git checkout -- bundles/acme_retail data/okf_roots.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import OKF_ROOTS_PATH, PUBLISHER_SIGNING_KEY_PATH
from src.crypto import load_signing_key, sign
from src.merkle import compute_root
from src.okf import (
    _HEADING_RE,
    _NEXT_HEADING_RE,
    attester_bytes,
    canonical_computation_bytes,
    parse_bundle,
    resolve_resource,
)
from src.schema import ConceptRecord
from src.trust import index_trust_signatures

BACKUP_ROOT = Path("data/tamper_backups")


class TamperError(Exception):
    """Raised when an attack's own before/after self-check fails -- the
    mutation it just wrote does not have the effect it advertises. The
    original bytes are restored before this is raised, so a failed
    self-check never leaves a half-applied mutation on disk."""


# ── shared lookups ────────────────────────────────────────────────────────────
def _bundle_id_for(bundle_path: Path, bundle_id: str | None) -> str:
    return bundle_id or bundle_path.name


def _find_concept(bundle_path: Path, bundle_id: str, concept_id: str) -> ConceptRecord:
    concepts = parse_bundle(bundle_path, bundle_id)
    concept = next((c for c in concepts if c["concept_id"] == concept_id), None)
    if concept is None:
        raise TamperError(f"concept not found in {bundle_id!r}: {concept_id}")
    return concept


def _root_now(bundle_path: Path, bundle_id: str) -> str:
    concepts = parse_bundle(bundle_path, bundle_id)
    return compute_root([c["sha256"] for c in concepts])


def _pin_digests(bundle_path: Path, concept: ConceptRecord) -> tuple[str, str]:
    comp = canonical_computation_bytes(concept, bundle_path)
    comp_sha = hashlib.sha256(comp).hexdigest() if comp else ""
    att = attester_bytes(bundle_path, concept)
    att_sha = hashlib.sha256(att[0]).hexdigest() if att else ""
    return comp_sha, att_sha


# ── backup / restore (D4) ──────────────────────────────────────────────────────
def _backup_key(bundle_path: Path, bundle_id: str) -> str:
    """Scope the backup directory to (bundle_id, resolved bundle_path), not
    bundle_id alone -- two DIFFERENT directories that happen to share a
    bundle_id (e.g. a tmp_path test copy vs. the real bundle, both named
    'acme_retail') must never share a manifest."""
    digest = hashlib.sha256(str(Path(bundle_path).resolve()).encode()).hexdigest()[:10]
    return f"{bundle_id}-{digest}"


def _manifest_path(bundle_path: Path, bundle_id: str, backup_root: Path) -> Path:
    return backup_root / _backup_key(bundle_path, bundle_id) / "manifest.json"


def _load_manifest(bundle_path: Path, bundle_id: str, backup_root: Path) -> dict:
    p = _manifest_path(bundle_path, bundle_id, backup_root)
    if not p.exists():
        return {"files": {}, "roots_backup": None, "roots_path": None}
    return json.loads(p.read_text())


def _save_manifest(bundle_path: Path, bundle_id: str, backup_root: Path, manifest: dict) -> None:
    p = _manifest_path(bundle_path, bundle_id, backup_root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(manifest, indent=2))


def _snapshot_file(bundle_path: Path, bundle_id: str, rel_path: str, backup_root: Path) -> None:
    """Snapshot rel_path's CURRENT bytes if this is the first time this
    bundle's manifest has seen it -- so a chain of attacks against the same
    file still restores to the original pristine bytes, not the previous
    attack's output."""
    manifest = _load_manifest(bundle_path, bundle_id, backup_root)
    if rel_path in manifest["files"]:
        return
    src = bundle_path / rel_path
    backup_name = rel_path.replace("/", "__")
    backup_path = backup_root / _backup_key(bundle_path, bundle_id) / backup_name
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    data = src.read_bytes()
    backup_path.write_bytes(data)
    manifest["files"][rel_path] = {"backup": backup_name, "sha256": hashlib.sha256(data).hexdigest()}
    _save_manifest(bundle_path, bundle_id, backup_root, manifest)
    print(f"[BACKUP] {rel_path} -> {backup_path}")


def _snapshot_roots(bundle_path: Path, bundle_id: str, roots_path: Path, backup_root: Path) -> None:
    manifest = _load_manifest(bundle_path, bundle_id, backup_root)
    if manifest.get("roots_backup"):
        return
    backup_path = backup_root / _backup_key(bundle_path, bundle_id) / "okf_roots.json.bak"
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path.write_bytes(roots_path.read_bytes())
    manifest["roots_backup"] = "okf_roots.json.bak"
    manifest["roots_path"] = str(roots_path)
    _save_manifest(bundle_path, bundle_id, backup_root, manifest)
    print(f"[BACKUP] {roots_path} -> {backup_path}")


def restore(bundle_path: Path, bundle_id: str, backup_root: Path = BACKUP_ROOT) -> list[str]:
    manifest = _load_manifest(bundle_path, bundle_id, backup_root)
    restored: list[str] = []
    for rel_path, rec in manifest.get("files", {}).items():
        backup_path = backup_root / _backup_key(bundle_path, bundle_id) / rec["backup"]
        (bundle_path / rel_path).write_bytes(backup_path.read_bytes())
        restored.append(rel_path)
        print(f"[OK] restored {rel_path}")
    if manifest.get("roots_backup"):
        roots_path = Path(manifest["roots_path"])
        backup_path = backup_root / _backup_key(bundle_path, bundle_id) / manifest["roots_backup"]
        roots_path.write_bytes(backup_path.read_bytes())
        restored.append(str(roots_path))
        print(f"[OK] restored {roots_path}")
    manifest_dir = _manifest_path(bundle_path, bundle_id, backup_root).parent
    if manifest_dir.exists():
        shutil.rmtree(manifest_dir)
    if not restored:
        print(f"[SKIP] no tamper backups recorded for {bundle_id!r} -- nothing to restore")
    return restored


def status(bundle_path: Path, bundle_id: str, backup_root: Path = BACKUP_ROOT) -> dict:
    manifest = _load_manifest(bundle_path, bundle_id, backup_root)
    rows = []
    for rel_path, rec in manifest.get("files", {}).items():
        current = (bundle_path / rel_path).read_bytes()
        current_sha = hashlib.sha256(current).hexdigest()
        rows.append(
            {
                "rel_path": rel_path,
                "pristine_sha256": rec["sha256"],
                "current_sha256": current_sha,
                "tampered": current_sha != rec["sha256"],
            }
        )
    roots_tampered = None
    if manifest.get("roots_backup"):
        roots_path = Path(manifest["roots_path"])
        backup_path = backup_root / _backup_key(bundle_path, bundle_id) / manifest["roots_backup"]
        roots_tampered = roots_path.read_bytes() != backup_path.read_bytes()
    return {
        "bundle_id": bundle_id,
        "files": rows,
        "roots_backed_up": bool(manifest.get("roots_backup")),
        "roots_tampered": roots_tampered,
    }


def _print_status(report: dict) -> None:
    if not report["files"] and not report["roots_backed_up"]:
        print(f"[OK] {report['bundle_id']!r}: no tamper backups recorded -- bundle is presumed pristine")
        return
    print(f"=== tamper status: {report['bundle_id']} ===")
    for row in report["files"]:
        mark = "TAMPERED" if row["tampered"] else "unchanged"
        print(f"  {row['rel_path']:<40} {mark:<9} pristine={row['pristine_sha256'][:12]}... current={row['current_sha256'][:12]}...")
    if report["roots_backed_up"]:
        mark = "TAMPERED" if report["roots_tampered"] else "unchanged"
        print(f"  {'data/okf_roots.json':<40} {mark}")
    print("\nrestore with: uv run python scripts/tamper_okf.py restore " + report["bundle_id"])


# ── attack 1: swap-fence ────────────────────────────────────────────────────────
DEFAULT_MALICIOUS_SQL = """SELECT
  SUM(
    CASE
      WHEN o.currency = 'USD' THEN o.net_amount
      ELSE o.net_amount * fx.rate_to_usd
    END
  ) * 1.5 AS revenue_usd
FROM `acme.sales.orders` AS o
LEFT JOIN `acme.finance.fx_daily_rates` AS fx
  ON fx.currency = o.currency
  AND fx.rate_date = DATE(o.order_ts)
WHERE o.order_status = 'delivered'
  AND DATE_DIFF(CURRENT_DATE(), DATE(o.order_ts), DAY) >= 30
  AND EXTRACT(YEAR FROM o.order_ts) = @year"""


def _fence_span(body: str) -> tuple[int, int, str, str, str]:
    """Locate the ```lang fence inside a concept's `# Computation` section.

    Returns (abs_start, abs_end, indent, marker, lang) for the FULL fenced
    block (opening marker through closing marker) so callers can splice a
    replacement in without disturbing anything else in the file. Mirrors
    okf._computation_section / okf.extract_computation's own fence-finding,
    but on absolute offsets into `body` rather than a copied substring.
    """
    heading = _HEADING_RE.search(body)
    if heading is None:
        raise TamperError("concept has no `# Computation` heading")
    rest = body[heading.end():]
    nxt = _NEXT_HEADING_RE.search(rest)
    section_end = heading.end() + (nxt.start() if nxt else len(rest))
    section = body[heading.end():section_end]

    from src.okf import _FENCE_RE

    fence = _FENCE_RE.search(section)
    if fence is None:
        raise TamperError("no fenced (```/~~~) computation block -- swap_fence only supports the fenced form")
    return heading.end() + fence.start(), heading.end() + fence.end(), fence.group(1), fence.group(2), fence.group(3)


def swap_fence(
    bundle_path: Path, bundle_id: str, concept_id: str, malicious_sql: str = DEFAULT_MALICIOUS_SQL,
    *, backup_root: Path = BACKUP_ROOT,
) -> dict:
    """Rewrite the `# Computation` fence in place -- the headline attack.

    Detected by okf_verify.check_pins ("computation tampered (pin
    mismatch)"); passes native_attest_run (SPEC S10.5), because the bundle's
    own attester re-derives from this SAME swapped fence.
    """
    concept = _find_concept(bundle_path, bundle_id, concept_id)
    sha_before = concept["sha256"]
    comp_before, att_before = _pin_digests(bundle_path, concept)
    file_path = bundle_path / concept["rel_path"]
    raw_before = file_path.read_bytes()
    text_before = raw_before.decode("utf-8")

    fm_block, body = _split_raw(text_before)
    start, end, indent, marker, lang = _fence_span(body)
    new_lines = [indent + ln if ln else ln for ln in malicious_sql.rstrip("\n").split("\n")]
    new_fence = f"{indent}{marker}{lang}\n" + "\n".join(new_lines) + f"\n{indent}{marker}"
    new_body = body[:start] + new_fence + body[end:]
    new_text = fm_block + "\n" + new_body

    _snapshot_file(bundle_path, bundle_id, concept["rel_path"], backup_root)
    file_path.write_text(new_text, encoding="utf-8")

    concept_after = _find_concept(bundle_path, bundle_id, concept_id)
    sha_after = concept_after["sha256"]
    comp_after, att_after = _pin_digests(bundle_path, concept_after)
    if sha_after == sha_before or comp_after == comp_before:
        file_path.write_bytes(raw_before)
        raise TamperError(
            f"swap_fence self-check failed for {concept_id}: expected concept digest AND "
            f"computation pin digest to change; got sha256 {'unchanged' if sha_after == sha_before else 'changed'}, "
            f"pin {'unchanged' if comp_after == comp_before else 'changed'}. File restored, nothing written."
        )
    result = {
        "attack": "swap-fence",
        "concept_id": concept_id,
        "files": [concept["rel_path"]],
        "bundle_path": str(bundle_path),
        "raw_before": hashlib.sha256(raw_before).hexdigest(), "raw_after": hashlib.sha256(file_path.read_bytes()).hexdigest(),
        "sha256_before": sha_before, "sha256_after": sha_after,
        "computation_pin_before": comp_before, "computation_pin_after": comp_after,
        "attester_pin_before": att_before, "attester_pin_after": att_after,
        "expected_detections": ["okf_verify.check_pins: computation tampered (pin mismatch)"],
    }
    _print_table(result)
    return result


def _split_raw(text: str) -> tuple[str, str]:
    """Return (frontmatter_block_incl_fences, body), byte-faithful.

    Same fence-detection rule as okf._split_frontmatter (a line that is
    exactly '---' or '...' closes the frontmatter) but returns the RAW
    frontmatter block text instead of a parsed dict, so a caller can
    reassemble the file without running anything through YAML. Assumes LF
    line endings, matching every file in this bundle.
    """
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        raise TamperError("file has no leading frontmatter fence")
    for i in range(1, len(lines)):
        if lines[i].strip() in ("---", "..."):
            return "\n".join(lines[: i + 1]), "\n".join(lines[i + 1:])
    raise TamperError("unterminated frontmatter fence")


# ── attack 2: swap-attester ─────────────────────────────────────────────────────
ALWAYS_OK_ATTESTER = '''"""[TAMPERED by scripts/tamper_okf.py swap-attester] Always-pass attester.

Ignores every argument; returns ok=True unconditionally. attesters/*.py is
NOT a `.md` concept file, so it is never a Merkle leaf -- this edit changes
NO concept digest and NO bundle root. Only okf_verify.check_pins's
attester_sha256 pin can catch it; native SPEC S10.5 attestation is blind to
it, because it re-imports and trusts whatever code is on disk right now.
"""


def attest(*, sanctioned_sql, receipt, claimed_value, **kwargs):
    return {"ok": True, "reason": None, "details": {"tampered": True, "note": "always-pass attester"}}
'''


def swap_attester(bundle_path: Path, bundle_id: str, concept_id: str, *, backup_root: Path = BACKUP_ROOT) -> dict:
    concept = _find_concept(bundle_path, bundle_id, concept_id)
    attester = concept["frontmatter"].get("attester")
    ref = attester.get("resource") if isinstance(attester, dict) else None
    if not ref:
        raise TamperError(f"{concept_id} declares no attester.resource")
    file_path = resolve_resource(bundle_path, ref)
    if file_path is None or not file_path.exists():
        raise TamperError(f"attester resource {ref!r} not found for {concept_id}")
    rel_path = str(file_path.relative_to(bundle_path.resolve()))  # resolve_resource always returns an absolute path

    sha_before = concept["sha256"]
    root_before = _root_now(bundle_path, bundle_id)
    comp_before, att_before = _pin_digests(bundle_path, concept)
    raw_before = file_path.read_bytes()

    _snapshot_file(bundle_path, bundle_id, rel_path, backup_root)
    file_path.write_text(ALWAYS_OK_ATTESTER, encoding="utf-8")

    concept_after = _find_concept(bundle_path, bundle_id, concept_id)
    sha_after = concept_after["sha256"]
    root_after = _root_now(bundle_path, bundle_id)
    comp_after, att_after = _pin_digests(bundle_path, concept_after)
    if sha_after != sha_before or root_after != root_before or att_after == att_before:
        file_path.write_bytes(raw_before)
        raise TamperError(
            f"swap_attester self-check failed for {concept_id}: expected concept digest AND bundle "
            f"root UNCHANGED (attester is not a Merkle leaf) and attester pin digest CHANGED; got "
            f"sha256 {'changed' if sha_after != sha_before else 'unchanged'}, root "
            f"{'changed' if root_after != root_before else 'unchanged'}, attester pin "
            f"{'unchanged' if att_after == att_before else 'changed'}. File restored, nothing written."
        )
    result = {
        "attack": "swap-attester",
        "concept_id": concept_id,
        "files": [rel_path],
        "bundle_path": str(bundle_path),
        "sha256_before": sha_before, "sha256_after": sha_after,
        "root_before": root_before, "root_after": root_after,
        "computation_pin_before": comp_before, "computation_pin_after": comp_after,
        "attester_pin_before": att_before, "attester_pin_after": att_after,
        "expected_detections": [
            "okf_verify.check_pins: attester tampered (pin mismatch)",
            "every OTHER integrity check (root, root signature, concept digest) stays GREEN",
        ],
    }
    _print_table(result)
    return result


# ── attack 3: forge-tier ─────────────────────────────────────────────────────────
def forge_tier(
    bundle_path: Path,
    bundle_id: str,
    concept_id: str,
    actor: str,
    *,
    resign: bool = False,
    roots_path: Path = OKF_ROOTS_PATH,
    publisher_sk=None,
    backup_root: Path = BACKUP_ROOT,
) -> dict:
    """Append an unsigned `verified:` entry claiming `actor` reviewed this
    concept. Without --resign: caught immediately by check_concept_tamper
    (the frontmatter edit moves the canonical hash away from the signed
    one). With --resign: the root is recomputed and RE-SIGNED with the
    publisher key -- root/signature/hash all verify, and only
    trust.derive_authenticated_tier's per-actor signature check (nothing
    upstream) catches the forgery, because `actor` never signed anything.

    `publisher_sk` defaults to loading data/keys/publisher.sk (the CLI path);
    pass a throwaway key to re-sign against a tests/conftest.py::signed_fixture
    copy without ever touching the live key or data/okf_roots.json.
    """
    concept = _find_concept(bundle_path, bundle_id, concept_id)
    sha_before = concept["sha256"]
    root_before = _root_now(bundle_path, bundle_id)
    file_path = bundle_path / concept["rel_path"]
    raw_before = file_path.read_bytes()
    text_before = raw_before.decode("utf-8")

    fm_block, body = _split_raw(text_before)
    fm = yaml.safe_load("\n".join(fm_block.split("\n")[1:-1])) or {}
    at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entry = {"by": actor, "at": at}
    existing = fm.get("verified")
    if existing is None:
        fm["verified"] = [entry]
    elif isinstance(existing, list):
        fm["verified"] = existing + [entry]
    else:
        fm["verified"] = [existing, entry]

    new_fm_text = yaml.safe_dump(fm, sort_keys=False, default_flow_style=False, allow_unicode=True)
    new_text = f"---\n{new_fm_text}---\n{body}"

    _snapshot_file(bundle_path, bundle_id, concept["rel_path"], backup_root)
    if resign:
        _snapshot_roots(bundle_path, bundle_id, roots_path, backup_root)
    file_path.write_text(new_text, encoding="utf-8")

    concept_after = _find_concept(bundle_path, bundle_id, concept_id)
    sha_after = concept_after["sha256"]
    root_after = _root_now(bundle_path, bundle_id)

    roots = json.loads(roots_path.read_text()) if roots_path.exists() else {}
    sig_index = index_trust_signatures(roots.get(bundle_id, {}).get("trust_signatures", []))
    forged_key = (concept_id, actor, at, "verified")
    if sha_after == sha_before or forged_key in sig_index:
        file_path.write_bytes(raw_before)
        raise TamperError(
            f"forge_tier self-check failed for {concept_id}: expected concept digest to change and "
            f"the forged entry to have NO matching trust signature; got sha256 "
            f"{'unchanged' if sha_after == sha_before else 'changed'}, forged key "
            f"{'present' if forged_key in sig_index else 'absent'} in trust_signatures. "
            f"File restored, nothing written."
        )

    result = {
        "attack": "forge-tier", "concept_id": concept_id, "files": [concept["rel_path"]],
        "bundle_path": str(bundle_path),
        "actor": actor, "at": at, "resigned": resign,
        "sha256_before": sha_before, "sha256_after": sha_after,
        "root_before": root_before, "root_after": root_after,
        "expected_detections": [
            "okf_verify.check_concept_tamper: concept canonical-hash mismatch"
            if not resign
            else "trust.derive_authenticated_tier: downgraded (unbacked: " + actor + ")",
        ],
    }

    if resign:
        print(
            "=" * 70
            + "\nRE-SIGNING with the publisher key: models an adversary who is ALSO the\n"
            "re-publisher. Restore with `tamper_okf.py restore " + bundle_id + "`.\n" + "=" * 70
        )
        concepts = parse_bundle(bundle_path, bundle_id)
        root_hex = compute_root([c["sha256"] for c in concepts])
        sk = publisher_sk or load_signing_key(PUBLISHER_SIGNING_KEY_PATH)
        bundle_rec = {
            "bundle_id": bundle_id,
            "merkle_root": root_hex,
            "root_signature": sign(sk, bytes.fromhex(root_hex)),
            "publisher_key_id": roots.get(bundle_id, {}).get("bundle", {}).get("publisher_key_id", "publisher_v1"),
            "signed_at": datetime.now(timezone.utc).isoformat(),
        }
        from src.okf_ingest import build_pins  # lazy: pulls sentence_transformers at module scope

        pins = build_pins(bundle_path, concepts, bundle_id, sk)
        prior = roots.get(bundle_id, {})
        roots[bundle_id] = {
            "bundle": bundle_rec,
            "bundle_path": prior.get("bundle_path", str(bundle_path)),
            "canonicalization": prior.get("canonicalization", "okf-concept/v1"),
            "concept_count": len(concepts),
            "concepts": [{"concept_id": c["concept_id"], "sha256": c["sha256"], "merkle_index": c["merkle_index"]} for c in concepts],
            "trust_signatures": prior.get("trust_signatures", []),  # unchanged: the forged entry stays unsigned
            "computation_pins": pins,
        }
        roots_path.write_text(json.dumps(roots, indent=2))
        result["merkle_root"] = root_hex
        print(f"[OK] re-signed {bundle_id!r}: root={root_hex[:12]}..., pins rebuilt ({len(pins)})")

    _print_table(result)
    return result


# ── attack 4: benign-round-trip ──────────────────────────────────────────────────
def benign_round_trip(bundle_path: Path, bundle_id: str, concept_id: str, *, backup_root: Path = BACKUP_ROOT) -> dict:
    """Reorder frontmatter keys, flip list-item flow style, re-spell a YAML
    date/timestamp, inject CRLF + trailing whitespace + extra blank lines in
    the body. Every transformation is one the canonicalizer's own docstrings
    (okf.canonical_frontmatter_json / _normalize_yaml_value / canonical_body)
    claim survives -- so this is a check on the canonicalizer's promises, not
    a hand-picked demo. The whole point: canonical digest, Merkle root, AND
    computation pin are all UNCHANGED, while the raw file bytes are not --
    exactly what a whole-bundle raw-byte signer (signed-okf) cannot survive.
    """
    concept = _find_concept(bundle_path, bundle_id, concept_id)
    sha_before = concept["sha256"]
    root_before = _root_now(bundle_path, bundle_id)
    comp_before, att_before = _pin_digests(bundle_path, concept)
    file_path = bundle_path / concept["rel_path"]
    raw_before = file_path.read_bytes()
    text_before = raw_before.decode("utf-8")

    fm_block, body = _split_raw(text_before)
    fm = yaml.safe_load("\n".join(fm_block.split("\n")[1:-1])) or {}

    # 1. frontmatter key reorder — canonical_frontmatter_json sorts keys
    reordered = dict(reversed(list(fm.items())))
    # 4. flow -> block style for `generated`/`verified` entries, AND (as a side
    # effect of the round-trip through yaml.safe_load/safe_dump) PyYAML
    # re-spells `verified[].at`/`generated.at` -- parsed as a real datetime
    # since YAML auto-resolves ISO timestamps -- with its OWN spelling
    # ("2026-07-01 09:00:00+00:00" instead of "2026-07-01T09:00:00Z").
    # _normalize_yaml_value collapses both spellings back to one ISO-Z form
    # at hash time (okf.py:163-165), so this is a real canonicalization win,
    # not an accident of this script.
    new_fm_text = yaml.safe_dump(reordered, sort_keys=False, default_flow_style=False, allow_unicode=True)
    # 2/3. re-spell `stale_after` as an explicitly single-quoted YAML string.
    # yaml.safe_load already turned it into a datetime.date, so safe_dump
    # re-emits it unquoted ("stale_after: 2026-12-31") -- quote it back with a
    # targeted substitution so the on-disk form differs while the VALUE does
    # not; okf._normalize_yaml_value claims 2026-12-31, '2026-12-31', and
    # "2026-12-31" all hash identically (okf.py:142-143), which is the exact
    # property under test here.
    if "stale_after" in reordered:
        plain = str(reordered["stale_after"])
        new_fm_text = re.sub(
            rf"^stale_after:\s*{re.escape(plain)}\s*$",
            f"stale_after: '{plain}'",
            new_fm_text,
            count=1,
            flags=re.M,
        )

    # 5. body: CRLF line endings, trailing whitespace per line, extra leading
    # and trailing blank lines -- all stripped by okf.canonical_body.
    noisy_lines = [ln + "   " if ln.strip() else ln for ln in body.split("\n")]
    new_body = "\r\n".join(["", *noisy_lines, "", ""])

    new_text = f"---\n{new_fm_text}---\n{new_body}"

    _snapshot_file(bundle_path, bundle_id, concept["rel_path"], backup_root)
    file_path.write_text(new_text, encoding="utf-8")

    concept_after = _find_concept(bundle_path, bundle_id, concept_id)
    sha_after = concept_after["sha256"]
    root_after = _root_now(bundle_path, bundle_id)
    comp_after, att_after = _pin_digests(bundle_path, concept_after)
    raw_after = file_path.read_bytes()

    if (
        sha_after != sha_before
        or root_after != root_before
        or comp_after != comp_before
        or att_after != att_before
        or raw_after == raw_before
    ):
        file_path.write_bytes(raw_before)
        raise TamperError(
            f"benign_round_trip self-check failed for {concept_id}: expected canonical digest, "
            f"root, and pin digests UNCHANGED with raw bytes CHANGED; got sha256 "
            f"{'changed' if sha_after != sha_before else 'unchanged'}, root "
            f"{'changed' if root_after != root_before else 'unchanged'}, pins "
            f"{'changed' if (comp_after, att_after) != (comp_before, att_before) else 'unchanged'}, "
            f"raw bytes {'unchanged' if raw_after == raw_before else 'changed'}. File restored, nothing written."
        )

    result = {
        "attack": "benign-round-trip", "concept_id": concept_id, "files": [concept["rel_path"]],
        "bundle_path": str(bundle_path),
        "raw_before": hashlib.sha256(raw_before).hexdigest(), "raw_after": hashlib.sha256(raw_after).hexdigest(),
        "sha256_before": sha_before, "sha256_after": sha_after,
        "root_before": root_before, "root_after": root_after,
        "computation_pin_before": comp_before, "computation_pin_after": comp_after,
        "expected_detections": ["none -- this is the canonicalization win: verify.py --okf-bundle stays GREEN"],
    }
    _print_table(result)
    return result


# ── printing ──────────────────────────────────────────────────────────────────
def _row(label: str, before: str, after: str, want_change: bool) -> str:
    changed = before != after
    ok = changed == want_change
    verdict = "CHANGED" if changed else "UNCHANGED"
    mark = "" if ok else "  <-- unexpected"
    b = before[:12] + "..." if len(before) > 12 else before
    a = after[:12] + "..." if len(after) > 12 else after
    return f"  {label:<20} {b:<16} -> {a:<16} {verdict}{mark}"


def _print_table(result: dict) -> None:
    print(f"[{result['attack']}] {result['concept_id']}")
    if "raw_before" in result:
        print(_row("raw file bytes", result["raw_before"], result["raw_after"], True))
    print(_row("canonical digest", result["sha256_before"], result["sha256_after"], result["attack"] not in ("swap-attester", "benign-round-trip")))
    if "root_before" in result:
        # forge-tier always moves the recomputed root (the concept's content
        # changed); the difference --resign makes is whether the SIGNED root
        # in okf_roots.json is then republished to match it -- not visible in
        # this before/after-on-disk comparison, so forge-tier always wants a change here.
        print(_row("bundle merkle root", result["root_before"], result["root_after"], result["attack"] in ("forge-tier",)))
    if "computation_pin_before" in result:
        print(_row("computation pin", result["computation_pin_before"], result["computation_pin_after"], result["attack"] == "swap-fence"))
    if "attester_pin_before" in result:
        print(_row("attester pin", result["attester_pin_before"], result["attester_pin_after"], result["attack"] == "swap-attester"))
    print("  expected detection:")
    for d in result["expected_detections"]:
        print(f"    - {d}")
    print(f"  next: uv run python verify.py --okf-bundle {result.get('bundle_path', '<bundle>')}".rstrip())


# ── CLI ──────────────────────────────────────────────────────────────────────
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "attack",
        choices=["swap-fence", "swap-attester", "forge-tier", "benign-round-trip", "status", "restore"],
    )
    parser.add_argument("bundle_path", help="path to the bundle root, e.g. bundles/acme_retail")
    parser.add_argument("concept_id", nargs="?", help="concept id, e.g. computations/revenue-ytd")
    parser.add_argument("actor", nargs="?", help="forge-tier only: the forged actor, e.g. human:attacker")
    parser.add_argument("--bundle-id", help="defaults to the bundle directory name")
    parser.add_argument("--sql", help="swap-fence only: malicious SQL (default: revenue * 1.5)")
    parser.add_argument("--resign", action="store_true", help="forge-tier only: recompute + re-sign the root and pins")
    parser.add_argument("--roots", default=str(OKF_ROOTS_PATH), help=f"path to okf_roots.json (default {OKF_ROOTS_PATH})")
    args = parser.parse_args()

    bundle_path = Path(args.bundle_path)
    if not bundle_path.is_dir():
        sys.exit(f"bundle path not found: {bundle_path}")
    bundle_id = _bundle_id_for(bundle_path, args.bundle_id)
    roots_path = Path(args.roots)

    try:
        if args.attack == "status":
            _print_status(status(bundle_path, bundle_id))
            return 0
        if args.attack == "restore":
            restored = restore(bundle_path, bundle_id)
            if restored:
                print(f"[OK] {len(restored)} file(s) restored for {bundle_id!r}")
            return 0

        if args.concept_id is None:
            sys.exit(f"{args.attack} requires a concept_id")

        if args.attack == "swap-fence":
            result = swap_fence(bundle_path, bundle_id, args.concept_id, args.sql or DEFAULT_MALICIOUS_SQL)
        elif args.attack == "swap-attester":
            result = swap_attester(bundle_path, bundle_id, args.concept_id)
        elif args.attack == "forge-tier":
            if args.actor is None:
                sys.exit("forge-tier requires an actor, e.g. human:attacker")
            result = forge_tier(bundle_path, bundle_id, args.concept_id, args.actor, resign=args.resign, roots_path=roots_path)
        elif args.attack == "benign-round-trip":
            result = benign_round_trip(bundle_path, bundle_id, args.concept_id)
        else:
            sys.exit(f"unknown attack: {args.attack}")
    except TamperError as e:
        sys.exit(f"[REFUSED] {e}")

    result["bundle_path"] = str(bundle_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
