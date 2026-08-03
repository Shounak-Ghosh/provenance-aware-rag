"""Tests for src/okf.py -- the canonicalization contract everything else binds to.

Canonicalization is the flagged rabbit-hole risk of this project: its whole
value proposition is a round-trip property (agent-benign edits don't break
signatures; value edits do), so it is pinned down here first rather than
deferred to a later phase.

Run against the real vendored bundles/acme_retail (see bundles/UPSTREAM.json)
rather than synthetic fixtures, so a passing suite means the contract holds
against real OKF v0.2 concepts, not an idealized shape.
"""
import copy
import datetime
import hashlib
from pathlib import Path

import pytest
import yaml

from src.okf import (
    _split_frontmatter,
    canonical_body,
    canonical_computation_bytes,
    canonical_frontmatter_json,
    canonicalize_concept,
    canonicalize_from_parts,
    extract_computation,
    parse_bundle,
    resolve_resource,
)

BUNDLE_PATH = Path(__file__).parent.parent / "bundles" / "acme_retail"
REVENUE_CONCEPT = BUNDLE_PATH / "computations" / "revenue-ytd.md"

EXPECTED_MERKLE_ROOT = "3353892637c89866c45b6c412100593fd8879976af5eece6ed11b9fed88f6252"


@pytest.fixture
def revenue_fm_body():
    fm, body = _split_frontmatter(REVENUE_CONCEPT.read_text())
    return fm, body


def test_parse_bundle_concept_count():
    concepts = parse_bundle(BUNDLE_PATH, "acme_retail")
    assert len(concepts) == 9
    ids = {c["concept_id"] for c in concepts}
    # reserved files (index.md, log.md) must never appear as concepts
    assert not any(i.endswith("index") or i.endswith("log") for i in ids if "/" not in i)
    assert "index" not in ids and "log" not in ids


def test_parse_bundle_merkle_root_pinned():
    """Regression pin against the vendored commit (bundles/UPSTREAM.json).
    A change here means either the canonicalization contract moved or the
    vendored bundle content changed -- both are worth noticing explicitly."""
    from src.merkle import compute_root

    concepts = parse_bundle(BUNDLE_PATH, "acme_retail")
    root = compute_root([c["sha256"] for c in concepts])
    assert root == EXPECTED_MERKLE_ROOT


def test_leaf_order_is_concept_id_not_path():
    """The landmine: path-sort and concept_id-sort disagree on this exact
    bundle ('-' 0x2D < '.' 0x2E), so the wrong sort key silently produces a
    different Merkle root than every downstream verifier expects."""
    concepts = parse_bundle(BUNDLE_PATH, "acme_retail")
    ids = [c["concept_id"] for c in concepts]
    assert ids.index("metrics/gross-margin") < ids.index("metrics/gross-margin-legacy")
    # every merkle_index must equal its position in the sorted list
    assert [c["merkle_index"] for c in concepts] == list(range(len(concepts)))


def test_canonicalize_survives_key_reorder_and_crlf(revenue_fm_body):
    fm, body = revenue_fm_body
    base = hashlib.sha256(canonicalize_concept(fm, body)).hexdigest()

    reordered = dict(reversed(list(fm.items())))
    rt_text = (
        "---\n"
        + yaml.safe_dump(reordered, sort_keys=False, allow_unicode=True)
        + "---\n\n"
        + "\n".join(line + "   " for line in body.split("\n"))  # trailing whitespace
        + "\n\n\n"  # extra trailing blank lines
    ).replace("\n", "\r\n")  # CRLF

    fm2, body2 = _split_frontmatter(rt_text)
    assert hashlib.sha256(canonicalize_concept(fm2, body2)).hexdigest() == base


def test_canonicalize_survives_quoted_date_string(revenue_fm_body):
    fm, body = revenue_fm_body
    base = hashlib.sha256(canonicalize_concept(fm, body)).hexdigest()

    fm_quoted = copy.deepcopy(fm)
    fm_quoted["stale_after"] = "2026-12-31"  # string, as if the source had quoted it
    assert hashlib.sha256(canonicalize_concept(fm_quoted, body)).hexdigest() == base


def test_canonicalize_survives_z_vs_offset_datetime(revenue_fm_body):
    fm, body = revenue_fm_body
    base = hashlib.sha256(canonicalize_concept(fm, body)).hexdigest()

    fm_tz = copy.deepcopy(fm)
    fm_tz["generated"]["at"] = datetime.datetime(2026, 6, 30, 14, 0, 0, tzinfo=datetime.timezone.utc)
    assert hashlib.sha256(canonicalize_concept(fm_tz, body)).hexdigest() == base

    text = REVENUE_CONCEPT.read_text()
    fm2, body2 = _split_frontmatter(text.replace("at: 2026-06-30T14:00:00Z", "at: 2026-06-30T14:00:00+00:00"))
    assert hashlib.sha256(canonicalize_concept(fm2, body2)).hexdigest() == base


def test_canonicalize_detects_value_change(revenue_fm_body):
    fm, body = revenue_fm_body
    base = hashlib.sha256(canonicalize_concept(fm, body)).hexdigest()

    fm_changed = copy.deepcopy(fm)
    fm_changed["status"] = "deprecated"
    assert hashlib.sha256(canonicalize_concept(fm_changed, body)).hexdigest() != base


def test_canonicalize_preserves_sql_indentation(revenue_fm_body):
    fm, body = revenue_fm_body
    canonical = canonicalize_concept(fm, body).decode()
    assert "    CASE" in canonical  # the fenced SQL's indentation must survive verbatim


def test_canonicalize_idempotent(revenue_fm_body):
    fm, body = revenue_fm_body
    assert canonicalize_concept(fm, canonical_body(body)) == canonicalize_concept(fm, body)
    fm_json = canonical_frontmatter_json(fm)
    assert canonicalize_from_parts(fm_json, body) == canonicalize_concept(fm, body)


def test_duplicate_frontmatter_key_rejected():
    text = REVENUE_CONCEPT.read_text().replace("status: stable", "status: stable\nstatus: deprecated")
    with pytest.raises(ValueError, match="duplicate frontmatter key"):
        _split_frontmatter(text)


def test_resolve_resource_rejects_traversal():
    with pytest.raises(ValueError, match="escapes the bundle root"):
        resolve_resource(BUNDLE_PATH, "../../../etc/passwd")


def test_resolve_resource_returns_none_for_absolute_url():
    assert resolve_resource(BUNDLE_PATH, "https://example.com/x") is None


def test_resolve_resource_bundle_root_relative():
    # executor.resource / attester.resource are bundle-root relative, no leading '/'
    path = resolve_resource(BUNDLE_PATH, "attesters/sql_equality.py")
    assert path is not None and path.exists()


def test_resolve_resource_concept_relative_body_link():
    path = resolve_resource(BUNDLE_PATH, "./gross-margin-legacy.md", concept_id="metrics/gross-margin.md")
    assert path is not None and path.exists() and path.name == "gross-margin-legacy.md"


def test_extract_computation_fenced():
    concepts = {c["concept_id"]: c for c in parse_bundle(BUNDLE_PATH, "acme_retail")}
    source, lang = extract_computation(concepts["computations/revenue-ytd"])
    assert lang == "sql"
    assert "SUM(" in source


def test_extract_computation_indented_form():
    """SPEC Appendix A shows a 4-space-indented block instead of a fence;
    the extractor must support both, not just what acme_retail happens to use."""
    concept = {
        "body": "# Computation\n\n    SELECT SUM(amount) AS revenue\n    FROM finance.recognized_revenue\n\nProse after.\n",
    }
    source, lang = extract_computation(concept)
    assert lang == ""
    assert "SELECT SUM(amount)" in source


def test_extract_computation_absent_returns_none():
    concept = {"body": "# Definition\n\nNo computation section here.\n"}
    assert extract_computation(concept) is None


def test_canonical_computation_bytes_matches_attester_pin_input():
    concepts = {c["concept_id"]: c for c in parse_bundle(BUNDLE_PATH, "acme_retail")}
    rev = concepts["computations/revenue-ytd"]
    comp_bytes = canonical_computation_bytes(rev, BUNDLE_PATH)
    assert comp_bytes is not None
    # deterministic: calling twice gives identical bytes
    assert comp_bytes == canonical_computation_bytes(rev, BUNDLE_PATH)


def test_non_concept_type_and_no_frontmatter_tolerated(tmp_path):
    """§11 conformance: a `.md` with no frontmatter at all must not crash
    parse_bundle -- OKF only requires a non-empty `type` when frontmatter IS
    present; a totally bare file (like a stray non-reserved doc) still needs
    to parse into a concept with type=''."""
    bundle = tmp_path / "mini_bundle"
    (bundle / "notes").mkdir(parents=True)
    (bundle / "notes" / "freeform.md").write_text("# Just prose\n\nNo frontmatter at all.\n")
    concepts = parse_bundle(bundle, "mini_bundle")
    assert len(concepts) == 1
    assert concepts[0]["type"] == ""
    assert concepts[0]["frontmatter"] == {}


def test_empty_bundle_raises_named_error(tmp_path):
    bundle = tmp_path / "empty_bundle"
    bundle.mkdir()
    (bundle / "index.md").write_text("# Nothing but an index\n")
    with pytest.raises(ValueError, match="no concepts"):
        parse_bundle(bundle, "empty_bundle")
