"""OKF v0.2 bundle parsing and concept canonicalization.

A *concept* is to a bundle what a chunk is to an arXiv paper (src/ingest.py):
the unit that gets its own SHA-256 leaf in a signed Merkle tree. This module
produces the deterministic bytes that src/merkle.py hashes into those leaves.
It never signs, never touches Chroma, and never writes to disk.

Canonical form (CANON_VERSION = "okf-concept/v1"):

    okf-concept/v1\\n
    {canonical JSON of the frontmatter, exactly one line}\\n
    ---\\n
    {canonical body}

Frontmatter is canonicalized as RFC-8785-flavored JSON (sorted keys, no
whitespace, NFC) rather than re-emitted YAML. yaml.safe_dump folds long
scalars at width=80, spells datetimes a third way
("2026-06-30 14:00:00+00:00"), and quotes an ISO-date *string* while leaving
a bare YAML date unquoted -- three ways to silently change the digest.
json.dumps also never emits a raw newline inside a string, so the
frontmatter segment is guaranteed single-line and "\\n---\\n" is an
unambiguous separator (no length prefix needed).

Documented round-trip limits (the digest deliberately does / does not
survive these):

  SURVIVES (digest unchanged): frontmatter key reordering; block <-> flow
  YAML style; quoted <-> bare ISO dates; "Z" <-> "+00:00"; CRLF/CR <-> LF;
  per-line trailing whitespace; leading/trailing blank lines; NFD <-> NFC;
  YAML comments added/removed; YAML 1.1 boolean spellings (yes/true).

  DOES NOT SURVIVE (digest changes, by design or as an accepted v1 limit):
  reordering LIST items (tags, sources, verified stay order-significant);
  a bare date (2026-12-31) vs. a datetime (2026-12-31T00:00:00Z) -- these
  are distinct values, not a formatting difference; 1 vs 1.0; prose reflow
  / re-wrapping; changed indentation; added/removed interior blank lines;
  "*" <-> "-" bullets.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re
import textwrap
import unicodedata
from pathlib import Path
from typing import Any

import yaml

from src.config import OKF_CANON_VERSION as CANON_VERSION
from src.config import OKF_PINS_VERSION
from src.schema import ConceptRecord

RESERVED_FILES = frozenset({"index.md", "log.md"})  # §3.1 navigation/history, never concepts

_DELIMITERS = ("|", "\n", "\r")


def _no_delimiters(*fields: str) -> None:
    """Reject '|'/newline in any field of a domain-separated signed message.

    Every signed message in this project ('|'-joined, version-prefixed: see
    pins_message() here and trust.trust_message()) is unambiguous only if no
    field can itself contain the join delimiter. Without this guard, a
    hostile bundle could craft two different field-tuples that join to the
    identical byte string -- fields don't need to be attacker-controlled
    today for this to be worth closing once, in one place, for every caller.
    """
    for f in fields:
        if any(d in f for d in _DELIMITERS):
            raise ValueError(f"field contains a reserved delimiter (|, \\n, \\r): {f!r}")


# ── frontmatter parsing ──────────────────────────────────────────────────────
class _UniqueKeySafeLoader(yaml.SafeLoader):
    """SafeLoader that REJECTS duplicate mapping keys.

    Plain yaml.safe_load silently keeps the *last* duplicate. Because OKF-Verify
    signs the canonical *parsed* form rather than raw bytes, an attacker could
    append a second `status:` line without changing our digest -- while a
    consumer whose loader keeps the *first* key would then act on values we
    never signed. Fail closed instead of letting the two loaders disagree.
    """


def _construct_mapping_no_dupes(loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in seen:
            raise ValueError(f"duplicate frontmatter key: {key!r}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping_no_dupes
)


def _split_frontmatter(text: str) -> tuple[dict, str]:
    """Split a concept file into (frontmatter dict, body).

    Line-based, not `text.find("\\n---")`: a body may legitimately contain a
    `---` horizontal rule or a markdown table separator, so the search must
    only match a `---`/`...` line that appears as the frontmatter's own
    closing fence. A file with no leading `---` fence (e.g. a root index.md)
    yields ({}, whole text) -- index.md is allowed no frontmatter (§8) except
    an optional bundle-root `okf_version` key, which this function does not
    special-case; callers that care can read it from the returned dict.
    """
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")
    if not lines or lines[0].strip() != "---":
        return {}, normalized
    for i in range(1, len(lines)):
        if lines[i].strip() in ("---", "..."):
            fm_text = "\n".join(lines[1:i])
            body = "\n".join(lines[i + 1 :])
            fm = yaml.load(fm_text, Loader=_UniqueKeySafeLoader) or {}
            if not isinstance(fm, dict):
                raise ValueError("frontmatter is not a YAML mapping")
            return fm, body
    raise ValueError("unterminated frontmatter: no closing '---' fence")


# ── normalization (runs BEFORE hashing and BEFORE storage) ───────────────────
def _normalize_yaml_value(value: Any) -> Any:
    """Recursively make a safe_load()ed value JSON-safe AND canonical.

    PyYAML's YAML-1.1 resolver turns `stale_after: 2026-12-31` into a
    datetime.date and `at: 2026-06-30T14:00:00Z` into a tz-aware datetime.
    Both are unserializable by json, and round-tripping them back through
    YAML produces a THIRD spelling ("2026-06-30 14:00:00+00:00"). Collapse
    every temporal type to one ISO string here, at parse time, so that:

      * the digest is computed over the same values that get stored
        (src/okf_ingest.py stores this same normalized frontmatter as JSON
        in Chroma metadata -- one pass feeds both, so they cannot drift), and
      * `2026-12-31`, `'2026-12-31'`, and `"2026-12-31"` all hash identically
        (a genuine benign-round-trip win), while
      * `2026-12-31` and `2026-12-31T00:00:00Z` remain distinct values.

    Strings and mapping KEYS are NFC-normalized here too, so a Unicode
    re-encoding by an agent does not break the signature, and so a later
    per-actor trust signature (over `verified[].by` / `sources[].author`)
    uses the same byte form as this digest.
    """
    if isinstance(value, bool):  # must precede int: bool is an int subclass
        return value
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key = unicodedata.normalize("NFC", str(k))
            if key in out:
                raise ValueError(f"frontmatter key collision after normalization: {key!r}")
            out[key] = _normalize_yaml_value(v)
        return out
    if isinstance(value, (list, tuple)):
        return [_normalize_yaml_value(v) for v in value]
    if isinstance(value, datetime.datetime):
        iso = value.isoformat()
        return iso[:-6] + "Z" if iso.endswith("+00:00") else iso
    if isinstance(value, (datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("non-finite float in frontmatter (not representable in JSON)")
        return value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, bytes):  # YAML !!binary
        return unicodedata.normalize("NFC", value.decode("utf-8"))
    if value is None or isinstance(value, int):
        return value
    raise ValueError(f"unsupported YAML type in frontmatter: {type(value).__name__}")


# ── canonicalization ─────────────────────────────────────────────────────────
def canonical_frontmatter_json(frontmatter: dict) -> str:
    """Canonical single-line JSON for a frontmatter mapping.

    Idempotent: canonical_frontmatter_json(json.loads(s)) == s, because JSON
    round-trips (unlike YAML dates) preserve exact string/number spelling.
    """
    return json.dumps(
        _normalize_yaml_value(frontmatter),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def canonical_body(body: str) -> str:
    """Conservative body canonicalization -- idempotent.

    Normalize line endings and NFC, strip TRAILING whitespace per line, strip
    leading/trailing blank lines, end with exactly one newline.

    DESIGN NOTE: deliberately does NOT touch leading whitespace or interior
    blank lines. A `# Computation` block may be a 4-space-indented code block
    (SPEC Appendix A) rather than a fenced one, and reindenting it would
    corrupt the SQL. Heavy prose reflow is out of scope for v1 -- see the
    documented round-trip limits in this module's docstring.
    """
    b = unicodedata.normalize("NFC", body).replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in b.split("\n")).strip() + "\n"


def canonicalize_from_parts(frontmatter_json: str, body: str) -> bytes:
    """Canonical bytes from an ALREADY-canonical frontmatter JSON string.

    This is the re-verification entry point: src/okf_ingest.py stores
    `frontmatter_json` verbatim in Chroma metadata, so a later tamper check
    (recomputing the hash from what's in the store) rebuilds the exact hashed
    bytes without re-running YAML or JSON serialization -- and so cannot drift
    from the bytes that were originally signed.
    """
    return f"{CANON_VERSION}\n{frontmatter_json}\n---\n{canonical_body(body)}".encode("utf-8")


def canonicalize_concept(frontmatter: dict, body: str) -> bytes:
    """Deterministic bytes for hashing a concept.

    Survives the benign round-trips OKF assumes (§5.1 "agents constantly
    rewrite these documents"; §4.1 "preserve unknown keys") -- see this
    module's docstring for the exact survives/does-not-survive list.
    """
    return canonicalize_from_parts(canonical_frontmatter_json(frontmatter), body)


def concept_sha256(frontmatter: dict, body: str) -> str:
    return hashlib.sha256(canonicalize_concept(frontmatter, body)).hexdigest()


# ── bundle walk ──────────────────────────────────────────────────────────────
def parse_bundle(bundle_path: Path, bundle_id: str) -> list[ConceptRecord]:
    """Walk a bundle; every non-reserved .md is a concept (§3.1, §4).

    Leaf order is lexicographic by CONCEPT_ID (path with the .md suffix
    stripped), not by raw file path -- these are not the same ordering. In
    acme_retail, path order puts "metrics/gross-margin-legacy.md" before
    "metrics/gross-margin.md" ('-' = 0x2D < '.' = 0x2E) while concept_id
    order is the reverse, so sorting the wrong key silently yields a
    different Merkle root than every downstream verifier expects.
    """
    concepts: list[ConceptRecord] = []
    for md in bundle_path.rglob("*.md"):
        if md.name in RESERVED_FILES:
            continue
        rel = md.relative_to(bundle_path).as_posix()
        try:
            fm, body = _split_frontmatter(md.read_text(encoding="utf-8"))
        except ValueError as e:
            raise ValueError(f"{rel}: {e}") from e
        fm_json = canonical_frontmatter_json(fm)
        concepts.append(
            {
                "concept_id": rel[: -len(".md")],
                "bundle_id": bundle_id,
                "rel_path": rel,
                "type": str(fm.get("type", "")),
                "title": str(fm.get("title", "")),
                "frontmatter": json.loads(fm_json),  # the normalized form, not the raw safe_load
                "frontmatter_json": fm_json,
                "body": body,
                "sha256": hashlib.sha256(canonicalize_from_parts(fm_json, body)).hexdigest(),
                "merkle_index": -1,
            }
        )

    concepts.sort(key=lambda c: c["concept_id"])  # code-point order == leaf order
    for i, c in enumerate(concepts):
        c["merkle_index"] = i

    if not concepts:
        raise ValueError(
            f"bundle {bundle_id!r} at {bundle_path} contains no concepts "
            f"(merkle.build_levels raises ValueError on an empty leaf list)"
        )
    return concepts


def _as_list(value: Any) -> list:
    """SPEC §5.2 permits `verified:` as a bare mapping OR a list of mappings.

    acme_retail uses the list form throughout, but a conformant producer may
    write the bare-mapping shorthand for a single entry. Consumers MUST treat
    it as a one-element list.
    """
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


# ── resource resolution ──────────────────────────────────────────────────────
def resolve_resource(bundle_path: Path, ref: str, *, concept_id: str | None = None) -> Path | None:
    """Resolve an OKF resource reference to a real path inside the bundle.

    Two different base directories, per SPEC §6.2/§6.3, confirmed against the
    real acme_retail bundle:

      * FRONTMATTER refs (`executor.resource: skills/run-on-bq.md`,
        `attester.resource: attesters/sql_equality.py`, `sources[].resource`)
        are BUNDLE-ROOT relative and carry no leading '/'.
      * BODY markdown links (`./gross-margin-legacy.md`,
        `../computations/revenue-ytd.md`) are CONCEPT relative -- pass
        `concept_id` to resolve those.

    Returns None for absolute URLs (a `resource:` on a table/policy concept is
    often an https:// console or wiki link, not a bundle file). Raises if the
    resolved path escapes the bundle root: a bundle is untrusted input, and
    `attester.resource: ../../../etc/passwd` must not resolve.
    """
    if ref.startswith(("http://", "https://", "//")):
        return None
    cleaned = ref.lstrip("/")
    if concept_id is not None and (cleaned.startswith("./") or cleaned.startswith("../")):
        base = (bundle_path / concept_id).parent
    else:
        base = bundle_path
    candidate = (base / cleaned).resolve()
    root = bundle_path.resolve()
    if not candidate.is_relative_to(root):
        raise ValueError(f"resource {ref!r} escapes the bundle root")
    return candidate


def attester_bytes(bundle_path: Path, concept: ConceptRecord) -> tuple[bytes, str] | None:
    """RAW bytes of a concept's attester resource, plus its bundle-relative path.

    Raw, not canonicalized: it is executable code, and a whitespace-tolerant
    digest over code would be a real hole here -- the whole point of the pin
    (see src/okf_ingest.py::build_pins) is byte identity of what will run.
    """
    attester = concept["frontmatter"].get("attester")
    ref = attester.get("resource") if isinstance(attester, dict) else None
    if not ref:
        return None
    path = resolve_resource(bundle_path, ref)
    if path is None or not path.exists():
        raise FileNotFoundError(f"{concept['concept_id']}: attester resource {ref!r} not found")
    return path.read_bytes(), ref


# ── `# Computation` extraction (shared by ingest-time pins and future runs) ──
_HEADING_RE = re.compile(r"^#{1,6}[ \t]+Computation[ \t]*$", re.M)
_NEXT_HEADING_RE = re.compile(r"^#{1,6}[ \t]+", re.M)
_FENCE_RE = re.compile(
    r"^([ \t]*)(`{3,}|~{3,})[ \t]*([A-Za-z0-9_+-]*)[ \t]*\n(.*?)^\1\2[ \t]*$",
    re.M | re.S,
)


def _computation_section(body: str) -> str | None:
    m = _HEADING_RE.search(body)
    if not m:
        return None
    rest = body[m.end() :]
    nxt = _NEXT_HEADING_RE.search(rest)
    return rest[: nxt.start()] if nxt else rest


def extract_computation(concept: ConceptRecord) -> tuple[str, str] | None:
    """Return (computation source, language) from a concept's `# Computation`.

    Supports BOTH forms: acme_retail uses a fenced ```sql block, while SPEC
    Appendix A shows a 4-space-indented block. Fenced wins if both somehow
    match. Returns None if the concept has no `# Computation` section.
    """
    section = _computation_section(concept["body"])
    if section is None:
        return None
    fence = _FENCE_RE.search(section)
    if fence:
        return textwrap.dedent(fence.group(4)), (fence.group(3) or "")
    indented = [ln for ln in section.split("\n") if ln.startswith(("    ", "\t"))]
    if not indented:
        return None
    return textwrap.dedent("\n".join(indented)), ""


def pins_message(bundle_id: str, concept_id: str, comp_sha: str, att_sha: str) -> bytes:
    """Domain-separated, unambiguous message for a ComputationPins signature.

    Lives here (pure stdlib) rather than in src/okf_ingest.py so that a
    verifier (src/okf_verify.py) can recompute it without transitively
    importing sentence_transformers/chromadb -- consistent with verify.py's
    public-key-only, no-heavy-deps verification path.
    """
    _no_delimiters(bundle_id, concept_id, comp_sha, att_sha)
    return f"{OKF_PINS_VERSION}|{bundle_id}|{concept_id}|{comp_sha}|{att_sha}".encode()


def canonical_computation_bytes(concept: ConceptRecord, bundle_path: Path | None = None) -> bytes | None:
    """Canonical bytes of the sanctioned computation -- the ComputationPins subject.

    Whitespace-canonicalized the same conservative way as a body: the OKF
    attester itself canonicalizes SQL (§10.2), so a pin digest that is
    *stricter* than the attester would reject runs the attester accepts.
    Prefers the frontmatter `computation:` file over the in-body fence when
    both are present (§10.3).
    """
    ref = concept["frontmatter"].get("computation")
    if ref:
        path = resolve_resource(bundle_path or Path("."), str(ref), concept_id=concept["rel_path"])
        if path is None or not path.exists():
            raise FileNotFoundError(f"{concept['concept_id']}: computation {ref!r} not found")
        return canonical_body(path.read_text(encoding="utf-8")).encode("utf-8")
    extracted = extract_computation(concept)
    if extracted is None:
        return None
    return canonical_body(extracted[0]).encode("utf-8")
