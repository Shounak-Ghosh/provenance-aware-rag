"""Runtime enforcement: refuse a concept at the point of use.

Every module before this one is a library function with no caller.
src.okf_verify.verify_bundle returns a report nobody reads; src.okf_attest
RECORDS an authenticated tier and explicitly does not gate on it. This module
is the first consumer, and the contribution is what it refuses:

    retrieve -> verify -> ADMIT or REFUSE with a named reason

A refused concept never enters the LLM's context. That is the difference
between checking a bundle at rest and enforcing it at the moment an agent
consumes a concept.

WHAT THIS ADDS THAT NOTHING UPSTREAM DOES
-----------------------------------------
1. It verifies the copy of the concept that the MODEL actually reads. Every
   at-rest check re-parses the bundle DIRECTORY; the agent serves Chroma rows,
   and nothing had ever hashed those. See src/okf_retrieve.py's module
   docstring for the two-copy argument. This gate checks BOTH surfaces against
   the same publisher-signed digest -- `integrity` for the store copy the model
   reads, `integrity_on_disk` for the copy a run would execute -- so an
   attacker has to compromise both to move either.
2. It is the first code to act on the claimed-vs-authenticated trust
   comparison. src.trust has computed both the claimed tier (what a
   signal-trusting consumer such as the bundle's own viz.html displays) and the
   signature-backed tier since Day 2; nothing consumed the difference. The demo
   sentence is exactly this: a signal-trusting consumer serves the concept, the
   verifying agent refuses it and names the actor whose signature was missing.
3. Its answer attestation signs the REFUSED set alongside the admitted one, so
   an auditor can prove absence-by-policy rather than absence-by-luck.

TWO INDEPENDENT TRUST GATES, AND WHY THEY MUST NOT BE ONE
---------------------------------------------------------
  * AUTHENTICITY is always a refusal: any `verified` entry that is unbacked or
    carries an invalid signature. Note this is a STRICTLY WIDER condition than
    TrustAssessment["downgraded"] -- see _authenticity_check, which explains why
    gating on the downgrade flag alone silently admits a forged claim added to a
    concept that was already human-reviewed.
  * `min_tier` is separate, configurable POLICY, defaulting to the most
    permissive value ("unverified").

The acme_retail bundle forces the split: skills/run-on-bq carries no `verified`
entry at all -- honest, and it is the executor skill every Attested Computation
depends on. One combined gate would either refuse it for no security reason or
accept a forged `verified: {by: human:attacker}` whose signature is absent.
Keeping the default floor permissive also means every refusal in the demo fires
under stock policy, so none of them depend on a hand-tuned threshold.

ORDERING: unlike src.okf_attest.attest_run, admit_concept does NOT
short-circuit. There the ordering IS the contribution (refuse before execute,
so no bundle code runs). Here the contribution is the EXPLANATION: a concept
that is simultaneously tampered, trust-forged, and stale must report all three,
because "the agent refuses and names each reason" is the demo.

Nothing behind this gate executes. The Attested-Computation check calls
src.okf_verify.check_pins directly rather than attest_run(allow_exec=False):
attest_run binds the declared `parameters:` at stage 4, so asking it about a
concept nobody is currently running would refuse revenue-ytd for a missing
`year` -- parameter binding is a property of a RUN, not of admission. check_pins
is the at-rest half and is exactly the question the gate is asking: are the
sanctioned computation and the attester still what the publisher signed?

HONEST LIMITS
  * Source closure is ONE level deep and refuses only on tamper/absence. A
    source that is merely deprecated or stale is a WARNING: OKF `sources` are
    citations, and cascading a policy's staleness into every concept citing it
    would refuse the whole bundle on 2027-01-01. Following a source's own
    sources needs a cycle guard and a policy for diamond dependencies; both are
    real design questions, not a one-line extension, so v1 stops at depth 1.
  * parse_answer_value() is a regex over model prose. It fails OPEN on absence
    (no number found -> warning, answer served marked value-unattested) and
    CLOSED on disagreement (number found and it contradicts the attested
    receipt -> the answer is refused). A heuristic gets to veto, not to vouch.
"""
from __future__ import annotations

import hashlib
import logging
import re
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import nacl.signing

from src.attestation import append_attestation, load_attestations, sign_attestation, verify_attestation
from src.config import (
    LLM_MODEL,
    OKF_ATTESTATION_LOG_PATH,
    OKF_MIN_TIER,
    OKF_SYSTEM_PROMPT,
    OKF_TIER_ORDER,
    OKF_USER_PROMPT_TEMPLATE,
)
from src.generate import generate, parse_concept_citations
from src.okf import _as_list, parse_bundle, resolve_resource
from src.okf_attest import attest_run
from src.okf_retrieve import retrieve_okf
from src.okf_verify import check_concept_tamper, check_pins
from src.schema import AdmissionDecision, ConceptRecord
from src.trust import derive_authenticated_tier

_OKF_ANSWER_PAYLOAD_FIELDS = (
    "answer_sha256",
    "concept_hashes",
    "concept_ids",
    "refused_concept_ids",
    "query_sha256",
    "bundle_id",
    "model",
    "timestamp",
)

# The lookbehind is load-bearing: without it "FY2026 revenue was 43042.42"
# yields 2026, and the fidelity check then fails on the fiscal-year label rather
# than on the figure. A number must start at a non-word, non-dot boundary.
_NUMBER_RE = re.compile(r"(?<![\w.])-?\d[\d,]*(?:\.\d+)?(?![\w])")


# ── the gate ─────────────────────────────────────────────────────────────────
def _tier_rank(tier: str) -> int:
    """Position on the §5.3 ladder; an unrecognized tier sorts below everything
    so an unknown value can never satisfy a floor."""
    return OKF_TIER_ORDER.index(tier) if tier in OKF_TIER_ORDER else -1


def _authenticity_check(trust: dict) -> tuple[bool, str]:
    """Is every `verified` claim this concept makes actually backed by its
    claimed actor's key?

    NOT the same question as TrustAssessment["downgraded"], and the difference
    matters. `downgraded` only fires when the forged claim moves the concept's
    position on the §5.3 ladder. Adding `verified: {by: human:attacker}` to a
    concept jsmith has already verified leaves the tier at "human-reviewed", so
    `downgraded` stays False -- while the concept now advertises a review that
    never happened, which is precisely the claim OKF's plaintext trust signals
    invite and cannot substantiate. So the gate refuses on the presence of any
    `unbacked` or `invalid` entry, and reports the tier movement only as extra
    colour when there is any.

    `unknown_actor` is deliberately NOT a refusal: src.trust separates it from
    forgery because an actor missing from the keyring is a key-distribution gap,
    and the claim is unevaluated rather than disproved. It cannot raise the
    authenticated tier either way, so the tier floor is what governs it; the
    caller surfaces it as a warning.
    """
    parts = []
    if trust["unbacked"]:
        parts.append(f"unbacked: {', '.join(trust['unbacked'])}")
    if trust["invalid"]:
        parts.append(f"invalid signature: {', '.join(trust['invalid'])}")
    if not parts:
        return True, f"every verified claim is signature-backed (tier {trust['tier']})"
    movement = (
        f"tier {trust['claimed_tier']} -> {trust['tier']}"
        if trust["downgraded"]
        else f"tier unchanged at {trust['tier']}"
    )
    return False, f"unbacked trust claim ({'; '.join(parts)}; {movement})"


def _staleness(frontmatter: dict, today: date) -> tuple[bool, str | None, str | None]:
    """(is_stale, refusal_reason, warning). `stale_after: 2026-12-31` means the
    concept is stale AFTER that date, so the comparison is strict `>` and the
    boundary day itself is still fresh. A malformed value is a warning, never a
    crash: okf._normalize_yaml_value guarantees an ISO string for a real date,
    but a hostile bundle can still write `stale_after: soon`."""
    raw = frontmatter.get("stale_after")
    if raw in (None, ""):
        return False, None, None
    try:
        stale_after = date.fromisoformat(str(raw)[:10])
    except ValueError:
        return False, None, f"unparsable stale_after {raw!r} — freshness not checked"
    if today > stale_after:
        return True, f"stale (stale_after {stale_after.isoformat()}, today {today.isoformat()})", None
    return False, None, None


def admit_concept(
    concept: ConceptRecord,
    expected_sha256: str | None,
    leaf_hashes: list[str],
    bundle_rec: dict,
    publisher_vk: nacl.signing.VerifyKey,
    sig_index: dict,
    keyring: dict[str, nacl.signing.VerifyKey],
    *,
    today: date,
    min_tier: str = OKF_MIN_TIER,
    bundle_path: Path | None = None,
    bundle_id: str | None = None,
    pins_index: dict[str, dict] | None = None,
    by_id: dict[str, ConceptRecord] | None = None,
    signed_sha256: dict[str, str] | None = None,
    disk: dict | None = None,
) -> AdmissionDecision:
    """Decide whether ONE retrieved concept may enter the LLM's context.

    Runs every check and collects every failure (see the module docstring on
    why this does not short-circuit). `expected_sha256` MUST come from the
    publisher-signed `concepts` list in okf_roots.json -- never from the store's
    own metadata, which an attacker who reached the store also controls.

    `disk` is {"by_id", "leaf_hashes"} from ONE parse_bundle() of the directory
    (see admit_all). It is what checks 6 and 7 reason about, because the bytes a
    future run would execute come off disk, not out of the store. Both copies
    are compared against the SAME publisher-signed digest, so if each passes its
    own integrity check the two are necessarily identical -- no third
    store-vs-disk comparison is needed.

    Nothing here executes. Actually running an Attested Computation is an
    explicit, separate step (run_agent's `run_concept`), never a side effect of
    retrieval.
    """
    reasons: list[str] = []
    warnings: list[str] = []
    checks: dict[str, dict] = {}

    def record(name: str, ok: bool, reason: str, blocking: bool = True) -> None:
        checks[name] = {"ok": ok, "reason": reason}
        if not ok and blocking:
            reasons.append(reason)

    disk_by_id = (disk or {}).get("by_id", {})
    disk_concept = disk_by_id.get(concept["concept_id"])

    # 1 — integrity of the STORE copy: the bytes the model would actually read.
    if expected_sha256 is None:
        record("integrity", False, "concept not present in signed bundle (added since signing)")
    else:
        tampered, reason = check_concept_tamper(  # REUSE okf_verify.check_concept_tamper
            concept, expected_sha256, concept["merkle_index"], leaf_hashes, bundle_rec, publisher_vk
        )
        record("integrity", not tampered, reason)

    # 2 — integrity of the DISK copy: the bytes a run would execute. Same
    # function, same signed digest, different surface (module docstring).
    if disk_concept is not None and expected_sha256 is not None:
        d_tampered, d_reason = check_concept_tamper(
            disk_concept, expected_sha256, disk_concept["merkle_index"],
            (disk or {}).get("leaf_hashes", []), bundle_rec, publisher_vk,
        )
        record("integrity_on_disk", not d_tampered, d_reason)

    # 3/4 — trust: the forgery gate and the policy floor, kept separate (module docstring).
    trust = derive_authenticated_tier(  # REUSE trust.derive_authenticated_tier
        concept["bundle_id"], concept, sig_index, keyring
    )
    authentic, authentic_reason = _authenticity_check(trust)
    record("trust_authentic", authentic, authentic_reason)
    for actor in trust["unknown_actor"]:
        warnings.append(f"trust claim by {actor} unevaluated: actor not in keyring")

    meets_floor = _tier_rank(trust["tier"]) >= _tier_rank(min_tier)
    record("trust_floor", meets_floor, f"tier {trust['tier']!r} below required {min_tier!r}" if not meets_floor else f"tier {trust['tier']} meets floor {min_tier}")

    # 4 — lifecycle status.
    status = str(concept["frontmatter"].get("status", ""))
    record("status", status != "deprecated", f"status: {status}" if status == "deprecated" else f"status: {status or 'unset'}")

    # 5 — freshness.
    stale, stale_reason, stale_warning = _staleness(concept["frontmatter"], today)
    if stale_warning:
        warnings.append(stale_warning)
    record("freshness", not stale, stale_reason or "within stale_after")

    # 6 — Attested Computation: publisher-signed pins, WITHOUT executing anything.
    # Runs against the DISK record, never the store one: check_pins extracts the
    # `# Computation` fence from the record's own body, so handing it a store
    # copy would pin-check bytes nobody is going to execute. The attester file
    # it also covers is read from disk either way, and is the ONE artifact the
    # pins uniquely protect -- attesters/*.py is not a `.md` file and so is
    # never a Merkle leaf.
    if concept["type"] == "Attested Computation":
        if bundle_path is None or disk_concept is None:
            record("pins", False, "attested computation: bundle not available on disk to check pins")
        else:
            pin_tampered, pin_reason = check_pins(  # REUSE okf_verify.check_pins
                disk_concept,
                bundle_path,
                (pins_index or {}).get(concept["concept_id"]),
                bundle_id or concept["bundle_id"],
                publisher_vk,
            )
            record("pins", not pin_tampered, pin_reason)

    # 7 — source closure, one level, tamper-only (module docstring).
    src_ok, src_reasons, src_warnings = _check_sources(
        concept, by_id or {}, signed_sha256 or {}, leaf_hashes, bundle_rec, publisher_vk, bundle_path, today
    )
    warnings.extend(src_warnings)
    record("sources", src_ok, "; ".join(src_reasons) if src_reasons else "all bundle-local sources verify")

    return {
        "concept_id": concept["concept_id"],
        "admitted": not reasons,
        "reasons": reasons,
        "warnings": warnings,
        "checks": checks,
        "trust": trust,
        "tier": trust["tier"],
        "claimed_tier": trust["claimed_tier"],
    }


def _check_sources(
    concept: ConceptRecord,
    by_id: dict[str, ConceptRecord],
    signed_sha256: dict[str, str],
    leaf_hashes: list[str],
    bundle_rec: dict,
    publisher_vk: nacl.signing.VerifyKey,
    bundle_path: Path | None,
    today: date,
) -> tuple[bool, list[str], list[str]]:
    """Verify each bundle-LOCAL `sources[].resource` resolves to an untampered concept.

    Absolute URLs (a wiki or console link, common on Policy/BigQuery Table
    concepts) resolve to None via okf.resolve_resource and are skipped -- this
    layer cannot speak about bytes it has never seen, and pretending otherwise
    would be the wrong kind of green check. A `resource` that escapes the bundle
    root raises inside resolve_resource and is reported as a refusal.
    """
    reasons: list[str] = []
    warnings: list[str] = []
    for source in _as_list(concept["frontmatter"].get("sources")):
        if not isinstance(source, dict):
            continue
        sid = str(source.get("id", "?"))
        ref = str(source.get("resource", ""))
        if not ref:
            continue
        try:
            resolved = resolve_resource(bundle_path or Path("."), ref, concept_id=concept["rel_path"])
        except ValueError as e:
            reasons.append(f"source {sid!r} rejected: {e}")
            continue
        if resolved is None or not ref.endswith(".md"):
            continue  # external URL or non-concept resource — out of this layer's reach

        target_id = ref[: -len(".md")].lstrip("/")
        target = by_id.get(target_id)
        if target is None:
            reasons.append(f"source {sid!r} not verifiable: concept {target_id!r} not in bundle")
            continue
        tampered, reason = check_concept_tamper(
            target, signed_sha256.get(target_id, ""), target["merkle_index"], leaf_hashes, bundle_rec, publisher_vk
        )
        if tampered:
            reasons.append(f"source {sid!r} not verifiable: {reason}")
            continue

        # Non-blocking signals on a source: a citation's lifecycle is worth
        # surfacing but must not cascade into refusing every concept citing it.
        if str(target["frontmatter"].get("status", "")) == "deprecated":
            warnings.append(f"source {sid!r} ({target_id}) is deprecated")
        stale, stale_reason, _ = _staleness(target["frontmatter"], today)
        if stale:
            warnings.append(f"source {sid!r} ({target_id}) is {stale_reason}")

    return (not reasons, reasons, warnings)


def admit_all(
    concepts: list[ConceptRecord],
    bundle_view: dict,
    publisher_vk: nacl.signing.VerifyKey,
    keyring: dict[str, nacl.signing.VerifyKey],
    *,
    today: date,
    min_tier: str = OKF_MIN_TIER,
    bundle_id: str | None = None,
) -> list[AdmissionDecision]:
    """admit_concept over a retrieved set, sharing one bundle view.

    `bundle_view` is one value of src.okf_retrieve.retrieve_okf's `bundles`
    map: leaf_hashes, bundle_rec, signed_sha256, sig_index, pins_index, by_id,
    bundle_path. Passing it whole means source closure reasons about the SAME
    store snapshot the retrieved concepts came from rather than issuing fresh
    reads an attacker could answer differently.

    The bundle directory is parsed exactly ONCE here and the result shared, for
    the same reason src.okf_attest.attest_run passes its parse into
    verify_bundle: every concept in a batch must be judged against one read of
    a directory an attacker may be writing to concurrently, not against N.
    A bundle that has become unparsable is not fatal -- the store copy can still
    be checked, and the disk-side checks report the parse failure by name.
    """
    disk: dict = {"by_id": {}, "leaf_hashes": [], "error": None}
    bundle_path = bundle_view.get("bundle_path")
    if bundle_path is not None and Path(bundle_path).is_dir():
        try:
            parsed = parse_bundle(Path(bundle_path), bundle_id or "")
            disk = {
                "by_id": {c["concept_id"]: c for c in parsed},
                "leaf_hashes": [c["sha256"] for c in parsed],
                "error": None,
            }
        except ValueError as e:
            disk["error"] = str(e)

    return [
        admit_concept(
            c,
            bundle_view["signed_sha256"].get(c["concept_id"]),
            bundle_view["leaf_hashes"],
            bundle_view["bundle_rec"],
            publisher_vk,
            bundle_view["sig_index"],
            keyring,
            today=today,
            min_tier=min_tier,
            bundle_path=bundle_view.get("bundle_path"),
            bundle_id=bundle_id or c["bundle_id"],
            pins_index=bundle_view.get("pins_index"),
            by_id=bundle_view.get("by_id"),
            signed_sha256=bundle_view.get("signed_sha256"),
            disk=disk,
        )
        for c in concepts
    ]


# ── the answer attestation (admitted AND refused) ────────────────────────────
def build_okf_answer_attestation(
    question: str,
    answer: str,
    admitted: list[ConceptRecord],
    refused_ids: list[str],
    bundle_id: str,
    model: str,
) -> dict:
    """Unsigned OKF answer attestation.

    `refused_concept_ids` is inside the SIGNED payload on purpose. Recording
    only what was used proves nothing about what was withheld: an auditor
    reading a normal attestation cannot distinguish "the agent never saw the
    tampered concept" from "the agent saw it and excluded it". Signing the
    refusals turns absence-by-luck into absence-by-policy, and it is the piece
    of evidence a downstream reviewer of an agent's answer actually wants.
    """
    return {
        "answer_sha256": hashlib.sha256(answer.encode()).hexdigest(),
        "concept_hashes": [c["sha256"] for c in admitted],
        "concept_ids": [c["concept_id"] for c in admitted],
        "refused_concept_ids": sorted(refused_ids),
        "query_sha256": hashlib.sha256(question.encode()).hexdigest(),
        "bundle_id": bundle_id,
        "model": model,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def sign_okf_answer(attestation: dict, sk: nacl.signing.SigningKey, key_id: str) -> dict:
    """REUSE attestation.sign_attestation with this module's field tuple -- same
    Ed25519 over the same canonical-JSON shape, only the signed field list
    differs. attestation._PAYLOAD_FIELDS stays frozen for the arXiv log."""
    return sign_attestation(attestation, sk, key_id, _OKF_ANSWER_PAYLOAD_FIELDS)


def verify_okf_answer(attestation: dict, vk: nacl.signing.VerifyKey) -> bool:
    return verify_attestation(attestation, vk, _OKF_ANSWER_PAYLOAD_FIELDS)


def append_okf_answer(attestation: dict, path: Path = OKF_ATTESTATION_LOG_PATH) -> None:
    append_attestation(attestation, path)  # REUSE attestation.append_attestation


def load_okf_answers(path: Path = OKF_ATTESTATION_LOG_PATH) -> list[dict]:
    return load_attestations(path)  # REUSE attestation.load_attestations


# ── the agent loop ────────────────────────────────────────────────────────────
def parse_answer_value(answer: str) -> Decimal | None:
    """The figure an answer presents, or None. Deliberately crude — see the
    module docstring's fail-open/fail-closed split.

    Two rules, both there to keep the check firing on substance rather than on
    prose. Thousands separators are stripped, because a model writes 1,234.56
    for a receipt value of 1234.56 and those are the same number. And a
    candidate carrying a decimal point wins over one without: an attested
    monetary figure has cents, while the bare integers in the same sentence are
    almost always years, counts, or list markers.

    KNOWN LIMIT, stated rather than papered over: an answer that states the
    correct figure AND an incorrect one is judged on whichever this picks. The
    check detects a SUBSTITUTED figure, which is the threat; it is not a proof
    that every number in the prose is attested.
    """
    candidates = _NUMBER_RE.findall(answer)
    if not candidates:
        return None
    chosen = next((c for c in candidates if "." in c), candidates[0])
    try:
        return Decimal(chosen.replace(",", ""))
    except InvalidOperation:
        return None


def _format_concept(c: dict) -> str:
    tier = c.get("_tier", "unverified")
    header = f"[{c['concept_id']}] ({c['type'] or 'Concept'} — {c['title']}, trust: {tier})"
    return f"{header}\n{c['body']}"


def run_agent(
    query: str,
    collection,
    embed_model,
    client,
    roots: dict,
    publisher_vk: nacl.signing.VerifyKey,
    keyring: dict[str, nacl.signing.VerifyKey],
    *,
    today: date,
    bundle_id: str | None = None,
    n_results: int = 5,
    min_tier: str = OKF_MIN_TIER,
    no_llm: bool = False,
    run_concept: str | None = None,
    params: dict[str, str] | None = None,
    service_sk: nacl.signing.SigningKey | None = None,
    service_key_id: str = "",
    log_path: Path = OKF_ATTESTATION_LOG_PATH,
    run_log_path: Path | None = None,
    model: str = LLM_MODEL,
) -> dict:
    """retrieve -> admit -> (optionally execute an attested computation) ->
    generate -> check citations -> attest.

    Returns a dict the CLI renders; raises nothing on a refusal, because a
    refusal is a normal outcome of this loop and the reasons are the product.

    When `run_concept` is given the loop closes the gap src.okf_attest's
    docstring names: the computation runs first (claimed_value_source
    "receipt", i.e. what the DATA says), its attested value goes into the
    model's context, and the number the model writes is then fed BACK to the
    bundle's own attester as `claimed_value` (source "caller", i.e. what the
    AGENT said). Until this loop existed, the attester's fidelity leg compared
    the receipt to itself and could not fail.
    """
    retrieved = retrieve_okf(query, collection, embed_model, roots, n_results=n_results, bundle_id=bundle_id)
    hits = retrieved["hits"]
    if not hits:
        return {"query": query, "decisions": [], "admitted": [], "answer": None, "served": False,
                "reasons": ["no concepts retrieved"], "warnings": [], "runs": []}

    resolved_bundle_id = bundle_id or hits[0]["bundle_id"]
    view = retrieved["bundles"][resolved_bundle_id]

    decisions = admit_all(
        hits, view, publisher_vk, keyring,
        today=today, min_tier=min_tier, bundle_id=resolved_bundle_id,
    )
    by_decision = {d["concept_id"]: d for d in decisions}
    admitted = [c for c in hits if by_decision[c["concept_id"]]["admitted"]]
    refused_ids = [d["concept_id"] for d in decisions if not d["admitted"]]
    warnings = [f"{d['concept_id']}: {w}" for d in decisions for w in d["warnings"]]

    result: dict[str, Any] = {
        "query": query,
        "bundle_id": resolved_bundle_id,
        "decisions": decisions,
        "admitted": admitted,
        "refused_concept_ids": refused_ids,
        "distances": retrieved["distances"],
        "warnings": warnings,
        "runs": [],
        "answer": None,
        "served": False,
        "reasons": [],
    }

    # Explicit execution step — never a side effect of retrieval.
    attested_value = None
    if run_concept is not None:
        if run_concept not in by_decision or not by_decision[run_concept]["admitted"]:
            result["reasons"].append(f"cannot run {run_concept!r}: it was not admitted")
            return result
        run = attest_run(
            view["bundle_path"], resolved_bundle_id, run_concept, params or {}, roots,
            publisher_vk, service_sk, service_key_id, keyring,
            **({"log_path": run_log_path} if run_log_path else {}),
        )
        result["runs"].append(run)
        if not run["ok"]:
            result["reasons"].append(f"attested computation refused: {run['reason']}")
            return result
        attested_value = run["receipt"]["result"][0]

    if no_llm or not admitted:
        if not admitted:
            result["reasons"].append("no concept survived admission")
        return result

    for c in admitted:  # tier shown to the model alongside each concept
        c["_tier"] = by_decision[c["concept_id"]]["tier"]
    question = query if attested_value is None else (
        f"{query}\n\n(The attested value of {run_concept} is {attested_value}. "
        f"State it exactly as given if you report it.)"
    )
    answer = generate(  # REUSE generate.generate, OKF prompts injected
        question, admitted, client,
        system_prompt=OKF_SYSTEM_PROMPT,
        template=OKF_USER_PROMPT_TEMPLATE,
        format_entry=_format_concept,
    )
    result["answer"] = answer

    cited, cited_refused = parse_concept_citations(
        answer, [c["concept_id"] for c in admitted], list(view["by_id"])
    )
    result["cited"] = cited
    if cited_refused:
        result["reasons"].append(f"answer cited refused concept(s): {', '.join(cited_refused)}")

    # The fidelity leg, made real: re-attest the number the MODEL wrote.
    if attested_value is not None:
        claimed = parse_answer_value(answer)
        if claimed is None:
            result["warnings"].append("no numeric value parsed from the answer — value-unattested")
        else:
            recheck = attest_run(
                view["bundle_path"], resolved_bundle_id, run_concept, params or {}, roots,
                publisher_vk, service_sk, service_key_id, keyring,
                claimed_value=float(claimed),
                **({"log_path": run_log_path} if run_log_path else {}),
            )
            result["runs"].append(recheck)
            if not recheck["ok"]:
                result["reasons"].append(
                    f"answer value {claimed} failed the bundle's attester: {recheck['reason']}"
                )

    result["served"] = not result["reasons"]

    if service_sk is not None:
        attestation = build_okf_answer_attestation(
            query, answer, admitted, refused_ids, resolved_bundle_id, model
        )
        signed = sign_okf_answer(attestation, service_sk, service_key_id)
        append_okf_answer(signed, log_path)
        result["attestation"] = signed
        logging.info("OKF answer attestation appended to %s", log_path)

    return result
