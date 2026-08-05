"""Attestation integrity AT THE RUN -- implements OKF SPEC's §12-deferred layer.

src/okf.py, src/okf_ingest.py, src/trust.py, and src/okf_verify.py answer
"are these BYTES what the publisher signed / what the claimed actor
attested to?" -- entirely at rest. This module answers a question nothing
upstream of it can: "what did THIS RUN actually execute, and under which
publisher-signed digests?"

The gap it closes is concrete. SPEC §10.5 has the executor run the in-bundle
`# Computation` and the attester re-derive from THAT SAME in-bundle
computation, so `executed == re-derived` holds even when both were swapped a
moment ago by a write-capable adversary -- native attestation returns PASS
over the attacker's SQL and the attacker's number. native_attest_run() below
implements §10.5 literally, as the measured baseline. attest_run() is the
alternative: it checks the ComputationPins signed at bundle-sign time
(src.okf_ingest.build_pins) BEFORE importing or executing anything, so a
swapped fence or a swapped attester is refused before either runs.

Three signing authorities now exist in this project:

    Authority   Key            Signs                         Answers
    ----------  -------------  ----------------------------  --------------------------------
    Publisher   publisher.sk   Merkle root + pins message     "is this bundle as published?"
    Actor       actors/*.sk    one sig per verified/generated "did THIS actor make this claim?"
    Service     service.sk     the run record + ITE-6 export  "what did THIS RUN execute?"

STAGE ORDER (attest_run short-circuits on the first failure; no bundle code
is imported and nothing executes once anything upstream is wrong):

    1. src.okf_verify.verify_bundle -- this concept's canonical hash, Merkle
       membership, and the publisher's root signature (all reused, unchanged)
    2. the EXECUTOR-SKILL concept (executor.resource, itself a Merkle leaf)
       must also be untampered -- nothing else in this project checks this.
       NOTE: because a Merkle proof reconstructs the root from FRESH
       sibling hashes (see verify_bundle's docstring), editing the skill
       concept's file on disk already breaks stage 1's proof for every
       OTHER concept too, so in practice this stage's distinct catch is a
       narrower case: the skill concept's own stored digest in okf_roots.json
       is wrong while the bundle files, root, and root signature are
       untouched (see tests/test_okf_attest.py::test_executor_skill_tamper_refused)
    3. src.okf_verify.check_pins -- pins signature, computation digest,
       attester digest, all against the publisher-signed pin
    4. parameter binding against the concept's declared `parameters:`
    5. runtime resolution (`runtime: bigquery` -> a registered executor;
       unknown runtime -> refuse). allow_exec=False stops here: a caller
       that wants "would this run be authorized" without executing anything
       gets stages 1-5 and nothing more.
    6. ONLY NOW: import the attester from the bundle (load_attester) and
       check its ABI
    7. execute -> receipt; validate the receipt against the concept's
       declared `executor.receipt` field list
    8. attest -> verdict
    9. build the run record, sign it under the SERVICE key, optionally
       export a DSSE ITE-6 Statement (src.intoto.sign_run_ite6_statement),
       append to the run log

The authenticated trust tier (src.trust.derive_authenticated_tier, reused
via verify_bundle's per-concept report) is RECORDED on the run but does NOT
gate it -- gating a run on tier/status/stale_after belongs to a future
admission-gate layer (an agent's retrieve -> verify -> admit loop), not this
module. Recording without enforcing keeps the seam between "what happened"
(this module) and "what an agent is allowed to act on" (that future layer)
explicit.

HONEST RESIDUALS -- stated here because the write-up will be checked against
this file, not around it:

  * ATTESTER EXECUTION. load_attester imports and RUNS the publisher's
    own code once its digest matches the publisher-signed pin. There is no
    sandbox, no timeout, no containment of import-time side effects. The pin
    authorizes the PUBLISHER's code; it does not mean a consumer should
    trust it unconditionally. This is exactly OKF §12's deferred "attester
    ABI and sandboxing" -- subprocess/seccomp isolation is a named next
    increment, not code in this module.
  * BOTH ATTESTER LEGS ARE PARTIALLY VACUOUS IN OUR OWN RUN. The
    executor is handed the PINNED bytes directly, so the attester's
    SQL-provenance check is trivially satisfied here -- it becomes
    meaningful once the executor is a real remote system that could rewrite
    the query in flight. Likewise `claimed_value` defaults to the receipt's
    own first cell (claimed_value_source="receipt"), so the fidelity leg is
    a no-op until a caller (a future agent, parsing a number out of an LLM
    answer) passes an independently-derived value
    (claimed_value_source="caller"). THE DIVISION OF LABOR: the pin defends
    against a lying BUNDLE; the attester defends against a lying EXECUTOR.
    Neither subsumes the other.
  * THE PIN IS STRICTER THAN THE ATTESTER. src.okf.canonical_computation_bytes
    (the pin's subject) only normalizes whitespace/NFC; the bundle's own
    attester additionally strips comments and uppercases keywords. A benign
    SQL-comment edit therefore refuses the run here (and, separately,
    changes the Merkle root) -- a documented v1 limit, not a false claim of
    equivalence.
"""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import nacl.signing

from src.config import OKF_RUN_VERSION, OKF_RUNS_PATH
from src.crypto import sign, verify
from src.okf import attester_bytes, canonical_computation_bytes, parse_bundle, pins_message, resolve_resource
from src.okf_exec import RUNTIMES, ParameterError, bind_parameters, canonical_params_json, validate_receipt
from src.okf_verify import check_pins, verify_bundle
from src.schema import ComputationPins, ConceptRecord, TrustAssessment


class AttesterLoadError(Exception):
    """Raised by load_attester when the pin check fails, the attester file
    is absent, import fails, or the loaded module's `attest` does not match
    the expected keyword-only ABI (sanctioned_sql, receipt, claimed_value)."""


def _refuse(stage: int, reason: str, **extra: Any) -> dict:
    return {"ok": False, "stage": stage, "reason": reason, **extra}


# ── attester import ──────────────────────────────────────────────────────────
_ATTESTER_ABI_PARAMS = frozenset({"sanctioned_sql", "receipt", "claimed_value"})


def _import_module_from_path(path: Path, modname: str):
    """Import `path` under an explicit, cache-keyed module name -- no
    sys.path mutation. `modname` MUST be derived from the attester's own
    content digest (see load_attester / _load_attester_unchecked) so a
    swapped file on disk can never reuse a stale cached module."""
    if modname in sys.modules:
        return sys.modules[modname]
    spec = importlib.util.spec_from_file_location(modname, path)
    if spec is None or spec.loader is None:
        raise AttesterLoadError(f"cannot load attester module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[modname] = module
    try:
        spec.loader.exec_module(module)
    except Exception as e:
        del sys.modules[modname]
        raise AttesterLoadError(f"attester import failed: {e}") from e
    return module


def _check_attester_abi(module) -> Callable | None:
    """Return the module's `attest` callable if it accepts the three
    keyword-only parameters OKF's own attester (attesters/sql_equality.py)
    uses, or **kwargs; else None. OKF does not prescribe this ABI -- it is
    discovered from the bundle -- so a mismatch is a named refusal, not a
    TypeError at call time."""
    attest_fn = getattr(module, "attest", None)
    if not callable(attest_fn):
        return None
    params = inspect.signature(attest_fn).parameters
    has_var_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
    if has_var_kwargs or _ATTESTER_ABI_PARAMS.issubset(params.keys()):
        return attest_fn
    return None


def load_attester(
    concept: ConceptRecord,
    bundle_path: Path,
    pins_rec: ComputationPins | None,
    bundle_id: str,
    publisher_vk: nacl.signing.VerifyKey,
) -> Callable:
    """Pin-check, THEN import, THEN ABI-check a concept's attester -- the
    only path in this project that imports code from an untrusted bundle.

    Self-contained: re-runs check_pins even though attest_run already ran it
    upstream, so this function is safe to call directly (as a test, or a
    future caller, might) without relying on an outer ordering it can't see.
    Raises AttesterLoadError naming the exact failure; never returns a
    partially-loaded module.
    """
    tampered, reason = check_pins(concept, bundle_path, pins_rec, bundle_id, publisher_vk)
    if tampered:
        raise AttesterLoadError(reason)

    att = attester_bytes(bundle_path, concept)
    if att is None:
        raise AttesterLoadError("concept declares no attester")
    _, ref = att
    path = resolve_resource(bundle_path, ref)
    if path is None:
        raise AttesterLoadError(f"attester resource {ref!r} is not a bundle-local file")

    modname = f"okf_attester_{pins_rec['attester_sha256'][:12]}"  # pins_rec is non-None: check_pins passed
    module = _import_module_from_path(path, modname)
    attest_fn = _check_attester_abi(module)
    if attest_fn is None:
        del sys.modules[modname]
        raise AttesterLoadError("attester ABI mismatch")
    return attest_fn


def _load_attester_unchecked(bundle_path: Path, concept: ConceptRecord) -> Callable | None:
    """Import a concept's attester with NO pin check -- used only by
    native_attest_run to model SPEC §10.5 literally (the attester re-derives
    from whatever is on disk right now, full stop). Never call this from a
    consumer path; see load_attester for the checked version."""
    att = attester_bytes(bundle_path, concept)
    if att is None:
        return None
    raw, ref = att
    path = resolve_resource(bundle_path, ref)
    if path is None:
        return None
    digest = hashlib.sha256(raw).hexdigest()
    module = _import_module_from_path(path, f"okf_attester_native_{digest[:12]}")
    return _check_attester_abi(module)


# ── run record: build, sign, verify, log ──────────────────────────────────────
_RUN_PAYLOAD_FIELDS = (
    "run_version", "bundle_id", "concept_id", "concept_sha256", "merkle_root",
    "computation_sha256", "attester_sha256", "attester_resource", "executor_resource",
    "runtime", "params_sha256", "receipt_sha256", "verdict_ok", "verdict_reason",
    "claimed_value", "claimed_value_source", "authenticated_tier", "status", "stale_after",
    "timestamp",
)


def build_run_record(
    bundle_id: str,
    concept: ConceptRecord,
    pins_rec: ComputationPins,
    executor_resource: str,
    runtime: str,
    bound_params: dict[str, Any],
    receipt: dict,
    verdict: dict,
    claimed_value: Any,
    claimed_value_source: str,
    trust: TrustAssessment,
    merkle_root: str,
) -> dict:
    """Unsigned run record (missing run_sha256/service_signature/service_key_id --
    see sign_run). `params`/`receipt` are stored in full for the log; only
    their digests (params_sha256/receipt_sha256) enter the signed payload,
    so the canonical payload stays flat JSON regardless of parameter types."""
    params_json = canonical_params_json(bound_params)
    receipt_json = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    return {
        "run_version": OKF_RUN_VERSION,
        "bundle_id": bundle_id,
        "concept_id": concept["concept_id"],
        "concept_sha256": concept["sha256"],
        "merkle_root": merkle_root,
        "computation_sha256": pins_rec.get("computation_sha256", ""),
        "attester_sha256": pins_rec.get("attester_sha256", ""),
        "attester_resource": pins_rec.get("attester_resource", ""),
        "executor_resource": executor_resource,
        "runtime": runtime,
        "params": json.loads(params_json),  # JSON-round-tripped: dates -> ISO strings
        "params_sha256": hashlib.sha256(params_json.encode()).hexdigest(),
        "receipt": receipt,
        "receipt_sha256": hashlib.sha256(receipt_json.encode()).hexdigest(),
        "verdict_ok": bool(verdict.get("ok")),
        "verdict_reason": verdict.get("reason"),
        "claimed_value": claimed_value,
        "claimed_value_source": claimed_value_source,
        "authenticated_tier": trust["tier"],
        "status": str(concept["frontmatter"].get("status", "")),
        "stale_after": str(concept["frontmatter"].get("stale_after", "")),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _canonical_run_payload(record: dict) -> bytes:
    """Same shape as src.attestation._canonical_payload: a fixed field
    tuple, sorted-key JSON, no whitespace. Excludes `params`/`receipt` (the
    raw values) -- only their digests are signed -- and excludes
    run_sha256/service_signature/service_key_id, which are computed FROM
    this payload, not part of it."""
    payload = {field: record[field] for field in _RUN_PAYLOAD_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign_run(record: dict, service_sk: nacl.signing.SigningKey, key_id: str) -> dict:
    """Return a copy of `record` with run_sha256/service_signature/service_key_id
    set. Mirrors src.merkle's sign-over-the-hex-digest convention (sign over
    bytes.fromhex(root_hex)), not src.attestation's sign-over-raw-JSON
    convention -- chosen so verify_run's first check (recompute the payload,
    compare run_sha256) is a pure-hash comparison, cheap enough to run before
    ever touching the signature."""
    run_sha256 = hashlib.sha256(_canonical_run_payload(record)).hexdigest()
    signature = sign(service_sk, bytes.fromhex(run_sha256))
    return {**record, "run_sha256": run_sha256, "service_signature": signature, "service_key_id": key_id}


def verify_run(
    entry: dict,
    service_vk: nacl.signing.VerifyKey,
    publisher_vk: nacl.signing.VerifyKey | None = None,
    pins_rec: ComputationPins | None = None,
) -> tuple[bool, list[str]]:
    """Re-verify a logged run record. Library function -- no printing;
    verify.py's --okf-run mode (a later pass) is the seam this feeds.

    Three independent checks, each optional given what the caller has on
    hand: (1) the service signature over the canonical payload -- always
    run; (2) the run's claimed computation/attester digests against the
    PUBLISHER-signed pin (given `pins_rec`) -- catches a run record whose
    digests were never actually authorized; (3) the DSSE ITE-6 envelope
    signature (given `entry['ite6']` and the `intoto` extra is installed).
    """
    reasons: list[str] = []

    recomputed = hashlib.sha256(_canonical_run_payload(entry)).hexdigest()
    if recomputed != entry.get("run_sha256"):
        reasons.append("run record hash mismatch")
    elif not verify(service_vk, bytes.fromhex(entry["run_sha256"]), entry.get("service_signature", "")):
        reasons.append("service signature invalid")

    if pins_rec is not None and publisher_vk is not None:
        msg = pins_message(
            entry["bundle_id"], entry["concept_id"], pins_rec.get("computation_sha256", ""), pins_rec.get("attester_sha256", "")
        )
        if not verify(publisher_vk, msg, pins_rec.get("pins_signature", "")):
            reasons.append("pins signature invalid")
        if entry.get("computation_sha256") != pins_rec.get("computation_sha256"):
            reasons.append("run computation digest does not match publisher-signed pin")
        if entry.get("attester_sha256") != pins_rec.get("attester_sha256"):
            reasons.append("run attester digest does not match publisher-signed pin")

    if entry.get("ite6"):
        try:
            from src.intoto import verify_real_ite6_statement

            if not verify_real_ite6_statement(entry["ite6"], service_vk, entry["service_key_id"]):
                reasons.append("ITE-6 envelope signature invalid")
        except ImportError:
            pass  # optional extra not installed -- not itself a failure

    return (len(reasons) == 0, reasons)


def append_run(entry: dict, path: Path = OKF_RUNS_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def load_runs(path: Path = OKF_RUNS_PATH) -> list[dict]:
    """Load every run from the append-only log, mirroring
    src.attestation.load_attestations: skip and warn on a malformed line
    rather than failing the whole load."""
    if not path.exists():
        return []
    entries = []
    for i, line in enumerate(path.read_text().splitlines()):
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            print(f"WARNING: skipping malformed line {i} in {path} (corrupt or truncated write)")
    return entries


# ── the two runs: pin-gated (real) and native (baseline) ───────────────────
def attest_run(
    bundle_path: Path,
    bundle_id: str,
    concept_id: str,
    params: dict[str, str],
    roots: dict,
    publisher_vk: nacl.signing.VerifyKey,
    service_sk: nacl.signing.SigningKey,
    service_key_id: str,
    keyring: dict[str, nacl.signing.VerifyKey],
    *,
    claimed_value: Any = None,
    allow_exec: bool = True,
    executor: Callable[[str, dict, ConceptRecord], dict] | None = None,
    log_path: Path = OKF_RUNS_PATH,
    build_ite6: bool = True,
) -> dict:
    """Run stages 1-9 of the module docstring's ordered gate; short-circuits
    on the first failure with {"ok": False, "stage": <1..8>, "reason": str}.
    On success (or on allow_exec=False stopping cleanly after stage 5)
    returns {"ok": bool, "stage": 5 or 9, "reason", "trust", ...}.

    `executor` overrides RUNTIMES[runtime] -- the hook tests use to spy on
    whether execution was reached at all.
    """
    bundle_entry = roots.get(bundle_id)
    if bundle_entry is None:
        return _refuse(1, f"no signed record for bundle {bundle_id!r}")

    try:
        concepts = parse_bundle(bundle_path, bundle_id)
    except ValueError as e:
        return _refuse(1, f"bundle parse failed: {e}")

    # Stage 1: this concept's canonical hash / Merkle membership / root signature.
    report = verify_bundle(bundle_path, bundle_id, roots, publisher_vk, keyring, concepts=concepts)
    concept_report = next((c for c in report["concepts"] if c["concept_id"] == concept_id), None)
    if concept_report is None:
        return _refuse(1, f"concept not found in bundle: {concept_id}")
    if concept_report["tampered"]:
        return _refuse(1, concept_report["reason"], trust=concept_report["trust"])

    concept = next(c for c in concepts if c["concept_id"] == concept_id)
    trust = concept_report["trust"]

    # Stage 2: the executor-skill concept (also a Merkle leaf) must be untampered.
    executor_field = concept["frontmatter"].get("executor")
    executor_resource = executor_field.get("resource", "") if isinstance(executor_field, dict) else ""
    if executor_resource.endswith(".md"):
        executor_concept_id = executor_resource[: -len(".md")]
        executor_report = next((c for c in report["concepts"] if c["concept_id"] == executor_concept_id), None)
        if executor_report is None or executor_report["tampered"]:
            reason = executor_report["reason"] if executor_report else "executor skill concept not found in bundle"
            return _refuse(2, f"executor skill concept tampered: {reason}", trust=trust)

    # Stage 3: pins -- computation + attester digests against the publisher-signed pin.
    pins_index = {p["concept_id"]: p for p in bundle_entry.get("computation_pins", [])}
    pins_rec = pins_index.get(concept_id)
    pin_tampered, pin_reason = check_pins(concept, bundle_path, pins_rec, bundle_id, publisher_vk)
    if pin_tampered:
        return _refuse(3, pin_reason, trust=trust)

    # Stage 4: parameter binding against the concept's declared `parameters:`.
    try:
        bound_params = bind_parameters(concept, params)
    except ParameterError as e:
        return _refuse(4, str(e), trust=trust)

    # Stage 5: runtime resolution.
    runtime = str(concept["frontmatter"].get("runtime", ""))
    executor_fn = executor or RUNTIMES.get(runtime)
    if executor_fn is None:
        return _refuse(5, f"unknown runtime {runtime!r}", trust=trust)

    if not allow_exec:
        return {
            "ok": True,
            "executed": False,
            "stage": 5,
            "reason": "pins verified; execution skipped (allow_exec=False)",
            "trust": trust,
        }

    # Stage 6: import + ABI-check the attester -- the first point any bundle code runs.
    try:
        attest_fn = load_attester(concept, bundle_path, pins_rec, bundle_id, publisher_vk)
    except AttesterLoadError as e:
        return _refuse(6, str(e), trust=trust)

    sql_bytes = canonical_computation_bytes(concept, bundle_path)
    if sql_bytes is None:
        return _refuse(7, "concept has no computation", trust=trust)
    sql = sql_bytes.decode("utf-8")

    # Stage 7: execute -> receipt.
    try:
        receipt = executor_fn(sql, bound_params, concept)
    except Exception as e:
        return _refuse(7, f"executor raised: {e}", trust=trust)
    if not isinstance(receipt, dict):
        return _refuse(7, "executor returned malformed receipt", trust=trust)
    missing = validate_receipt(concept, receipt)
    if missing:
        return _refuse(7, missing, trust=trust)

    receipt_value = receipt["result"][0] if isinstance(receipt.get("result"), list) else receipt.get("result")
    cv = claimed_value if claimed_value is not None else receipt_value
    cv_source = "caller" if claimed_value is not None else "receipt"

    # Stage 8: attest -> verdict.
    try:
        verdict = attest_fn(sanctioned_sql=sql, receipt=receipt, claimed_value=cv)
    except Exception as e:
        return _refuse(8, f"attester raised: {e}", trust=trust)
    if not isinstance(verdict, dict) or "ok" not in verdict:
        return _refuse(8, "attester returned malformed verdict", trust=trust)

    # Stage 9: build, sign, (optionally) export ITE-6, log.
    merkle_root = bundle_entry["bundle"]["merkle_root"]
    record = build_run_record(
        bundle_id, concept, pins_rec, executor_resource, runtime, bound_params,
        receipt, verdict, cv, cv_source, trust, merkle_root,
    )
    signed = sign_run(record, service_sk, service_key_id)

    ite6 = None
    if build_ite6:
        try:
            from src.intoto import sign_run_ite6_statement

            ite6 = sign_run_ite6_statement(signed, service_sk, service_key_id)
        except ImportError:
            ite6 = None  # optional `intoto` extra not installed -- the native signature above is not optional

    entry = {**signed, "ite6": ite6}
    append_run(entry, path=log_path)

    return {
        "ok": bool(verdict.get("ok")),
        "stage": 9,
        "reason": verdict.get("reason") or "verified",
        "trust": trust,
        "receipt": receipt,
        "verdict": verdict,
        "run": entry,
    }


def native_attest_run(
    bundle_path: Path,
    bundle_id: str,
    concept_id: str,
    params: dict[str, str],
    *,
    executor: Callable[[str, dict, ConceptRecord], dict] | None = None,
) -> dict:
    """Model SPEC §10.5 LITERALLY -- the unprotected baseline attest_run is
    measured against, not a consumer path. Re-reads the `# Computation`
    fence AND the attester from disk right now, with NO pin check, NO root
    check, and NO signature of any kind: `executed == re-derived` holds
    trivially even against a fence a write-capable adversary swapped a
    moment ago. Returns {"ok"/"reason"/"receipt"/"verdict", "native": True}.
    MUST NOT be used as a consumer path -- see attest_run.
    """
    concepts = parse_bundle(bundle_path, bundle_id)
    concept = next((c for c in concepts if c["concept_id"] == concept_id), None)
    if concept is None:
        return {"ok": False, "reason": f"concept not found: {concept_id}", "native": True}

    try:
        bound_params = bind_parameters(concept, params)
    except ParameterError as e:
        return {"ok": False, "reason": str(e), "native": True}

    runtime = str(concept["frontmatter"].get("runtime", ""))
    executor_fn = executor or RUNTIMES.get(runtime)
    if executor_fn is None:
        return {"ok": False, "reason": f"unknown runtime {runtime!r}", "native": True}

    sql_bytes = canonical_computation_bytes(concept, bundle_path)
    if sql_bytes is None:
        return {"ok": False, "reason": "concept has no computation", "native": True}
    sql = sql_bytes.decode("utf-8")

    try:
        receipt = executor_fn(sql, bound_params, concept)
    except Exception as e:
        return {"ok": False, "reason": f"executor raised: {e}", "native": True}
    missing = validate_receipt(concept, receipt)
    if missing:
        return {"ok": False, "reason": missing, "native": True}

    attest_fn = _load_attester_unchecked(bundle_path, concept)
    if attest_fn is None:
        return {"ok": False, "reason": "attester ABI mismatch or missing", "native": True}

    claimed_value = receipt["result"][0] if isinstance(receipt.get("result"), list) else receipt.get("result")
    try:
        verdict = attest_fn(sanctioned_sql=sql, receipt=receipt, claimed_value=claimed_value)
    except Exception as e:
        return {"ok": False, "reason": f"attester raised: {e}", "native": True}

    return {
        "ok": bool(verdict.get("ok")),
        "reason": verdict.get("reason") or "verified",
        "receipt": receipt,
        "verdict": verdict,
        "claimed_value": claimed_value,
        "native": True,
    }


# ── CLI ──────────────────────────────────────────────────────────────────────
def _parse_params(pairs: list[str]) -> dict[str, str]:
    params: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            raise SystemExit(f"--param must be KEY=VALUE, got {pair!r}")
        key, _, value = pair.partition("=")
        params[key] = value
    return params


def main() -> int:
    import argparse
    import json as _json

    from src.config import (
        ACTOR_KEYRING_PATH,
        OKF_ROOTS_PATH,
        PUBLISHER_VERIFY_KEY_PATH,
        SERVICE_KEY_ID,
        SERVICE_SIGNING_KEY_PATH,
    )
    from src.crypto import load_signing_key, load_verify_key
    from src.trust import load_keyring

    parser = argparse.ArgumentParser(
        description="Attest one OKF Attested-Computation run: pin-gated (default) or the "
        "native SPEC-§10.5 baseline (--native)."
    )
    parser.add_argument("bundle_path", help="path to the bundle root, e.g. bundles/acme_retail")
    parser.add_argument("concept_id", help="concept id of the Attested Computation, e.g. computations/revenue-ytd")
    parser.add_argument("--bundle-id", help="defaults to the bundle directory name")
    parser.add_argument("--param", action="append", default=[], metavar="KEY=VALUE", help="repeatable")
    parser.add_argument(
        "--native", action="store_true",
        help="run the UNPROTECTED SPEC-§10.5 baseline (native_attest_run) instead of the pin-gated attest_run",
    )
    parser.add_argument(
        "--no-exec", action="store_true",
        help="stop after pin verification (stage 5); do not import the attester or execute anything",
    )
    parser.add_argument("--out", metavar="PATH", help="write the DSSE ITE-6 envelope to this file")
    parser.add_argument("--json", action="store_true", help="print the full result as JSON instead of a summary")
    args = parser.parse_args()

    bundle_path = Path(args.bundle_path)
    if not bundle_path.is_dir():
        raise SystemExit(f"bundle path not found: {bundle_path}")
    bundle_id = args.bundle_id or bundle_path.name
    params = _parse_params(args.param)

    if args.native:
        print("=" * 70)
        print("THIS IS THE UNPROTECTED BASELINE (SPEC §10.5, no pins, no signature)")
        print("=" * 70)
        result = native_attest_run(bundle_path, bundle_id, args.concept_id, params)
        if args.json:
            print(_json.dumps(result, indent=2, default=str))
        else:
            mark = "✅ PASS" if result["ok"] else "❌ REFUSED"
            print(f"[native] {mark} -- {result['reason']}")
            if result.get("receipt"):
                print(f"  executed value: {result['receipt']['result']}")
        return 0 if result["ok"] else 1

    try:
        publisher_vk = load_verify_key(PUBLISHER_VERIFY_KEY_PATH)
        service_sk = load_signing_key(SERVICE_SIGNING_KEY_PATH)
    except FileNotFoundError as e:
        raise SystemExit(f"Missing key: {e}. Run `uv run python scripts/generate_keys.py` first.")

    keyring = load_keyring(ACTOR_KEYRING_PATH)
    roots = _json.loads(OKF_ROOTS_PATH.read_text()) if OKF_ROOTS_PATH.exists() else {}
    if not roots:
        print(f"WARNING: {OKF_ROOTS_PATH} not found or empty -- every stage-1 check below will refuse.\n")

    result = attest_run(
        bundle_path, bundle_id, args.concept_id, params, roots, publisher_vk, service_sk, SERVICE_KEY_ID,
        keyring, allow_exec=not args.no_exec,
    )

    if args.json:
        print(_json.dumps(result, indent=2, default=str))
    else:
        mark = "✅ PASS" if result["ok"] else "❌ REFUSED"
        print(f"[stage {result.get('stage')}] {mark} -- {result['reason']}")
        if result.get("trust"):
            t = result["trust"]
            print(f"  authenticated tier: {t['tier']} (claimed: {t['claimed_tier']})")
        if result.get("receipt"):
            print(f"  executed value: {result['receipt']['result']}")
        if result.get("run", {}).get("ite6") and args.out:
            Path(args.out).write_text(_json.dumps(result["run"]["ite6"], indent=2))
            print(f"  ITE-6 envelope written to {args.out}")

    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
