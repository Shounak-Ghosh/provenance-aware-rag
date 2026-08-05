"""SIMULATED runtime execution for OKF Attested Computations.

Quarantined in its own module, on purpose: everything in src/okf_attest.py is
real cryptography (pin verification, ITE-6 signing) and real policy (the
refuse-before-execute ordering). Nothing in *this* file is real data --
simulated_bigquery_executor() never touches BigQuery, or any network. The
NUMBER IT RETURNS IS FAKE.

What IS real: the returned value is a deterministic, pure function of the
exact SQL string it was handed (plus the bound parameters). That is the one
property the Day-3 demo needs -- a fence-swapped bundle produces a visibly
DIFFERENT number under src.okf_attest.native_attest_run(), which is what
turns "the spec defers this" into a reproducible finding instead of a
diagram. Swap this module for a real skills/run-on-bq.md executor (a real
BigQuery client keyed off `runtime: bigquery`) without touching anything in
src/okf_attest.py -- RUNTIMES is the only seam that needs to grow.
"""
from __future__ import annotations

import datetime
import hashlib
import json
from typing import Any, Callable

from src.schema import ConceptRecord, RunReceipt

# Per skills/run-on-bq.md step 2: "Do NOT string-interpolate; the attester
# will reject a receipt whose executed_sql shows literal substitution" --
# so bound parameter VALUES never appear inside `executed_sql`; only the
# already-canonicalized SQL (with @name placeholders intact) does.


class ParameterError(ValueError):
    """A concept's declared `parameters:` could not be satisfied by the caller-supplied values."""


_COERCERS: dict[str, Callable[[str], Any]] = {
    "integer": int,
    "float": float,
    "string": str,
    "boolean": lambda v: v.strip().lower() in ("true", "1", "yes"),
    "date": lambda v: datetime.date.fromisoformat(v),
}


def bind_parameters(concept: ConceptRecord, raw: dict[str, str]) -> dict[str, Any]:
    """Coerce caller-supplied string values against a concept's declared `parameters:`.

    Every required parameter must be present and coercible to its declared
    `type`; every supplied key must be declared (an unknown parameter is
    refused, not silently ignored -- an attacker-controlled extra parameter
    should never reach an executor). Raises ParameterError naming the exact
    parameter for every failure mode, so src.okf_attest can surface a
    specific refusal reason rather than a bare exception.
    """
    declared = {p["name"]: p for p in concept["frontmatter"].get("parameters", []) if isinstance(p, dict)}

    unknown = sorted(set(raw) - set(declared))
    if unknown:
        raise ParameterError(f"unknown parameter(s): {', '.join(unknown)}")

    bound: dict[str, Any] = {}
    for name, spec in declared.items():
        if name not in raw:
            if spec.get("required", False):
                raise ParameterError(f"missing required parameter '{name}'")
            continue
        ptype = str(spec.get("type", "string"))
        coerce = _COERCERS.get(ptype)
        if coerce is None:
            raise ParameterError(f"parameter '{name}': unsupported declared type '{ptype}'")
        try:
            bound[name] = coerce(raw[name])
        except (ValueError, TypeError) as e:
            raise ParameterError(f"parameter '{name}': cannot coerce {raw[name]!r} to {ptype}") from e
    return bound


def canonical_params_json(params: dict[str, Any]) -> str:
    """Deterministic JSON for a bound-parameter dict -- used both to feed the
    simulated executor's digest and as the RunRecord.params_sha256 subject.
    `datetime.date` values (from a `type: date` parameter) are not natively
    JSON-serializable; collapse them to ISO strings here, the one place both
    the digest and the signed record read from."""
    return json.dumps(
        {k: (v.isoformat() if isinstance(v, datetime.date) else v) for k, v in params.items()},
        sort_keys=True,
        separators=(",", ":"),
    )


def simulated_bigquery_executor(sql: str, params: dict[str, Any], concept: ConceptRecord) -> RunReceipt:
    """Deterministic stand-in for skills/run-on-bq.md. SIMULATED -- no real
    query runs anywhere. The result value is derived from sha256(sql |
    canonical params), so identical SQL + params always reproduce the same
    receipt, and different SQL (e.g. an attacker's swapped `# Computation`
    fence) always produces a different result -- the property the fence-swap
    demo depends on.

    executed_sql echoes `sql` VERBATIM (bind placeholders left symbolic),
    exactly as skills/run-on-bq.md step 2 requires of a real executor.
    """
    digest = hashlib.sha256(sql.encode("utf-8") + b"|" + canonical_params_json(params).encode("utf-8")).hexdigest()
    value = round(int(digest[:10], 16) % 10_000_000 / 100, 2)
    return {
        "job_id": f"bq://simulated/us/{digest[:12]}",
        "executed_sql": sql,
        "result": [value],
    }


RUNTIMES: dict[str, Callable[[str, dict[str, Any], ConceptRecord], RunReceipt]] = {
    "bigquery": simulated_bigquery_executor,
}


def validate_receipt(concept: ConceptRecord, receipt: dict[str, Any]) -> str | None:
    """Return a refusal reason if `receipt` is missing a field the concept's
    own `executor.receipt` frontmatter declares, else None. Checkable purely
    from the concept -- no executor-specific knowledge needed here."""
    executor = concept["frontmatter"].get("executor")
    declared = executor.get("receipt", []) if isinstance(executor, dict) else []
    for field in declared:
        if field not in receipt:
            return f"receipt missing declared field '{field}'"
    return None
