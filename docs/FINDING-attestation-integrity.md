# Finding: OKF's native attestation loop re-derives its verdict from the same artifacts an adversary just edited

**Status**: an aligned contribution to a layer OKF §12 explicitly defers, not a defect report against
the spec. **Severity, in this project's own terms**: high against a write-capable adversary on an
Attested Computation, and structurally undetectable by every check upstream of it.

## The mechanism (SPEC §10.5)

OKF v0.2's Attested Computation flow is: an executor runs the in-bundle `# Computation` (SQL or
similar), and an *attester* — code named by the concept's `attester.resource` field — re-derives a
verdict by checking the executor's result against the same in-bundle computation. §10.5 describes this
literally: the attester's job is to confirm `executed == re-derived`.

[`src/okf_attest.py`](../src/okf_attest.py)'s `native_attest_run()` implements exactly this, as the
measured, unprotected baseline this project's own `attest_run()` is compared against — not a consumer
path. It re-reads the computation fence and imports the attester **from disk, right now**, with no pin
check, no root check, and no signature verification of any kind.

## Why that fails a write-capable adversary

The attester module (e.g. `attesters/sql_equality.py`) is Python, not a `.md` file. It is not parsed by
`src.okf.parse_bundle`, so it is **never a Merkle leaf** — no concept digest, and therefore no bundle
root, moves when it is edited. Every at-rest check this project has upstream of `okf_attest.py`
(`src.okf_verify.verify_bundle`: canonical hash, Merkle membership, root signature) stays fully green
against a tampered attester, because none of them ever look at that file.

`native_attest_run()` re-imports and trusts whatever attester code is on disk at call time. If that
code was replaced a moment ago, its own re-derivation runs over the attacker's version too —
`executed == re-derived` holds *trivially*, because both sides of the comparison are now the
adversary's. The check cannot fail by construction: it was never given an independent reference to
compare against.

## The demo (`scripts/demo.sh --act 1`, `scripts/tamper_okf.py swap-attester`)

`swap_attester()` overwrites the attester file in place with an always-pass stub:

```python
def attest(*, sanctioned_sql, receipt, claimed_value, **kwargs):
    return {"ok": True, "reason": None, "details": {"tampered": True, "note": "always-pass attester"}}
```

Before/after walkthrough on `bundles/acme_retail`'s `computations/revenue-ytd`:

1. **Swap the attester file.** `attesters/sql_equality.py` is overwritten. No concept digest changes,
   no Merkle leaf changes, the signed root is untouched.
2. **Native §10.5 attestation accepts it.**
   ```bash
   uv run python -m src.okf_attest bundles/acme_retail computations/revenue-ytd --param year=2026 --native
   ```
   returns `ok: True` — the always-pass stub re-derives against itself and reports success on
   whatever the executor returned.
3. **The publisher-signed attester pin refuses it.**
   ```bash
   uv run python -m src.okf_attest bundles/acme_retail computations/revenue-ytd --param year=2026
   ```
   `attest_run()` checks `ComputationPins.attester_sha256` — a digest over the attester's raw bytes,
   signed by the publisher at bundle-sign time (`src.okf_ingest.build_pins`) — **before** the attester
   module is imported or the executor runs. The swapped file's hash no longer matches the pin, so the
   run is refused before either side ever executes. This ordering is the actual control: a refusal
   issued after the bundle's code has already run is not one.
4. **The at-rest verifier still reports the swap as `[5] Computation pins ... ❌`**, and nothing else
   in the report moves — `[1]`–`[4]` stay green, because they were never checking this surface either.
   That divergence — everything upstream green, only the pin check red — is the figure this finding is
   about.

## Why this is an aligned contribution, not a defect report

OKF v0.2 §12's *Considered and deferred* list names "the attester ABI, portability, and sandboxing" and
"the full runtime protocol" explicitly. §10.5's re-derivation loop is not a bug in the spec; it is
what the spec currently defines, scoped to what it set out to standardize (frontmatter and
declarative structure, not a verified execution runtime). This project's `ComputationPins` — hash and
sign the computation *and* the attester at publish time, verify both before either runs — is one
concrete answer to a question §12 leaves open, offered as a runtime consumer might implement it, not
as a change OKF itself needs to make.

## What this does and does not close

**Closes**: attester substitution and computation-fence substitution by a write-capable adversary
between publish and run, for a runtime that adopts pin-before-import as its execution discipline.

**Does not close** (see [docs/THREAT_MODEL.md](THREAT_MODEL.md)):
- sandboxing of the executor/attester once the pin check passes — both still run in-process;
- a malicious but *correctly signed* attester (the publisher's own bad-faith code passes its own pin);
- key compromise — a stolen publisher key can re-pin an attacker's attester exactly as validly as the
  real one;
- any executor ABI or runtime protocol beyond this project's own simulated in-process executor
  (`src/okf_exec.py`).
