# OKF compatibility

This project pins itself to a specific version of the [Open Knowledge Format
(OKF)](https://github.com/GoogleCloudPlatform/knowledge-catalog) spec rather than tracking it
continuously. This page records what's assumed, so a compatibility review is a quick diff against
these bullets rather than a re-read of the spec.

- **Supported OKF version**: v0.2.
- **Date last checked**: 2026-08-30.
- **Vendored sample bundle**: [`bundles/acme_retail`](../bundles/acme_retail), vendored verbatim from
  the upstream OKF repository at commit `3fcbb9f`
  ([`bundles/UPSTREAM.json`](../bundles/UPSTREAM.json)).

## Assumptions this project makes about OKF v0.2

- **`verified` semantics (§5.3)**: trust-tier frontmatter (`verified: {by: ..., at: ...}`) is an
  *advisory signal*, not access control, exactly as the spec states. This project's contribution is
  binding each claim to a signature from the actor it names (`src/trust.py`), authenticating the
  signal without changing what the spec itself promises about it.
- **Actor identity**: an actor is identified by the string in `verified.by` /
  `generated.by` (`"human:jsmith@acme"`, `"process:finance-nightly"`, `"<producer>/<version>"`, per
  §7's convention). This project assumes those strings are stable identifiers, and separately
  maintains its own keyring (`data/keys/actors/keyring.json`) mapping them to Ed25519 keys — OKF
  itself does not standardize key material or distribution.
- **Freshness/lifecycle**: `stale_after` and `status` (deprecated) are read as the spec defines them;
  no additional lifecycle states are assumed. There is no snapshot/rollback-protection role — an old,
  authentically signed bundle still verifies (see [docs/THREAT_MODEL.md](THREAT_MODEL.md)).
- **Attested Computation**: the `# Computation` fence / `computation:` file and its named attester
  resource are treated as the two artifacts that must be pinned (hashed and signed) at bundle-sign
  time. This project assumes an Attested Computation names exactly one attester.
- **Executor/attester semantics**: OKF v0.2 does not standardize an executor ABI, sandboxing, or
  portability (§12 lists this as deliberately deferred). This project's executor
  (`src/okf_exec.py`) is a simulated, in-process stand-in with no live warehouse — not a reference
  implementation of a future OKF executor protocol.
- **Runtime protocol**: OKF v0.2 standardizes frontmatter, not a consumption-time runtime (§12). This
  project's enforcement layer (`src/enforce.py`) is an implementation of one possible runtime built on
  top of v0.2 frontmatter, not a claim about what a future OKF runtime protocol will look like.

## Known specification ambiguities

- The spec does not define how a verifier should treat a `verified` entry whose named actor is absent
  from the verifier's own keyring. This project treats that case as `unknown_actor` (see
  `TrustAssessment` in `src/schema.py`) — a downgrade, not a hard failure, since keyring completeness
  is a local-trust-store concern OKF doesn't address.
- The spec does not define canonical byte-level hashing for a concept file. This project's
  `okf-concept/v1` canonicalization (`src/okf.py`) is this project's own convention, not one drawn
  from the spec — see the README's "Canonicalization" section for exactly what it does and does not
  survive.

## What triggers a re-review

Only these categories are worth monitoring in OKF's changelog/discussions; everything else (tooling,
formatting, unrelated goals) can be ignored:

- `verified` / trust-tier semantics
- actor identity conventions
- lifecycle/freshness fields
- Attested Computation structure
- executor/attester semantics
- runtime receipts, verdicts, or any future runtime protocol

A short compatibility pass (re-read the changed sections, diff against the bullets above) is enough —
this doesn't need a full spec re-read each time.
