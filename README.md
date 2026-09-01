# OKF-Verify

[![CI](https://github.com/Shounak-Ghosh/provenance-aware-rag/actions/workflows/ci.yml/badge.svg)](https://github.com/Shounak-Ghosh/provenance-aware-rag/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Shounak-Ghosh/provenance-aware-rag/badge)](https://scorecard.dev/viewer/?uri=github.com/Shounak-Ghosh/provenance-aware-rag)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Cryptographically enforceable trust for [OKF](https://github.com/GoogleCloudPlatform/knowledge-catalog)
v0.2 knowledge bundles — checked at the moment an agent consumes a concept, not at rest.**

OKF standardizes the frontmatter that makes an agent-maintained corpus trustable: who verified a
concept, when, what it derives from, when it goes stale, and which SQL is sanctioned for a metric.
Those signals are plain YAML. `verified: {by: human:alice}` is a string that anyone with write
access can type, and the spec is candid about it — §5.3 calls trust tiers "advisory signals, not
access control," and §12 lists the runtime protocol and attester integrity as work deliberately
deferred to a future revision.

This project builds that deferred layer on a bundle in transit between organizations. Every trust
signal becomes a signature: per-concept digests under a publisher key, each `verified` entry under
the key of the actor who claims it, and the sanctioned computation and its attester pinned by digest
before either is allowed to run. An agent then verifies at the point of use — a concept that fails
any check never reaches the model's context, and the refusal names its reason.

It also demonstrates why the run needs pinning: **OKF's native attestation loop re-derives its
verdict from the same in-bundle artifacts an adversary just edited.** See
[docs/FINDING-attestation-integrity.md](docs/FINDING-attestation-integrity.md).

---

## The demo

One command. It mutates the real bundle, shows what the verifier and the admission gate do about it,
and restores itself — including from a Ctrl-C, via a trap. It refuses to start on a dirty tree.

```bash
bash scripts/demo.sh
```

| Act | What it does | What it shows |
|---|---|---|
| 0 | verify + gate the pristine bundle | the baseline, on both surfaces |
| 1 | **swap the attester** | every integrity check stays green; native §10.5 attestation *accepts* the swap; the publisher-signed pin refuses it |
| 2 | **benign round-trip** — reorder keys, re-spell a date, add CRLF | raw bytes move on disk; the canonical digest, pins, and root do not. A raw-byte signer breaks here |
| 3 | **forge a trust tier and re-sign the root** | the adversary holds the publisher key; root recomputes and verifies; the forged actor still never signed, so it is still refused |
| 4 | **swap the computation, skip re-ingest** | the disk and store surfaces diverge, and each is independently anchored |
| 5 | the full loop with a model *(needs `OPENAI_API_KEY`, skipped otherwise)* | the served answer, its signed refusal set, the ITE-6 run envelope |

```bash
bash scripts/demo.sh --list          # the acts
bash scripts/demo.sh --act 1         # just the headline
DEMO_PAUSE=1 bash scripts/demo.sh    # pause between acts (for recording)
```

Every claim above is reproducible with no API key at all; act 5 is the only one that needs one.

## What it enforces, at the point of use

[`src/enforce.py`](src/enforce.py)'s `admit_concept` runs eight checks per retrieved concept. A
refused concept never enters the LLM's context. It does not short-circuit — a concept that is
tampered *and* trust-forged *and* stale reports all three, because naming every reason is the point.

| Check | Question |
|---|---|
| `integrity` | do the bytes **the model reads** (the vector-store row) match the publisher-signed digest? |
| `integrity_on_disk` | do the bytes **a run would execute** (the file on disk) match that same signed digest? |
| `trust_authentic` | is every `verified` claim actually signed by the actor it names? |
| `trust_floor` | does the *authenticated* tier meet the configured `--min-tier`? |
| `status` | is the concept deprecated? |
| `freshness` | is `today` past `stale_after`? |
| `pins` | for an Attested Computation: are the sanctioned computation and the attester still what the publisher signed? |
| `sources` | do this concept's bundle-local sources still verify? |

Two surfaces, not one: an at-rest verifier checks the bundle *directory*, but an agent serves rows
out of a vector store, and nothing had ever hashed those. Both are compared against the same signed
digest, so an attacker has to compromise both to move either.

The `pins` check runs **before** the executor is invoked and before the attester module is imported.
A refusal that happens after the bundle's code runs is not a control.

## What a third party can check, at rest

Public keys only. No private key, no API key, no vector store.

```bash
uv run python verify.py --okf-bundle bundles/acme_retail
```

```
[1] Merkle root recomputation ... ✅ MATCHES  26c250093747…
[2] Bundle root signature (publisher_v1) ... ✅ VALID
[3] Concept set (9 signed / 9 on disk) ... ✅ no additions or removals
[4] Per-concept integrity + authenticated trust (9 concepts)
[5] Computation pins (2 Attested Computations)

RESULT: ✅ PASS — bundle integrity and authenticated trust verify
```

Also `verify.py --okf-run -1` (re-verify a logged computation run, including its DSSE ITE-6
envelope) and `verify.py --okf-answer -1` (re-verify an answer attestation, including the signed
list of concepts that were *refused* — absence by policy, provable after the fact).

## Canonicalization: what the digest survives

OKF assumes agents constantly rewrite these documents — §5.1 uses keyed rather than positional
footnote labels for exactly that reason. A signature over raw bytes therefore breaks on ordinary,
legitimate edits, and a verifier that cries wolf on benign rewrites trains its operator to ignore
it. Concepts are hashed in a canonical form (`okf-concept/v1`) instead: RFC-8785-flavored JSON for
the frontmatter, normalized body.

**Digest unchanged** (a benign agent rewrite stays verified):
frontmatter key reordering · block ↔ flow YAML style · quoted ↔ bare ISO dates · `Z` ↔ `+00:00` ·
CRLF/CR ↔ LF · per-line trailing whitespace · leading/trailing blank lines · NFD ↔ NFC · YAML
comments · `yes`/`true` spellings.

**Digest changes** — by design, or as an accepted v1 limit:
reordering *list* items (`tags`, `sources`, `verified` stay order-significant) · a bare date vs. a
datetime (distinct values, not formatting) · `1` vs `1.0` · prose reflow · changed indentation ·
added/removed interior blank lines · `*` ↔ `-` bullets.

The body rules are deliberately conservative: a `# Computation` fence can be an indented code block,
and reindenting it would corrupt the SQL. Frontmatter — where the trust signals live — is the robust
part.

## Prior art, and what is actually new here

This is not the first attempt to sign OKF, and the claim is the *conjunction*: canonicalized **and**
per-actor **and** run-attested **and** enforced at the point of use.

- **[`signed-okf`](https://github.com/dynamicfeed/signed-okf)** is the closest prior work: a
  whole-bundle, single-issuer, raw-byte Ed25519 signature with at-rest CLI verification, built
  against v0.1. It genuinely mitigates third-party tampering of concept files. It hashes raw bytes,
  so it breaks on the round-trips §5.1 anticipates; it binds one issuer, so `verified: human:alice`
  is still a string alice never signed; it does not cover the attester (not a `.md` file, so not in
  the signed set); and it never touches the run.
- **The `okf` CLI, `okf-enforcer`, and the Rust `okf` crate** parse, validate, and shape-check v0.2.
  No signing, no enforcement — useful as a conformance baseline alongside this.
- **OKF v0.2 itself** already names this territory: Goal 4 standardizes trust frontmatter
  "without prescribing any runtime," §5.3 calls tiers advisory, and §12's *Considered and deferred*
  list includes "the full runtime protocol" and "the attester ABI, portability, and sandboxing."
  This work implements a layer the spec explicitly defers — an aligned contribution, not a defect
  report.
- The surrounding RAG-security literature (the OWASP LLM Top 10's retrieval-poisoning entries,
  RAGShield and similar) motivates *why* the interesting boundary is the point of use rather than
  the store.

## Quickstart

Python 3.12+, [uv](https://docs.astral.sh/uv/). No API key needed for anything except generating an
answer.

```bash
uv sync && uv sync --extra intoto      # the intoto extra enables ITE-6 export/verify

uv run python scripts/generate_keys.py                                  # publisher + service keys
uv run python -m src.okf_ingest bundles/acme_retail                     # canonicalize, hash, sign, embed; use --force --resign if needed
uv run python scripts/sign_trust.py bundles/acme_retail --mint-missing  # per-actor trust signatures
```

`sign_trust.py` runs *after* ingest — it needs a signed root to bind claims against. `--mint-missing`
mints a keypair for each actor the bundle names, standing in for the real-world key distribution
this project does not solve (see the threat model).

Then verify, gate, and run:

```bash
uv run python verify.py --okf-bundle bundles/acme_retail

# the admission gate, no model required
uv run python main_okf.py "What is Acme's revenue definition?" --no-llm --today 2026-08-01

# execute an Attested Computation under its publisher-signed pins
uv run python -m src.okf_attest bundles/acme_retail computations/revenue-ytd --param year=2026

# the full loop, with a model (needs OPENAI_API_KEY in .env)
uv run python main_okf.py "What was FY2026 revenue?" \
    --run computations/revenue-ytd --param year=2026
uv run python verify.py --okf-run -1
uv run python verify.py --okf-answer -1
```

Attack the bundle yourself — each attack prints a before/after digest table and the detection it
expects, and `restore` undoes it:

```bash
uv run python scripts/tamper_okf.py swap-attester      bundles/acme_retail computations/revenue-ytd
uv run python scripts/tamper_okf.py swap-fence         bundles/acme_retail computations/revenue-ytd
uv run python scripts/tamper_okf.py forge-tier         bundles/acme_retail metrics/revenue human:attacker
uv run python scripts/tamper_okf.py benign-round-trip  bundles/acme_retail computations/revenue-ytd
uv run python scripts/tamper_okf.py status             bundles/acme_retail
uv run python scripts/tamper_okf.py restore            bundles/acme_retail
```

A Streamlit UI renders the disk surface and the store surface side by side, with the attacks as
buttons — the one view the CLI cannot show at once:

```bash
uv run streamlit run app_okf.py
```

Tests: `uv run pytest -q`.

## The bundle

[`bundles/acme_retail`](bundles/acme_retail) is vendored verbatim from the upstream OKF repository at
commit `3fcbb9f` ([`bundles/UPSTREAM.json`](bundles/UPSTREAM.json)) — 9 concepts (`index.md` and
`log.md` are reserved navigation files, not concepts), of which 2 are Attested Computations, both
naming the same attester. Nothing about it was authored for this demo, which is the point: the
attacks work on the sample bundle the spec authors ship.

## Repo map

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for a diagram of how the pieces below fit into one
trust boundary, from publish time through consumption to independent verification.

```
src/
  okf.py          parse a bundle; canonicalize a concept to deterministic bytes
  okf_ingest.py   hash → Merkle tree → sign root + computation pins → embed into Chroma
  trust.py        per-actor keyring; sign a trust entry; derive the AUTHENTICATED tier
  okf_verify.py   check_concept_tamper, check_pins, verify_bundle (the at-rest report)
  okf_attest.py   attest_run (pin-gated) and native_attest_run (the §10.5 baseline); ITE-6 out
  okf_exec.py     simulated executor with parameter binding — no live warehouse needed
  okf_retrieve.py retrieval over the okf_concepts collection
  enforce.py      admit_concept, admit_all, run_agent — the eight checks, and the refusal

  merkle.py crypto.py intoto.py attestation.py schema.py config.py    shared substrate

verify.py            standalone verifier: --okf-bundle / --okf-run / --okf-answer (public keys only)
main_okf.py          the agent loop, CLI
app_okf.py           Streamlit UI: both surfaces, side by side
scripts/demo.sh      the whole argument, six acts, self-restoring
scripts/tamper_okf.py the four attacks, plus status/restore
scripts/sign_trust.py issue per-actor trust signatures
```

The crypto substrate is shared with this repository's original track — a provenance layer over arXiv
abstracts, with Merkle-signed chunks, answer attestations, and in-toto ITE-6 export. That system is
documented in full in [docs/ARXIV-RAG.md](docs/ARXIV-RAG.md) and still runs (`main.py`, `app.py`,
`verify.py --log-index -1`).

## Limits

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before believing anything here. In short: this
proves provenance, not truth. A publisher can sign false content. The pins decide *which* attester
runs but do not sandbox it — bundle code executes in-process, and §12 defers sandboxing. Source
closure is one level deep. There is no TUF-style snapshot role, so an old, authentically signed
bundle still verifies. And key rotation, revocation, delegation, and thresholds are unimplemented:
*which identities may sign which concepts* is the open problem this work is meant to motivate, not
one it solves. See [docs/OKF_COMPATIBILITY.md](docs/OKF_COMPATIBILITY.md) for exactly which OKF v0.2
semantics this project assumes.
