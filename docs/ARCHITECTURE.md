# Architecture: the trust boundary

This is the one-diagram version of what [`src/enforce.py`](../src/enforce.py)'s `admit_concept` does
and why. Read the README first for the demo and the eight checks in prose; this page is the shape of
the pipeline those checks sit inside.

```mermaid
flowchart TD
    subgraph PUBLISH["Publish time -- publisher + actors, trusted"]
        BUNDLE["Bundle on disk\n(OKF concepts, .md)"]
        CANON["Canonicalize\n(RFC-8785 JSON frontmatter\n+ normalized body)"]
        LEAF["Per-concept SHA-256"]
        MERKLE["Merkle tree\n(leaf/node domain-separated,\nleaf-count bound -- src/merkle.py)"]
        ROOT["Bundle root"]
        PSIG["Publisher signature\nover the root"]
        PINS["Computation + attester digests\npinned and signed\n(ComputationPins)"]
        TRUST["Per-actor trust signatures\n(verified/generated claims,\neach signed by the actor it names)"]

        BUNDLE --> CANON --> LEAF --> MERKLE --> ROOT --> PSIG
        BUNDLE --> PINS
        BUNDLE --> TRUST
    end

    subgraph INGEST["Ingest -- src/okf_ingest.py"]
        STORE["Vector store row\n(Chroma) -- SECOND surface,\nnever hashed before this project"]
    end
    PSIG --> STORE

    subgraph CONSUME["Consume time -- src/enforce.py admit_concept, per retrieved concept"]
        RETRIEVE["Agent retrieves a concept\nfrom the vector store"]
        CHECKS["Eight checks against BOTH surfaces\n(disk copy AND store copy)\nvs. the SAME signed digest:\nintegrity, integrity_on_disk, trust_authentic,\ntrust_floor, status, freshness, pins, sources"]
        DECISION{"All required\nchecks pass?"}
        ADMIT["ADMIT\ninto the model's context"]
        REFUSE["REFUSE\nnames every failed reason,\nnot just the first"]

        RETRIEVE --> CHECKS --> DECISION
        DECISION -- yes --> ADMIT
        DECISION -- no --> REFUSE
    end
    STORE --> RETRIEVE
    BUNDLE -. "disk copy, re-checked live" .-> CHECKS
    TRUST --> CHECKS
    PINS --> CHECKS

    subgraph EXEC["Attested Computation only -- src/okf_attest.py"]
        PINCHECK["Pin check:\nis the executor/attester still\nwhat the publisher signed?"]
        RUN["Executor runs,\nattester judges the result"]
        RUNSIG["Signed RunRecord\n(ITE-6 / DSSE envelope)"]

        PINCHECK -- "BEFORE the executor is invoked\nand BEFORE the attester\nmodule is imported" --> RUN --> RUNSIG
    end
    ADMIT -. "if concept is an\nAttested Computation" .-> PINCHECK

    subgraph EVIDENCE["Output evidence"]
        ANSWER["Signed answer attestation:\nadmitted concept hashes\n+ REFUSED concept ids\n(absence-by-policy, provable after the fact)"]
    end
    ADMIT --> ANSWER
    REFUSE --> ANSWER
    RUNSIG --> ANSWER

    subgraph VERIFY["Independent verification -- verify.py, public keys only"]
        THIRDPARTY["Third party re-checks:\nroot, signatures, pins,\nrun + answer attestations"]
    end
    PSIG -.-> THIRDPARTY
    TRUST -.-> THIRDPARTY
    RUNSIG -.-> THIRDPARTY
    ANSWER -.-> THIRDPARTY
```

## Why the shape is this shape

- **Two surfaces, one signed digest.** The disk copy and the vector-store copy are independently
  anchored against the *same* publisher-signed digest (solid arrows into `CHECKS` from both `BUNDLE`
  and `STORE`). An attacker has to compromise both to move either — see
  [docs/FINDING-attestation-integrity.md](FINDING-attestation-integrity.md) for what happens when only
  one is checked.
- **Pin-before-import, not pin-then-run.** `PINCHECK` gates `RUN` before the executor or attester code
  ever executes. A refusal that happens after the bundle's code has already run is not a control —
  see the `pins` check in the README's enforcement table.
- **Identity is authenticated, not read off the page.** `TRUST` signatures feed `CHECKS` alongside the
  content digest, so `trust_floor` gates on the tier a signature actually backs, not the tier a
  `verified:` string merely claims.
- **Refusal is evidence, not silence.** `REFUSE` still flows into `ANSWER` — the signed attestation
  names every concept that was kept out, so a third party can later prove a concept was excluded
  *by policy*, not just absent.
- **What this diagram does not show:** key distribution, rotation, revocation, or delegation — there
  is no TUF-style trust root yet. See [docs/THREAT_MODEL.md](THREAT_MODEL.md) and
  [docs/OKF_COMPATIBILITY.md](OKF_COMPATIBILITY.md) for what's assumed rather than enforced.
