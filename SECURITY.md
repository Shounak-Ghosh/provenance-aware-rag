# Security Policy

This is an independent security-research prototype, not a maintained product with an SLA. That said,
real vulnerability reports are welcome and will be taken seriously.

## Reporting a vulnerability

Preferred: open a [GitHub private security advisory](https://github.com/Shounak-Ghosh/provenance-aware-rag/security/advisories/new)
on this repository. If that isn't an option, email **subuddhi8@gmail.com** with a description of the
issue, the affected component, and reproduction steps.

Please do not open a public issue for a vulnerability until it's been triaged privately.

You can expect an initial response within about a week. This is solo-maintained alongside a full
graduate course load, so turnaround is best-effort, not guaranteed.

## Scope

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before reporting — it defines what this project
claims to defend against and, just as importantly, what it explicitly does not.

**In scope** — anything that breaks a claimed guarantee, e.g.:
- a tampered concept/chunk that verification (`verify.py`, `enforce.admit_concept`,
  `src.okf_verify.verify_bundle`) fails to detect;
- a forgeable or replayable signature (root, trust, pins, run, or answer attestation);
- a Merkle proof that verifies against the wrong content, index, or leaf count
  (see `src/merkle.py`);
- an attester or computation substitution that the pin check (`enforce.py`'s `pins` check) fails to
  catch;
- canonicalization that makes two semantically different documents hash identically, or a benign
  edit the spec anticipates that breaks verification.

**Out of scope** — known, documented limitations, not vulnerabilities:
- truthfulness of correctly signed content (a publisher can sign something false);
- compromise of a publisher's or actor's private signing key;
- sandboxing of executed computation/attester code (bundle code runs in-process; §12 of OKF defers
  sandboxing, and so does this project — see the Lind extension noted in the threat model);
- prompt injection into the LLM;
- confidentiality or denial-of-service — this project targets integrity and provenance only;
- key distribution/rotation/revocation/delegation (no TUF-style trust root exists here yet).

## Supported versions

Only the latest commit on `main` is supported. There are no maintained release branches.
