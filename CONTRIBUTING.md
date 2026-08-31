# Contributing

This started as independent research and is solo-maintained. Contributions are welcome, but given the
scope, please **open an issue or discussion before sending a substantial PR** — small fixes (typos,
broken links, obvious bugs) can just be a PR directly.

## Setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync && uv sync --extra intoto   # the intoto extra enables ITE-6 export/verify + dev tooling
```

## Running things

```bash
uv run pytest -q          # test suite
uv run ruff check .       # lint
bash scripts/demo.sh      # the six-act demo; no API key required except act 5
```

See the README's Quickstart for the full ingest/sign/verify/enforce walkthrough.

## Before opening a PR

- Tests pass: `uv run pytest -q`.
- Lint is clean: `uv run ruff check .`.
- If you touched `src/merkle.py`, `src/okf.py` (canonicalization), or anything else that changes a
  signed digest, re-run the ingest/sign scripts (see the README Quickstart) so `data/` stays
  consistent, and expect any pinned-root regression tests (e.g. `tests/test_okf.py`) to need updating.
- If you're changing what a check enforces (`src/enforce.py`, `src/okf_verify.py`), explain the
  security reasoning in the PR description — this is a security-focused project, and *why* a check
  exists matters as much as the diff.

## What this project is not looking for

New integrations (LangChain/LlamaIndex), large refactors, or performance work, unless discussed first
— see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what's explicitly in/out of scope, and
[SECURITY.md](SECURITY.md) for how to report a vulnerability rather than opening a public PR/issue
about one.
