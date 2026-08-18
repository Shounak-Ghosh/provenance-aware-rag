"""End-to-end tests that drive the SHIPPED command lines as real subprocesses.

Every other test in this suite calls library functions. These call
`python verify.py --okf-bundle ...`, `python scripts/tamper_okf.py ...`, and
`python -m src.okf_attest ...` exactly as a reviewer would type them, inside
the e2e_sandbox CWD (see tests/conftest.py). That closes a gap the library
tests cannot: argument names, exit codes, module-level imports, and the
printed reasons are all part of the contract the demo and the README rely on,
and none of them are exercised by importing a function.

Two tiers:

  fast (default)  tamper_okf, verify.py, src.okf_attest -- all disk-only.
                  These carry the headline assertions.
  slow            src.okf_ingest and main_okf.py, which load
                  SentenceTransformer and build a real Chroma store. Skipped
                  unless OKF_E2E_SLOW=1 is set, so `uv run pytest -q` keeps
                  its current runtime and meaning.

Assertions deliberately match SHORT, stable tokens ("RESULT: ✅ PASS",
"❌ DOWNGRADED", "attester tampered") rather than whole formatted lines, so
re-wording a table or widening a column does not turn into a red test.
"""
import os
import subprocess

import pytest

from tests.conftest import REPO_ROOT

CONCEPT = "computations/revenue-ytd"
OTHER_CONCEPT = "computations/gross-margin-period"
TRUST_CONCEPT = "metrics/revenue"
YEAR = "year=2026"

slow = pytest.mark.skipif(
    os.environ.get("OKF_E2E_SLOW") != "1",
    reason="builds a real Chroma store and loads SentenceTransformer; set OKF_E2E_SLOW=1 to run",
)


def _tamper(sb, *args) -> subprocess.CompletedProcess:
    proc = sb.run("scripts/tamper_okf.py", *args)
    assert proc.returncode == 0, f"tamper_okf {args} failed:\n{proc.stdout}\n{proc.stderr}"
    return proc


def _verify(sb) -> subprocess.CompletedProcess:
    return sb.run("verify.py", "--okf-bundle", sb.bundle_arg)


def _attest(sb, *extra) -> subprocess.CompletedProcess:
    return sb.run("-m", "src.okf_attest", sb.bundle_arg, CONCEPT, "--param", YEAR, *extra)


# ── baseline ────────────────────────────────────────────────────────────────


def test_clean_bundle_verifies_via_cli(e2e_sandbox):
    proc = _verify(e2e_sandbox)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "RESULT: ✅ PASS" in proc.stdout
    assert "❌" not in proc.stdout
    # The header the D7 fix added: a third party needs to see WHICH key signed.
    assert "by test_publisher" in proc.stdout
    assert "[2] Bundle root signature (test_publisher)" in proc.stdout
    assert "[3] Concept set (9 signed / 9 on disk)" in proc.stdout


def test_clean_attested_run_via_cli(e2e_sandbox):
    proc = _attest(e2e_sandbox)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "✅ PASS" in proc.stdout


# ── the headline: swap the attester ─────────────────────────────────────────


def test_swap_attester_is_the_headline_via_cli(e2e_sandbox):
    """Every integrity check stays green, the native SPEC-§10.5 attestation
    still passes, and the pinned attestation refuses anyway.

    attesters/sql_equality.py is not a .md file, so it is not a concept: no
    concept digest moves, no Merkle leaf moves, the signed root still
    verifies. A whole-bundle raw-byte signature over the .md files would miss
    this too. Only the publisher-signed attester pin catches it -- and it
    catches it twice, because both Attested Computations point at that one
    file.
    """
    sb = e2e_sandbox
    _tamper(sb, "swap-attester", sb.bundle_arg, CONCEPT)

    native = _attest(sb, "--native")
    assert native.returncode == 0, native.stdout + native.stderr
    assert "✅ PASS" in native.stdout
    assert "UNPROTECTED BASELINE" in native.stdout

    pinned = _attest(sb)
    assert pinned.returncode == 1
    assert "❌ REFUSED" in pinned.stdout
    assert "attester tampered" in pinned.stdout

    report = _verify(sb)
    assert report.returncode == 1
    # [1]-[4] green: the bundle's own bytes are untouched.
    assert "[1] Merkle root recomputation ... ✅ MATCHES" in report.stdout
    assert "✅ VALID" in report.stdout
    assert "✅ no additions or removals" in report.stdout
    assert "canonical-hash mismatch" not in report.stdout
    assert "merkle proof failed" not in report.stdout
    # [5] red, twice -- both computations share the one attester.
    assert report.stdout.count("❌ attester tampered (pin mismatch)") == 2
    assert "RESULT: ❌ FAIL" in report.stdout


# ── the canonicalization win: a benign agent rewrite ────────────────────────


def test_benign_round_trip_changes_bytes_but_nothing_signed_via_cli(e2e_sandbox):
    """A raw-byte signer (signed-okf) breaks here. This one does not."""
    sb = e2e_sandbox
    rel = f"bundles/{sb.bundle_id}/{CONCEPT}.md"
    before = sb.read(rel)

    _tamper(sb, "benign-round-trip", sb.bundle_arg, CONCEPT)

    assert sb.read(rel) != before, "the round-trip did not actually rewrite the file"

    report = _verify(sb)
    assert report.returncode == 0, report.stdout + report.stderr
    assert "RESULT: ✅ PASS" in report.stdout

    # The pinned computation still runs: the fence's canonical bytes survived.
    run = _attest(sb)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "✅ PASS" in run.stdout


def test_benign_round_trip_preserves_trust_on_a_pinless_concept_via_cli(e2e_sandbox):
    """metrics/revenue has trust signatures but no pins: this checks the YAML
    timestamp re-spelling does not break the per-actor signature, which is
    built from the NORMALIZED `at` value."""
    sb = e2e_sandbox
    _tamper(sb, "benign-round-trip", sb.bundle_arg, TRUST_CONCEPT)

    report = _verify(sb)
    assert report.returncode == 0, report.stdout + report.stderr
    assert "DOWNGRADED" not in report.stdout


# ── the trust win: forge a tier, then re-sign as the publisher ──────────────


def test_forge_tier_resigned_is_caught_only_by_trust_via_cli(e2e_sandbox):
    """The adversary is also the re-publisher: root recomputes, root signature
    is valid, no concept is tampered, pins are fine. The forged actor never
    signed anything, so the tier is downgraded and the CLI refuses."""
    sb = e2e_sandbox
    _tamper(sb, "forge-tier", sb.bundle_arg, TRUST_CONCEPT, "human:attacker", "--resign")

    report = _verify(sb)
    assert report.returncode == 1
    assert "[1] Merkle root recomputation ... ✅ MATCHES" in report.stdout
    assert "✅ VALID" in report.stdout
    assert "canonical-hash mismatch" not in report.stdout
    assert "merkle proof failed" not in report.stdout
    assert "❌ attester tampered" not in report.stdout
    assert "❌ DOWNGRADED" in report.stdout
    # verify_bundle's own `ok` stays True here; the FAIL is a policy refusal
    # this CLI applies on top, and it has to say so.
    assert "TRUST POLICY refusal" in report.stdout


def test_forge_tier_without_resign_is_caught_by_the_hash_via_cli(e2e_sandbox):
    sb = e2e_sandbox
    _tamper(sb, "forge-tier", sb.bundle_arg, TRUST_CONCEPT, "human:attacker")

    report = _verify(sb)
    assert report.returncode == 1
    assert "canonical-hash mismatch" in report.stdout


# ── swap the fence: noisy on purpose, and the CLI must explain the noise ────


def test_swap_fence_explains_the_moved_root_via_cli(e2e_sandbox):
    """One edited concept reports a hash mismatch; its eight siblings report
    'merkle proof failed' because the root they are proved against has moved.
    Without the NOTE a reader concludes nine concepts were tampered."""
    sb = e2e_sandbox
    _tamper(sb, "swap-fence", sb.bundle_arg, CONCEPT)

    report = _verify(sb)
    assert report.returncode == 1
    # Count the ❌ ROWS, not the strings -- the NOTE quotes both reasons, which
    # is precisely why it exists.
    assert report.stdout.count("❌ concept canonical-hash mismatch") == 1
    assert report.stdout.count("❌ merkle proof failed") == 8
    assert "the recomputed root differs from the signed root" in report.stdout

    # And the run is refused before the swapped SQL executes at all.
    run = _attest(sb)
    assert run.returncode == 1
    assert "❌ REFUSED" in run.stdout


def test_clean_bundle_has_no_moved_root_note_via_cli(e2e_sandbox):
    report = _verify(e2e_sandbox)
    assert "the recomputed root differs" not in report.stdout


# ── restore ─────────────────────────────────────────────────────────────────


def test_restore_returns_the_bundle_to_pristine_via_cli(e2e_sandbox):
    """Chain every attack, including the one that rewrites okf_roots.json,
    then restore. The demo script's `trap` depends on exactly this."""
    sb = e2e_sandbox
    root_before = sb.read("data/okf_roots.json")

    _tamper(sb, "swap-fence", sb.bundle_arg, CONCEPT)
    _tamper(sb, "swap-attester", sb.bundle_arg, OTHER_CONCEPT)
    _tamper(sb, "benign-round-trip", sb.bundle_arg, TRUST_CONCEPT)
    _tamper(sb, "forge-tier", sb.bundle_arg, "policies/margin-standard", "human:attacker", "--resign")
    assert _verify(sb).returncode == 1

    status = _tamper(sb, "status", sb.bundle_arg)
    assert "TAMPERED" in status.stdout.upper()

    _tamper(sb, "restore", sb.bundle_arg)

    report = _verify(sb)
    assert report.returncode == 0, report.stdout + report.stderr
    assert "RESULT: ✅ PASS" in report.stdout
    assert sb.read("data/okf_roots.json") == root_before


# ── the other two public-key-only modes ─────────────────────────────────────


def test_okf_run_mode_verifies_a_logged_run_via_cli(e2e_sandbox):
    sb = e2e_sandbox
    assert _attest(sb).returncode == 0

    proc = sb.run("verify.py", "--okf-run", "-1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "❌" not in proc.stdout


def test_okf_run_mode_with_no_log_exits_with_a_message(e2e_sandbox):
    proc = e2e_sandbox.run("verify.py", "--okf-run", "-1")
    assert proc.returncode != 0
    assert "No runs found" in proc.stdout + proc.stderr


def test_missing_roots_warns_rather_than_looking_like_tampering(e2e_sandbox):
    """A key-distribution gap and a forged bundle must not print the same
    thing -- the distinction verify.py's WARNING blocks exist to preserve."""
    sb = e2e_sandbox
    (sb.root / "data" / "okf_roots.json").unlink()

    proc = _verify(sb)
    assert proc.returncode == 1
    assert "WARNING" in proc.stdout
    assert "NOT the same signal as a tampered" in proc.stdout


# ── the demo script itself ──────────────────────────────────────────────────


def test_demo_script_is_syntactically_valid():
    script = REPO_ROOT / "scripts" / "demo.sh"
    assert script.exists(), "scripts/demo.sh is the recorded artifact; it must exist"
    proc = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_demo_script_lists_its_acts():
    proc = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "demo.sh"), "--list"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "swap-attester" in proc.stdout


# ── slow tier: the store surface ────────────────────────────────────────────


@slow
def test_ingest_then_gate_admits_the_clean_bundle_via_cli(e2e_sandbox):
    sb = e2e_sandbox
    ingest = sb.run("-m", "src.okf_ingest", sb.bundle_arg, "--force")
    assert ingest.returncode == 0, ingest.stdout + ingest.stderr

    gate = sb.run("main_okf.py", "What is Acme's revenue definition?", "--no-llm", "--today", "2026-08-01")
    assert gate.returncode == 0, gate.stdout + gate.stderr
    assert "✅ ADMITTED" in gate.stdout


@slow
def test_fence_swap_splits_the_disk_and_store_surfaces_via_cli(e2e_sandbox):
    """Day 4's two-surface property, on real wiring: with no re-ingest the
    store copy is still the bytes that were signed, so the store-side
    integrity check stays green while disk goes red."""
    sb = e2e_sandbox
    assert sb.run("-m", "src.okf_ingest", sb.bundle_arg, "--force").returncode == 0
    _tamper(sb, "swap-fence", sb.bundle_arg, CONCEPT)

    assert _verify(sb).returncode == 1  # disk: red

    gate = sb.run(
        "main_okf.py", "How is revenue computed?", "--no-llm",
        "--today", "2026-08-01", "--run", CONCEPT, "--param", YEAR,
    )
    assert "❌" in gate.stdout, gate.stdout + gate.stderr
