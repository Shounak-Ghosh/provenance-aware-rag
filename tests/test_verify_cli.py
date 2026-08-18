"""Tests for verify.py's OKF modes: --okf-bundle / --okf-run / --okf-answer.

Calls the `_verify_okf_*` functions directly (no subprocess) and drives them
with monkeypatched config paths pointed at a signed_fixture copy, so these
tests never touch data/keys/*, data/okf_roots.json, or any real log file.
Two import surfaces get patched, matching where each name is actually bound:

  * PUBLISHER_VERIFY_KEY_PATH / SERVICE_VERIFY_KEY_PATH are imported at
    verify.py's MODULE level (once, at import time) -- patch the attribute
    on the `verify` module object itself.
  * OKF_ROOTS_PATH / ACTOR_KEYRING_PATH / OKF_RUNS_PATH /
    OKF_ATTESTATION_LOG_PATH are imported LOCALLY inside each `_verify_okf_*`
    function (D7 lazy-import discipline) -- patch the attribute on
    src.config, which is re-read fresh on every call.
"""
import json
from pathlib import Path

import pytest

import verify as verify_module
from src.crypto import generate_keypair
from src.enforce import append_okf_answer, build_okf_answer_attestation, sign_okf_answer
from src.okf_attest import attest_run

SERVICE_KEY_ID = "test_service"


@pytest.fixture
def cli_env(signed_fixture, tmp_path, monkeypatch):
    service_sk, service_vk = generate_keypair()
    publisher_vk_path = tmp_path / "publisher.vk"
    service_vk_path = tmp_path / "service.vk"
    publisher_vk_path.write_bytes(bytes(signed_fixture.publisher_vk))
    service_vk_path.write_bytes(bytes(service_vk))

    roots_path = tmp_path / "okf_roots.json"
    roots_path.write_text(json.dumps(signed_fixture.roots, indent=2))
    runs_path = tmp_path / "okf_runs.jsonl"
    answers_path = tmp_path / "okf_attestation_log.jsonl"

    monkeypatch.setattr(verify_module, "PUBLISHER_VERIFY_KEY_PATH", publisher_vk_path)
    monkeypatch.setattr(verify_module, "SERVICE_VERIFY_KEY_PATH", service_vk_path)
    monkeypatch.setattr("src.config.OKF_ROOTS_PATH", roots_path)
    monkeypatch.setattr("src.config.ACTOR_KEYRING_PATH", signed_fixture.keyring_path)
    monkeypatch.setattr("src.config.OKF_RUNS_PATH", runs_path)
    monkeypatch.setattr("src.config.OKF_ATTESTATION_LOG_PATH", answers_path)

    class CliEnv:
        pass

    env = CliEnv()
    env.service_sk = service_sk
    env.service_vk = service_vk
    env.publisher_vk_path = publisher_vk_path
    env.roots_path = roots_path
    env.runs_path = runs_path
    env.answers_path = answers_path
    return env


# ── --okf-bundle ───────────────────────────────────────────────────────────────
def test_okf_bundle_clean_exits_zero(signed_fixture, cli_env, capsys):
    code = verify_module._verify_okf_bundle(str(signed_fixture.bundle_path))
    out = capsys.readouterr().out
    assert code == 0
    assert "RESULT: ✅ PASS" in out


def test_okf_bundle_tampered_exits_one(signed_fixture, cli_env, tmp_path, capsys):
    from scripts.tamper_okf import swap_attester

    swap_attester(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "computations/revenue-ytd",
        backup_root=tmp_path / "backups",
    )
    code = verify_module._verify_okf_bundle(str(signed_fixture.bundle_path))
    out = capsys.readouterr().out
    assert code == 1
    assert "RESULT: ❌ FAIL" in out
    assert "attester tampered (pin mismatch)" in out


def test_okf_bundle_prints_root_moved_note(signed_fixture, cli_env, tmp_path, capsys):
    from scripts.tamper_okf import swap_fence

    swap_fence(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "computations/revenue-ytd",
        backup_root=tmp_path / "backups",
    )
    code = verify_module._verify_okf_bundle(str(signed_fixture.bundle_path))
    out = capsys.readouterr().out
    assert code == 1
    assert "NOTE: the recomputed root differs" in out


def test_okf_bundle_clean_run_has_no_root_moved_note(signed_fixture, cli_env, capsys):
    verify_module._verify_okf_bundle(str(signed_fixture.bundle_path))
    out = capsys.readouterr().out
    assert "NOTE: the recomputed root differs" not in out


def test_okf_bundle_fails_on_trust_downgrade(signed_fixture, cli_env, tmp_path, capsys, monkeypatch):
    """D6's policy layer: verify_bundle's own `ok` is True (integrity is
    green), but the CLI applies trust_downgraded as its own refusal."""
    from scripts.tamper_okf import forge_tier

    new_sk, new_vk = generate_keypair()
    forge_tier(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "metrics/revenue", "human:attacker",
        resign=True, roots_path=cli_env.roots_path, publisher_sk=new_sk, backup_root=tmp_path / "backups",
    )
    cli_env.publisher_vk_path.write_bytes(bytes(new_vk))  # operator fetches the newly-republished key

    code = verify_module._verify_okf_bundle(str(signed_fixture.bundle_path))
    out = capsys.readouterr().out
    assert code == 1
    assert "RESULT: ❌ FAIL" in out
    assert "DOWNGRADED" in out
    assert "bundle-integrity is green" in out  # the D6 clarifying NOTE


def test_missing_roots_warns_not_crashes(signed_fixture, cli_env, monkeypatch, capsys):
    monkeypatch.setattr("src.config.OKF_ROOTS_PATH", Path("/nonexistent/okf_roots.json"))
    code = verify_module._verify_okf_bundle(str(signed_fixture.bundle_path))
    out = capsys.readouterr().out
    assert "WARNING" in out
    assert code == 1  # no signed record for the bundle -> a clean refusal, not a crash


# ── --okf-run ────────────────────────────────────────────────────────────────
def test_okf_run_verifies_and_detects_flipped_field(signed_fixture, cli_env, capsys):
    result = attest_run(
        signed_fixture.bundle_path, signed_fixture.bundle_id, "computations/revenue-ytd", {"year": "2026"},
        signed_fixture.roots, signed_fixture.publisher_vk, cli_env.service_sk, SERVICE_KEY_ID, signed_fixture.keyring,
        log_path=cli_env.runs_path,
    )
    assert result["ok"] is True

    code = verify_module._verify_okf_run(-1)
    out = capsys.readouterr().out
    assert code == 0
    assert "RESULT: ✅ PASS" in out

    lines = cli_env.runs_path.read_text().splitlines()
    entry = json.loads(lines[-1])
    entry["verdict_ok"] = not entry["verdict_ok"]
    cli_env.runs_path.write_text("\n".join(lines[:-1] + [json.dumps(entry)]) + "\n")

    code = verify_module._verify_okf_run(-1)
    out = capsys.readouterr().out
    assert code == 1
    assert "run record hash mismatch" in out


def test_okf_run_no_runs_exits_with_message(signed_fixture, cli_env, capsys):
    with pytest.raises(SystemExit, match="No runs found"):
        verify_module._verify_okf_run(-1)


# ── --okf-answer ─────────────────────────────────────────────────────────────
def test_okf_answer_verifies_and_detects_flipped_refusals(signed_fixture, cli_env, capsys):
    admitted = signed_fixture.concepts[:2]
    attestation = build_okf_answer_attestation(
        "What is Acme's revenue?", "Revenue was 43042.42.", admitted,
        ["metrics/gross-margin-legacy"], signed_fixture.bundle_id, "test-model",
    )
    signed = sign_okf_answer(attestation, cli_env.service_sk, SERVICE_KEY_ID)
    append_okf_answer(signed, path=cli_env.answers_path)

    code = verify_module._verify_okf_answer(-1)
    out = capsys.readouterr().out
    assert code == 0
    assert "RESULT: ✅ PASS" in out
    assert "metrics/gross-margin-legacy" in out

    lines = cli_env.answers_path.read_text().splitlines()
    entry = json.loads(lines[-1])
    entry["refused_concept_ids"] = []  # attacker launders the refusal out of the log
    cli_env.answers_path.write_text("\n".join(lines[:-1] + [json.dumps(entry)]) + "\n")

    code = verify_module._verify_okf_answer(-1)
    out = capsys.readouterr().out
    assert code == 1
    assert "RESULT: ❌ FAIL" in out
