"""Streamlit UI for the OKF verification layer.

    uv run streamlit run app_okf.py

A sibling of app.py, not a mode inside it -- the same split this repo already
uses for main.py/main_okf.py, ingest/okf_ingest, retrieve/okf_retrieve,
roots.json/okf_roots.json and arxiv_chunks/okf_concepts. app.py is untouched.

What this shows that neither CLI can: BOTH SURFACES AT ONCE.

    Panel A  bundle integrity at rest      reads DISK   (okf_verify.verify_bundle)
    Panel B  the adversary                 writes DISK  (scripts/tamper_okf.py)
    Panel C  the admission gate at use     reads CHROMA (enforce.run_agent)

A and C are independent. Tamper a computation and A goes red immediately while
C's per-concept `integrity` check stays green -- the store still holds the
bytes that were signed -- until Re-ingest moves that surface too. `verify.py
--okf-bundle` and `main_okf.py` each show one half of that; this shows the
divergence itself, which is the point Day 4 established and nothing rendered.

CACHING RULE (the way this page would most easily ship broken): only the embed
model and the Chroma client are cached. okf_roots.json, the keyring, the
verify_bundle report and the tamper status are re-read on EVERY rerun, because
every button below changes what they say -- forge-tier --resign rewrites the
roots file itself. A cached report would make the attacks look like no-ops.
"""
import json
import os
import sys
from datetime import date
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

# Must run before any `src.*` import — see app.py for why (src/config.py reads
# env-derived settings like LLM_MODEL once, at import time).
load_dotenv(override=True)

sys.path.insert(0, str(Path(__file__).parent / "scripts"))

import tamper_okf  # noqa: E402  (scripts/ is not a package; path set above)
from src.config import (  # noqa: E402
    ACTOR_KEYRING_PATH,
    EMBED_MODEL_NAME,
    LLM_MODEL,
    OKF_BUNDLES_DIR,
    OKF_CANON_VERSION,
    OKF_COLLECTION_NAME,
    OKF_MIN_TIER,
    OKF_ROOTS_PATH,
    OKF_TIER_ORDER,
    PUBLISHER_VERIFY_KEY_PATH,
    SERVICE_KEY_ID,
    SERVICE_SIGNING_KEY_PATH,
)
from src.crypto import load_signing_key, load_verify_key  # noqa: E402
from src.enforce import run_agent  # noqa: E402
from src.okf import parse_bundle  # noqa: E402
from src.okf_verify import verify_bundle  # noqa: E402
from src.trust import load_keyring  # noqa: E402

st.set_page_config(page_title="OKF-Verify", page_icon="🔐", layout="wide")

DEFAULT_COMPUTATION = "computations/revenue-ytd"
DEFAULT_TRUST_CONCEPT = "metrics/revenue"


# ── cached resources (immutable for the life of the process) ────────────────


@st.cache_resource
def load_embed_model():
    from sentence_transformers import SentenceTransformer

    return SentenceTransformer(EMBED_MODEL_NAME)


@st.cache_resource
def load_okf_collection():
    from src.store import get_collection

    return get_collection(OKF_COLLECTION_NAME)


@st.cache_resource
def load_openai_client():
    from openai import OpenAI

    return OpenAI(api_key=os.environ["OPENAI_API_KEY"])


# ── live state (re-read every rerun; see the CACHING RULE above) ─────────────


def live_roots() -> dict:
    return json.loads(OKF_ROOTS_PATH.read_text()) if OKF_ROOTS_PATH.exists() else {}


def live_keyring() -> dict:
    return load_keyring(ACTOR_KEYRING_PATH)


def bundle_ids() -> list[str]:
    if not OKF_BUNDLES_DIR.is_dir():
        return []
    return sorted(p.name for p in OKF_BUNDLES_DIR.iterdir() if p.is_dir())


# ── rendering helpers ───────────────────────────────────────────────────────


def chip(ok: bool, label: str, tooltip: str = "") -> str:
    css = "chip-verified" if ok else "chip-tampered"
    return f'<span class="chip {css}" title="{tooltip}">{label}</span>'


def check_row(number: str, label: str, ok: bool, verdict: str) -> None:
    st.markdown(
        f"<div class='row'><b>[{number}]</b> {label} &nbsp; {chip(ok, verdict)}</div>",
        unsafe_allow_html=True,
    )


def digest_table(result: dict) -> None:
    """The before/after digest table scripts/tamper_okf.py prints, as a table.

    Same four rows, same source data -- this renders the dict the attack
    function already returns rather than re-deriving anything, so the UI and
    the CLI can never disagree about what an attack did.
    """
    rows = [("raw file bytes", "raw_before", "raw_after")]
    rows += [("canonical digest", "sha256_before", "sha256_after")]
    if result.get("root_before"):
        rows += [("bundle merkle root", "root_before", "root_after")]
    if result.get("computation_pin_before"):
        rows += [("computation pin", "computation_pin_before", "computation_pin_after")]
    if result.get("attester_pin_before"):
        rows += [("attester pin", "attester_pin_before", "attester_pin_after")]

    lines = []
    for label, kb, ka in rows:
        before, after = result.get(kb), result.get(ka)
        if before is None or after is None:
            continue
        changed = before != after
        mark = "CHANGED  " if changed else "UNCHANGED"
        lines.append(f"{label:<20} {before[:12]}…  ->  {after[:12]}…  {mark}")
    st.code("\n".join(lines), language=None)

    st.caption("Expected detection: " + "; ".join(result.get("expected_detections", ["—"])))


# ── UI ──────────────────────────────────────────────────────────────────────

st.markdown(
    """<style>
    .chip{display:inline-block;padding:2px 10px;border-radius:12px;font-size:0.85rem;font-weight:600;color:white;}
    .chip-verified{background:#1e7e34;}
    .chip-tampered{background:#c62828;}
    .row{margin:4px 0;font-size:0.95rem;}
    .surface{font-size:0.8rem;text-transform:uppercase;letter-spacing:.08em;color:#888;}
    </style>""",
    unsafe_allow_html=True,
)

st.title("🔐 OKF-Verify")
st.caption(
    "Cryptographic verification of an OKF v0.2 bundle, at rest and at the moment "
    "an agent consumes a concept. Panel A reads the files on disk; Panel C reads "
    "the vector store. They are checked independently, and Panel B is what makes "
    "them disagree."
)

available = bundle_ids()
if not available:
    st.error(f"No bundles found under {OKF_BUNDLES_DIR}/.")
    st.stop()

with st.sidebar:
    st.header("Bundle")
    bundle_id = st.selectbox("Bundle", available, index=0)
    bundle_path = OKF_BUNDLES_DIR / bundle_id

    st.header("Gate policy")
    min_tier = st.selectbox(
        "Minimum authenticated tier", list(OKF_TIER_ORDER), index=list(OKF_TIER_ORDER).index(OKF_MIN_TIER),
        help="A forged or unbacked trust claim is refused regardless of this floor.",
    )
    today = st.date_input("Evaluate stale_after as of", value=date(2026, 8, 1))
    n_results = st.slider("Concepts retrieved", 1, 9, 5)

    st.header("Attested computation")
    run_concept = st.text_input("Run this concept (optional)", value="")
    run_year = st.text_input("Parameter: year", value="2026")

    has_key = bool(os.environ.get("OPENAI_API_KEY"))
    use_llm = st.toggle(
        "Call the model", value=False, disabled=not has_key,
        help="Off = show the gate only; no API key needed." if has_key else "OPENAI_API_KEY is not set.",
    )

try:
    publisher_vk = load_verify_key(PUBLISHER_VERIFY_KEY_PATH)
except FileNotFoundError:
    st.error(
        f"Missing {PUBLISHER_VERIFY_KEY_PATH}. Run `uv run python scripts/generate_keys.py` first."
    )
    st.stop()

roots = live_roots()
keyring = live_keyring()

if not roots:
    st.warning(
        f"{OKF_ROOTS_PATH} is missing or empty — every concept will report "
        "'no signed record for bundle', which is NOT the same signal as a tampered "
        f"concept. Run `uv run python -m src.okf_ingest {bundle_path}` first."
    )
if not keyring:
    st.warning(
        f"{ACTOR_KEYRING_PATH} is missing or empty — every claimed actor will report "
        "'unknown_actor', which is a key-distribution gap, NOT evidence of forgery."
    )

# ── the dirty-bundle banner ─────────────────────────────────────────────────
# A CLI demo ends with an explicit `restore`. A browser tab can be closed
# mid-attack, so this is read from tamper_okf's own manifest on every rerun --
# never from session state, which a refresh would clear while the files on disk
# stayed tampered.
tamper_status = tamper_okf.status(bundle_path, bundle_id)
dirty = [r for r in tamper_status["files"] if r["tampered"]] or tamper_status["roots_tampered"]
if dirty:
    banner = st.container()
    with banner:
        st.error(
            "**This bundle is currently tampered.** Files still mutated on disk:\n\n"
            + "\n".join(
                f"- `{r['rel_path']}` — pristine `{r['pristine_sha256'][:12]}…`, "
                f"now `{r['current_sha256'][:12]}…`"
                for r in tamper_status["files"] if r["tampered"]
            )
            + ("\n- `data/okf_roots.json` — re-signed" if tamper_status["roots_tampered"] else "")
        )
        if st.button("🧹 Restore this bundle now", type="primary"):
            tamper_okf.restore(bundle_path, bundle_id)
            st.rerun()

col_a, col_b = st.columns([3, 2])

# ── Panel A: bundle integrity at rest (DISK) ────────────────────────────────

with col_a:
    st.markdown("<div class='surface'>Surface 1 — disk</div>", unsafe_allow_html=True)
    st.subheader("A. Bundle integrity (at rest)")
    st.caption(
        "Public keys only. No vector store, no private key — the same checks "
        "`verify.py --okf-bundle` runs, from the same library function."
    )

    report = verify_bundle(bundle_path, bundle_id, roots, publisher_vk, keyring)

    if report.get("error"):
        st.error(report["error"])
    else:
        st.caption(
            f"Signed {report['signed_at'] or '(unknown)'} by **{report['publisher_key_id'] or '(unknown)'}** "
            f"· canonicalization `{OKF_CANON_VERSION}`"
        )
        root_ok = report["root_matches"]
        check_row("1", "Merkle root recomputation", root_ok,
                  f"{'MATCHES' if root_ok else 'MISMATCH'} {report['recomputed_root'][:12]}…")
        check_row("2", f"Bundle root signature ({report['publisher_key_id']})",
                  report["root_signature_valid"], "VALID" if report["root_signature_valid"] else "INVALID")
        set_ok = not report["added_concepts"] and not report["removed_concepts"]
        check_row("3", f"Concept set ({report['signed_concept_count']} signed / "
                       f"{report['disk_concept_count']} on disk)", set_ok,
                  "no additions or removals" if set_ok
                  else f"added={report['added_concepts']} removed={report['removed_concepts']}")

        if not root_ok:
            st.info(
                "The recomputed root differs from the signed root, so every concept's "
                "Merkle proof is checked against a root that has **moved** — sibling "
                "concepts report `merkle proof failed` even though their own bytes are "
                "intact. The one reporting `concept canonical-hash mismatch` is the "
                "edited concept."
            )

        st.markdown(f"**[4] Per-concept integrity + authenticated trust** ({len(report['concepts'])} concepts)")
        for c in report["concepts"]:
            trust = c["trust"]
            tier = trust["tier"] if trust["tier"] == trust["claimed_tier"] \
                else f"{trust['tier']} (claimed: {trust['claimed_tier']})"
            marks = chip(not c["tampered"], "verified" if not c["tampered"] else c["reason"])
            if trust["downgraded"]:
                marks += " " + chip(False, "DOWNGRADED", "the claimed actor never signed this entry")
            st.markdown(
                f"<div class='row'><code>{c['concept_id']}</code> &nbsp; {marks} "
                f"&nbsp; <small>trust: {tier}</small></div>",
                unsafe_allow_html=True,
            )

        if report["pins"]:
            st.markdown(f"**[5] Computation pins** ({len(report['pins'])} Attested Computations)")
            for p in report["pins"]:
                st.markdown(
                    f"<div class='row'><code>{p['concept_id']}</code> &nbsp; "
                    f"{chip(p['ok'], 'verified' if p['ok'] else p['reason'])}</div>",
                    unsafe_allow_html=True,
                )

        overall = report["ok"] and not report["trust_downgraded"]
        st.markdown("---")
        st.markdown(
            f"### {'✅ PASS' if overall else '❌ FAIL'}",
        )
        if report["ok"] and report["trust_downgraded"]:
            st.caption(
                "Bundle integrity is green — `verify_bundle`'s own `ok` is True. The FAIL "
                "is a **trust policy** refusal applied on top: a downgraded tier is a policy "
                "question (`enforce.admit_concept` always refuses it), not an integrity defect."
            )

# ── Panel B: the adversary (writes DISK) ────────────────────────────────────

with col_b:
    st.markdown("<div class='surface'>Surface 1 — disk (write)</div>", unsafe_allow_html=True)
    st.subheader("B. The adversary")
    st.caption(
        "A write-capable actor on a bundle in transit between orgs. Each attack "
        "self-checks its own before/after digests and refuses to write if the "
        "mutation would not have the effect it advertises."
    )

    try:
        concept_ids = [c["concept_id"] for c in parse_bundle(bundle_path, bundle_id)]
    except Exception as e:  # a mid-tamper parse failure must not blank the page
        st.error(f"could not parse the bundle: {e}")
        concept_ids = []

    def _default(cid: str) -> int:
        return concept_ids.index(cid) if cid in concept_ids else 0

    target = st.selectbox("Target concept", concept_ids, index=_default(DEFAULT_COMPUTATION))

    def _attack(fn, *args, **kwargs):
        try:
            st.session_state["last_attack"] = fn(bundle_path, bundle_id, *args, **kwargs)
        except tamper_okf.TamperError as e:
            # A failed self-check writes nothing. That is worth showing, not hiding.
            st.session_state["last_attack"] = None
            st.session_state["last_error"] = str(e)
        st.rerun()

    c1, c2 = st.columns(2)
    with c1:
        if st.button("🧪 swap-fence", use_container_width=True,
                     help="Rewrite the sanctioned SQL. Native §10.5 attestation passes; the pin does not."):
            _attack(tamper_okf.swap_fence, target)
        if st.button("🧪 forge-tier", use_container_width=True,
                     help="Add an unsigned `verified:` entry claiming a human reviewed this."):
            _attack(tamper_okf.forge_tier, target, "human:attacker")
    with c2:
        if st.button("🧪 swap-attester", use_container_width=True,
                     help="Replace the attester with always-ok code. No concept digest moves."):
            _attack(tamper_okf.swap_attester, target)
        if st.button("♻️ benign-round-trip", use_container_width=True,
                     help="An agent rewrite: key order, YAML spelling, whitespace. Nothing signed moves."):
            _attack(tamper_okf.benign_round_trip, target)

    if st.button("💀 forge-tier + re-sign as the publisher", use_container_width=True,
                 help="Models an adversary who is ALSO the re-publisher. Only the per-actor "
                      "trust check survives this."):
        _attack(tamper_okf.forge_tier, target, "human:attacker", resign=True)

    st.markdown("---")
    b1, b2 = st.columns(2)
    with b1:
        if st.button("🧹 Restore", use_container_width=True):
            tamper_okf.restore(bundle_path, bundle_id)
            st.session_state["last_attack"] = None
            st.rerun()
    with b2:
        # force=True only, NEVER resign=True: re-ingesting must move the store
        # surface, never launder a tamper by re-publishing it. Re-signing stays a
        # deliberate CLI act (`okf_ingest --resign`).
        if st.button("🔄 Re-ingest (--force)", use_container_width=True,
                     help="Move the STORE surface to match disk. Watch Panel C change and Panel A not."):
            from src.okf_ingest import ingest_bundle

            with st.spinner("Re-embedding concepts…"):
                ingest_bundle(bundle_path, bundle_id, load_okf_collection(), load_embed_model(), force=True)
            st.rerun()

    if st.session_state.get("last_error"):
        st.error(f"TamperError — nothing was written:\n\n{st.session_state.pop('last_error')}")
    if st.session_state.get("last_attack"):
        result = st.session_state["last_attack"]
        st.markdown(f"**Last attack: `{result['attack']}` on `{result['concept_id']}`**")
        digest_table(result)

# ── Panel C: the admission gate (reads CHROMA) ──────────────────────────────

st.markdown("---")
st.markdown("<div class='surface'>Surface 2 — vector store</div>", unsafe_allow_html=True)
st.subheader("C. The admission gate (at the point of use)")
st.caption(
    "Retrieve → verify → admit or refuse. A refused concept never enters the "
    "model's context. This panel reads the Chroma row that was written at ingest "
    "time, which is why it can stay green while Panel A is red — until Re-ingest."
)

with st.form("okf_query"):
    question = st.text_input("Question", value="What is Acme's revenue definition?")
    submitted = st.form_submit_button("Run the gate")

if submitted and question.strip():
    collection = load_okf_collection()
    if collection.count() == 0:
        st.error(
            f"The {OKF_COLLECTION_NAME!r} collection is empty — run "
            f"`uv run python -m src.okf_ingest {bundle_path}` first."
        )
    else:
        client = load_openai_client() if use_llm else None
        service_sk = None
        if use_llm or run_concept.strip():
            try:
                service_sk = load_signing_key(SERVICE_SIGNING_KEY_PATH)
            except FileNotFoundError:
                st.error(f"Missing {SERVICE_SIGNING_KEY_PATH}. Run scripts/generate_keys.py.")
                st.stop()

        with st.spinner("Retrieving and verifying…"):
            st.session_state["gate"] = run_agent(
                question, collection, load_embed_model(), client, roots, publisher_vk, keyring,
                today=today,
                bundle_id=bundle_id,
                n_results=n_results,
                min_tier=min_tier,
                no_llm=not use_llm,
                run_concept=run_concept.strip() or None,
                params={"year": run_year} if run_concept.strip() else {},
                service_sk=service_sk,
                service_key_id=SERVICE_KEY_ID,
                model=LLM_MODEL,
            )

gate = st.session_state.get("gate")
if gate:
    for i, d in enumerate(gate["decisions"], start=1):
        tier = d["tier"] if d["tier"] == d["claimed_tier"] else f"{d['tier']} (claimed: {d['claimed_tier']})"
        st.markdown(
            f"<div class='row'><b>[{i}]</b> <code>{d['concept_id']}</code> &nbsp; "
            f"{chip(d['admitted'], 'ADMITTED' if d['admitted'] else 'REFUSED')} "
            f"&nbsp; <small>trust: {tier}</small></div>",
            unsafe_allow_html=True,
        )
        with st.expander("checks", expanded=not d["admitted"]):
            for name, check in d["checks"].items():
                st.markdown(
                    f"<div class='row'>{chip(check['ok'], name)} &nbsp; <small>{check['reason']}</small></div>",
                    unsafe_allow_html=True,
                )
            for w in d["warnings"]:
                st.caption(f"⚠️ {w}")

    admitted = [d["concept_id"] for d in gate["decisions"] if d["admitted"]]
    st.markdown(f"**Admitted {len(admitted)}/{len(gate['decisions'])}** — {', '.join(admitted) or '(none)'}")
    if gate.get("refused_concept_ids"):
        st.markdown(f"**Refused** — `{'`, `'.join(gate['refused_concept_ids'])}`")

    for run in gate.get("runs", []):
        source = run.get("run", {}).get("claimed_value_source", "?")
        st.markdown(
            f"<div class='row'>Attested run <code>{source}</code> &nbsp; "
            f"{chip(run['ok'], 'PASS' if run['ok'] else 'REFUSED')} &nbsp; "
            f"<small>{run['reason']}</small></div>",
            unsafe_allow_html=True,
        )
        if run.get("receipt"):
            st.caption(f"executed value: {run['receipt']['result']}")
        envelope = run.get("run", {}).get("ite6")
        if envelope:
            st.download_button(
                "Download in-toto ITE-6 run statement (DSSE)",
                data=json.dumps(envelope, indent=2),
                file_name=f"ite6_run_{source}.json",
                mime="application/json",
                key=f"ite6_{source}_{run['reason'][:16]}",
                help="Verify with `uv run python verify.py --verify-ite6-statement <file>`.",
            )

    if gate.get("answer") is not None:
        st.subheader("Answer")
        st.markdown(gate["answer"] if gate["served"] else "_(withheld)_")
        if gate.get("cited"):
            st.caption("Cited: " + ", ".join(gate["cited"]))

    for w in gate.get("warnings", []):
        st.caption(f"⚠️ {w}")
    if gate["reasons"]:
        st.error("NOT SERVED:\n\n" + "\n".join(f"- {r}" for r in gate["reasons"]))
    elif gate.get("answer") is not None:
        st.success("SERVED — every cited concept passed admission")

    if gate.get("attestation"):
        att = gate["attestation"]
        with st.expander(
            f"Signed answer attestation — including {len(att['refused_concept_ids'])} signed refusal(s)"
        ):
            st.caption(
                "The refusals are inside the signed payload, so an auditor can prove a "
                "concept was withheld BY POLICY rather than absent by luck. Re-verify with "
                "`uv run python verify.py --okf-answer -1`."
            )
            st.code(json.dumps(att, indent=2), language="json")
