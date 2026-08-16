#!/usr/bin/env bash
#
# The OKF-Verify argument, end to end, on the committed bundle.
#
# Six acts. Each one mutates real files, shows what the verifier and the
# admission gate do about it, and restores before the next act begins. The
# script refuses to start on a dirty tree and restores from a trap, so an
# interrupt (Ctrl-C) in the middle of an act still leaves the repo clean.
#
#     bash scripts/demo.sh              # run everything, unattended
#     DEMO_PAUSE=1 bash scripts/demo.sh # wait for Enter between acts (recording)
#     bash scripts/demo.sh --act 1      # one act only
#     bash scripts/demo.sh --list       # print the acts and exit
#
# Act 5 needs OPENAI_API_KEY and is skipped with a note when it is unset:
# every claim this script makes is reproducible with no secrets at all.
#
# Escape hatch that does not depend on this script:
#     git checkout -- bundles/acme_retail data/okf_roots.json
#     uv run python -m src.okf_ingest bundles/acme_retail --force
set -euo pipefail

BUNDLE="bundles/acme_retail"
BUNDLE_ID="acme_retail"
COMPUTATION="computations/revenue-ytd"
TRUST_CONCEPT="metrics/revenue"
TODAY="2026-08-01"
PY="uv run python"
INGESTED=0
DIRTY=0        # 1 once an act has mutated the bundle; keeps the EXIT trap quiet
               # (and keeps it from re-ingesting) when there is nothing to undo

# ── output helpers ──────────────────────────────────────────────────────────

say() {
    echo
    echo "══════════════════════════════════════════════════════════════════════"
    echo "  $*"
    echo "══════════════════════════════════════════════════════════════════════"
    echo
}

note() { echo "-- $*"; }

# Echo the command, then run it. The recording has to show what produced
# each block of output, not just the output.
run() {
    echo "\$ $*"
    "$@"
    echo
}

# Same, but this command is EXPECTED to exit non-zero -- a refusal is the
# product here, so a zero exit is the failure.
run_refused() {
    echo "\$ $*"
    if "$@"; then
        echo "!! FAILED: expected a refusal (non-zero exit), got success"
        exit 1
    fi
    echo
}

# Echo the command but swallow its output. Only used for ingest: loading the
# embedding model prints ~40 lines of HuggingFace chatter that is not part of
# the argument and would bury it in a recording.
run_quiet() {
    echo "\$ $*"
    if ! "$@" >/dev/null 2>&1; then
        echo "!! FAILED. Re-run without the output suppressed to see why:" >&2
        echo "   $*" >&2
        exit 1
    fi
    echo "  (output suppressed -- embedding-model chatter)"
    echo
}

# main_okf.py logs embedding-model loading to stderr at INFO. Its STDOUT -- the
# admission table -- is the thing being demonstrated, so keep that on screen and
# send stderr to a log file instead of letting 40 lines of HuggingFace chatter
# bury it. Nothing is discarded: the file path is printed and the log is kept.
DEMO_LOG="$(mktemp -t okf-demo-log.XXXXXX)"

run_gate() {
    local rc=0
    echo "\$ $*"
    "$@" 2>>"$DEMO_LOG" || rc=$?
    echo "  (stderr -> $DEMO_LOG)"
    echo
    return $rc
}

pause() {
    if [ "${DEMO_PAUSE:-0}" = "1" ]; then
        read -r -p "   [Enter to continue] " _
    fi
}

# ── restore ─────────────────────────────────────────────────────────────────

restore_all() {
    [ "$DIRTY" = "1" ] || return 0
    echo
    note "restoring ${BUNDLE} (and data/okf_roots.json if it was re-signed)"
    $PY scripts/tamper_okf.py restore "$BUNDLE" >/dev/null 2>&1 || true
    if [ "$INGESTED" = "1" ]; then
        note "re-ingesting so the store matches the restored disk"
        $PY -m src.okf_ingest "$BUNDLE" --force >/dev/null 2>&1 || true
    fi
    DIRTY=0
}

# Called at the top of every act that writes to the bundle, so the trap knows
# there is something to undo even if the act dies halfway through.
mark_dirty() { DIRTY=1; }

# ── acts ────────────────────────────────────────────────────────────────────

act0() {
    say "ACT 0 -- the pristine bundle, on both surfaces"
    note "Disk: the at-rest verifier, public keys only, no vector store."
    run $PY verify.py --okf-bundle "$BUNDLE"
    note "Store: the admission gate the agent actually consumes concepts through."
    run_gate $PY main_okf.py "What is Acme's revenue definition?" --no-llm --today "$TODAY"
}

act1() {
    say "ACT 1 -- swap the attester: every integrity check stays green"
    note "attesters/sql_equality.py is not a .md file, so it is not a concept."
    note "No concept digest moves. No Merkle leaf moves. The signed root still"
    note "verifies. A whole-bundle raw-byte signature over the .md files would"
    note "miss this too. Both Attested Computations point at that one file."
    pause
    mark_dirty
    run $PY scripts/tamper_okf.py swap-attester "$BUNDLE" "$COMPUTATION"
    pause

    note "The bundle's own attestation (SPEC §10.5) re-derives from the SAME"
    note "swapped code the executor ran, so it accepts the swap:"
    run $PY -m src.okf_attest "$BUNDLE" "$COMPUTATION" --param year=2026 --native
    pause

    note "The publisher-signed attester pin does not:"
    run_refused $PY -m src.okf_attest "$BUNDLE" "$COMPUTATION" --param year=2026
    pause

    note "[1]-[4] green, [5] red twice. THIS IS THE FIGURE."
    run_refused $PY verify.py --okf-bundle "$BUNDLE"
    restore_all
}

act2() {
    say "ACT 2 -- a benign agent rewrite: the canonicalization win"
    note "Reorder frontmatter keys, re-spell a YAML date, flip flow style to"
    note "block, add CRLF and trailing whitespace. Exactly the round-trips OKF's"
    note "agent-maintained model assumes -- and exactly what breaks a raw-byte"
    note "signer. The raw bytes move; nothing signed does."
    pause
    mark_dirty
    run $PY scripts/tamper_okf.py benign-round-trip "$BUNDLE" "$COMPUTATION"
    pause

    note "The file really did change on disk:"
    run git diff --stat -- "$BUNDLE"
    pause

    note "Still valid, and the pinned computation still runs:"
    run $PY verify.py --okf-bundle "$BUNDLE"
    run $PY -m src.okf_attest "$BUNDLE" "$COMPUTATION" --param year=2026
    restore_all
}

act3() {
    say "ACT 3 -- forge a trust tier and re-sign: the per-actor win"
    note "The adversary is ALSO the re-publisher: they add an unsigned"
    note "'verified: human:attacker' entry and re-sign the root with the"
    note "publisher key. Root recomputes. Root signature valid. Pins fine."
    note "The forged actor still never signed anything."
    pause
    mark_dirty
    run $PY scripts/tamper_okf.py forge-tier "$BUNDLE" "$TRUST_CONCEPT" human:attacker --resign
    pause

    note "[1][2][3][5] green; [4] downgraded, and the CLI refuses on policy:"
    run_refused $PY verify.py --okf-bundle "$BUNDLE"
    pause

    note "And at the point of use, after the store is updated too:"
    INGESTED=1
    run_quiet $PY -m src.okf_ingest "$BUNDLE" --force
    run_gate $PY main_okf.py "What is Acme's revenue definition?" --no-llm --today "$TODAY"
    restore_all
}

act4() {
    say "ACT 4 -- swap the computation, do NOT re-ingest: two surfaces"
    note "Disk and store are independently checkable. Without a re-ingest the"
    note "store still holds the bytes that were signed, so its own integrity"
    note "check stays green while disk goes red -- and the disk-side pin check"
    note "refuses the run regardless."
    pause
    mark_dirty
    run $PY scripts/tamper_okf.py swap-fence "$BUNDLE" "$COMPUTATION"
    pause

    note "Disk: red. One concept's hash moved; its siblings fail against a root"
    note "that moved with it (the verifier says so explicitly)."
    run_refused $PY verify.py --okf-bundle "$BUNDLE"
    pause

    note "Store: the concept row is still intact, and the run is still refused."
    run_gate $PY main_okf.py "How is revenue computed?" --no-llm --today "$TODAY" \
        --run "$COMPUTATION" --param year=2026 || true
    restore_all
}

has_openai_key() {
    # main_okf.py calls load_dotenv(), so a key in .env counts exactly as much
    # as one exported in the shell -- checking only the environment would print
    # "skipped" to users whose key works fine.
    [ -n "${OPENAI_API_KEY:-}" ] || grep -qs '^[[:space:]]*OPENAI_API_KEY=..' .env
}

act5() {
    say "ACT 5 -- the full loop, with a model in it"
    if ! has_openai_key; then
        note "SKIPPED: no OPENAI_API_KEY in the environment or .env."
        note "Everything above this line is reproducible with no secrets;"
        note "the gate table, not the prose answer, is the artifact."
        return 0
    fi
    INGESTED=1
    run_quiet $PY -m src.okf_ingest "$BUNDLE" --force
    note "Run the attested computation, put its attested value in the model's"
    note "context, then feed the number the model wrote BACK to the bundle's"
    note "own attester."
    run_gate $PY main_okf.py "What was FY2026 revenue and how is it computed?" \
        --today "$TODAY" --run "$COMPUTATION" --param year=2026
    pause

    note "Both artifacts re-verify from the logs with public keys only:"
    run $PY verify.py --okf-run -1
    run $PY verify.py --okf-answer -1
}

# ── preflight ───────────────────────────────────────────────────────────────

preflight() {
    if [ ! -f verify.py ] || [ ! -d "$BUNDLE" ]; then
        echo "!! run this from the repository root: bash scripts/demo.sh" >&2
        exit 1
    fi
    if [ ! -f data/keys/publisher.vk ]; then
        echo "!! missing data/keys/publisher.vk -- run: uv run python scripts/generate_keys.py" >&2
        exit 1
    fi
    # A dirty tree means a previous tamper (or a real edit) is still in place;
    # stacking on it would make this script's own restore a lie.
    if [ -n "$(git status --porcelain -- "$BUNDLE" data/okf_roots.json 2>/dev/null)" ]; then
        echo "!! ${BUNDLE} or data/okf_roots.json has uncommitted changes." >&2
        echo "   Restore first:  $PY scripts/tamper_okf.py restore $BUNDLE" >&2
        echo "   Or discard:     git checkout -- $BUNDLE data/okf_roots.json" >&2
        exit 1
    fi
    note "ingesting ${BUNDLE_ID} (idempotent; the gate needs the store)"
    INGESTED=1
    run_quiet $PY -m src.okf_ingest "$BUNDLE"
}

usage_list() {
    cat <<'EOF'
Acts:
  0  the pristine bundle, on both surfaces (disk + store)
  1  swap-attester   -- every integrity check green, native §10.5 accepts, pins refuse
  2  benign-round-trip -- raw bytes move, canonical digest / pins / root do not
  3  forge-tier --resign -- re-signed by the publisher, still refused on trust
  4  swap-fence, no re-ingest -- the disk and store surfaces diverge
  5  the full loop with a model (needs OPENAI_API_KEY; skipped otherwise)

  bash scripts/demo.sh --act N     run one act
  DEMO_PAUSE=1 bash scripts/demo.sh
EOF
}

# ── main ────────────────────────────────────────────────────────────────────

ACT="all"
while [ $# -gt 0 ]; do
    case "$1" in
        --list) usage_list; exit 0 ;;
        --act) ACT="${2:?--act needs a number}"; shift 2 ;;
        --pause) DEMO_PAUSE=1; shift ;;
        -h|--help) usage_list; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage_list >&2; exit 2 ;;
    esac
done

trap restore_all EXIT INT TERM

preflight

case "$ACT" in
    all) act0; pause; act1; pause; act2; pause; act3; pause; act4; pause; act5 ;;
    0) act0 ;;
    1) act1 ;;
    2) act2 ;;
    3) act3 ;;
    4) act4 ;;
    5) act5 ;;
    *) echo "unknown act: $ACT" >&2; usage_list >&2; exit 2 ;;
esac

say "DONE -- the bundle is restored; 'git status' should be clean"
run git status --porcelain -- "$BUNDLE" data/okf_roots.json
run $PY verify.py --okf-bundle "$BUNDLE"
