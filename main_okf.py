#!/usr/bin/env python3
"""OKF agent entrypoint: retrieve -> verify -> admit or refuse -> answer.

Mirrors main.py for the OKF corpus, with one difference that is the whole
point: concepts that fail admission never reach the model. The printed table
shows every retrieved concept with ✅/❌ per check, in the same numbered idiom
verify.py already uses.

    # the gate alone, no API key needed
    uv run python main_okf.py "What is Acme's gross margin definition?" --no-llm

    # strict policy / a future date
    uv run python main_okf.py "..." --min-tier human-reviewed --today 2027-01-02

    # full loop: run the attested computation, then check the model's number
    # back against the bundle's own attester
    uv run python main_okf.py "What was FY2026 revenue?" \\
        --run computations/revenue-ytd --param year=2026
"""
import argparse
import json
import logging
import os
import sys
from datetime import date

from dotenv import load_dotenv

from src.config import (
    ACTOR_KEYRING_PATH,
    EMBED_MODEL_NAME,
    LLM_MODEL,
    OKF_ATTESTATION_LOG_PATH,
    OKF_COLLECTION_NAME,
    OKF_MIN_TIER,
    OKF_ROOTS_PATH,
    OKF_TIER_ORDER,
    PUBLISHER_VERIFY_KEY_PATH,
    SERVICE_KEY_ID,
    SERVICE_SIGNING_KEY_PATH,
)
from src.crypto import load_signing_key, load_verify_key
from src.enforce import run_agent
from src.okf_retrieve import load_okf_roots
from src.store import get_collection
from src.trust import load_keyring


def _parse_params(pairs: list[str]) -> dict[str, str]:
    params: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            raise SystemExit(f"--param must be KEY=VALUE, got {pair!r}")
        key, _, value = pair.partition("=")
        params[key] = value
    return params


def _print_report(result: dict) -> None:
    print("=== OKF admission gate ===")
    print(f"Query:  {result['query']}")
    print(f"Bundle: {result.get('bundle_id', '?')}\n")

    for i, d in enumerate(result["decisions"], start=1):
        mark = "✅ ADMITTED" if d["admitted"] else "❌ REFUSED"
        tier = d["tier"] if d["tier"] == d["claimed_tier"] else f"{d['tier']} (claimed: {d['claimed_tier']})"
        print(f"[{i}] {d['concept_id']:<34} {mark}   trust: {tier}")
        for name, check in d["checks"].items():
            print(f"      {'✅' if check['ok'] else '❌'} {name:<16} {check['reason']}")
        for w in d["warnings"]:
            print(f"      ⚠️  {w}")
        print()

    admitted = [d["concept_id"] for d in result["decisions"] if d["admitted"]]
    print(f"Admitted {len(admitted)}/{len(result['decisions'])}: {', '.join(admitted) or '(none)'}")
    if result.get("refused_concept_ids"):
        print(f"Refused: {', '.join(result['refused_concept_ids'])}")

    for run in result.get("runs", []):
        mark = "✅ PASS" if run["ok"] else "❌ REFUSED"
        src = run.get("run", {}).get("claimed_value_source", "?")
        print(f"\nAttested run [{src}]: {mark} — {run['reason']}")
        if run.get("receipt"):
            print(f"  executed value: {run['receipt']['result']}")

    if result.get("answer") is not None:
        print("\n--- ANSWER ---")
        print(result["answer"] if result["served"] else "(withheld)")
        if result.get("cited"):
            print(f"\nCited: {', '.join(result['cited'])}")

    for w in result.get("warnings", []):
        print(f"⚠️  {w}")
    if result["reasons"]:
        print("\n❌ NOT SERVED:")
        for r in result["reasons"]:
            print(f"   - {r}")
    elif result.get("answer") is not None:
        print("\n✅ SERVED — every cited concept passed admission")

    if result.get("attestation"):
        print(f"\nAnswer attestation appended to {OKF_ATTESTATION_LOG_PATH} "
              f"(signs {len(result['attestation']['refused_concept_ids'])} refusal(s))")


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Query an OKF bundle through the admission gate.")
    parser.add_argument("query")
    parser.add_argument("--bundle-id", help="restrict retrieval to one bundle")
    parser.add_argument("--n-results", type=int, default=5)
    parser.add_argument(
        "--min-tier", default=OKF_MIN_TIER, choices=list(OKF_TIER_ORDER),
        help=f"minimum AUTHENTICATED trust tier to admit (default {OKF_MIN_TIER!r}). A forged or "
             f"unbacked trust claim is refused regardless of this floor.",
    )
    parser.add_argument(
        "--today", help="ISO date used for stale_after checks (default: the real today)"
    )
    parser.add_argument("--no-llm", action="store_true", help="print the gate's table and stop; no API key needed")
    parser.add_argument("--run", metavar="CONCEPT_ID", help="execute this Attested Computation and attest the run")
    parser.add_argument("--param", action="append", default=[], metavar="KEY=VALUE", help="repeatable, for --run")
    parser.add_argument("--json", action="store_true", help="print the raw result as JSON")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s", datefmt="%H:%M:%S")

    try:
        today = date.fromisoformat(args.today) if args.today else date.today()
    except ValueError:
        raise SystemExit(f"--today must be an ISO date (YYYY-MM-DD), got {args.today!r}")

    try:
        publisher_vk = load_verify_key(PUBLISHER_VERIFY_KEY_PATH)
    except FileNotFoundError as e:
        raise SystemExit(f"Missing key: {e}. Run `uv run python scripts/generate_keys.py` first.")

    roots = load_okf_roots(OKF_ROOTS_PATH)
    if not roots:
        print(f"WARNING: {OKF_ROOTS_PATH} not found or empty — every concept will be refused "
              f"as unsigned. Run `uv run python -m src.okf_ingest bundles/<name>` first.\n")

    keyring = load_keyring(ACTOR_KEYRING_PATH)
    collection = get_collection(OKF_COLLECTION_NAME)
    if collection.count() == 0:
        raise SystemExit(
            f"the {OKF_COLLECTION_NAME!r} collection is empty — run "
            f"`uv run python -m src.okf_ingest bundles/acme_retail` first."
        )

    from sentence_transformers import SentenceTransformer  # heavy; only once we know we'll query

    embed_model = SentenceTransformer(EMBED_MODEL_NAME)

    client = None
    service_sk = None
    if not args.no_llm:
        from openai import OpenAI

        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise SystemExit("OPENAI_API_KEY is not set — use --no-llm to exercise the gate without it.")
        client = OpenAI(api_key=api_key)
        try:
            service_sk = load_signing_key(SERVICE_SIGNING_KEY_PATH)
        except FileNotFoundError as e:
            raise SystemExit(f"Missing key: {e}. Run `uv run python scripts/generate_keys.py` first.")
    elif args.run:
        # --run signs a RunRecord under the service key even without an LLM.
        service_sk = load_signing_key(SERVICE_SIGNING_KEY_PATH)

    result = run_agent(
        args.query, collection, embed_model, client, roots, publisher_vk, keyring,
        today=today,
        bundle_id=args.bundle_id,
        n_results=args.n_results,
        min_tier=args.min_tier,
        no_llm=args.no_llm,
        run_concept=args.run,
        params=_parse_params(args.param),
        service_sk=service_sk,
        service_key_id=SERVICE_KEY_ID,
        model=LLM_MODEL,
    )

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        _print_report(result)

    return 0 if not result["reasons"] else 1


if __name__ == "__main__":
    sys.exit(main())
