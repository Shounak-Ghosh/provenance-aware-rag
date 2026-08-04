"""Per-actor authenticated trust signatures for OKF v0.2 concepts.

src/okf.py + src/okf_ingest.py (Day 1) answer one question: "is this bundle
byte-identical to what the publisher signed?" They do NOT answer the question
OKF's own trust signals claim to answer: "did `human:jsmith@acme` actually
verify this concept?" A `verified: {by: human:jsmith@acme}` entry is plain
YAML that anyone with write access to the file can author -- a publisher who
writes that line still gets a perfectly valid Merkle root signature over the
lie. §5.3 concedes exactly this: trust tiers are "advisory signals, not
access control."

This module adds a SECOND, independent signing authority:

    Authority        Signs                                Answers
    ---------------  -----------------------------------  --------------------------------
    publisher key    the Merkle root over concept digests  "is this bundle as published?"
    actor key        one signature per verified/generated  "did THIS actor make this claim?"
                      entry, under that actor's own key

A forged `verified:` line added before the publisher signs still produces a
valid root signature -- the publisher cannot speak for jsmith. Under OKF's
own cross-org, agent-maintained distribution model (§1), publisher != actor
is the normal case, not a corner case. The gate that proves this module is
not redundant with the Day-1 Merkle root: forge a tier, RE-SIGN the root over
the forged bundle, and the root signature still comes back valid while
derive_authenticated_tier() still refuses to raise the tier -- see
tests/test_okf_verify.py::test_resigned_forged_tier_still_downgrades.

A second property falls out for free: because the trust message binds the
concept's own content digest (see trust_message()), editing a verified
concept silently invalidates every existing signature on it -- the actor
signed a claim about specific bytes, not about "whatever this path currently
contains." An attacker who edits a verified concept doesn't just fail to add
a new authenticated claim; they revoke the real one, and the tier drops to
"unverified" until the actor re-attests.

HONEST NOTE ON KEY CUSTODY: this demo mints and holds all actor keys itself
(see ensure_actor_key()), so it simulates a multi-party world rather than
being one. That's fine -- the contribution is the verification logic below,
which behaves identically regardless of who custodies the keys -- but it
should never be presented as if jsmith and kliu signed anything themselves.

The keyring (data/keys/actors/keyring.json) is itself trusted by plain
distribution; nothing signs the actor-set. A signed root role over the
keyring, and a signed manifest over the trust-signature set, are the
TUF-shaped next increments -- research-runway material, not this pass.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

import nacl.signing

from src.config import (
    ACTOR_KEYRING_PATH,
    ACTOR_KEYS_DIR,
    OKF_KEYRING_VERSION,
    OKF_TRUST_VERSION,
)
from src.crypto import generate_keypair, load_signing_key, sign, verify
from src.okf import _as_list, _no_delimiters
from src.schema import ConceptRecord, TrustAssessment, TrustSignature

_ACTOR_PREFIX_KIND = {"human:": "human", "team:": "team", "process:": "process"}


# ── the signed message ────────────────────────────────────────────────────
def trust_message(bundle_id: str, concept_id: str, concept_sha256: str, actor: str, at: str, kind: str) -> bytes:
    """Domain-separated, unambiguous message for one trust-entry signature.

    Binds FOUR things, each closing a specific gap:
      * concept_sha256 -- the claim is about these exact bytes (revocation-on-edit, see module docstring)
      * concept_id -- okf.canonicalize_concept does NOT hash the path, so a
        signature bound only to the digest would transfer to any
        identical-content concept at a different path
      * bundle_id -- blocks replaying a signature from one bundle into another
      * kind -- "verified" and "generated" are different claims; a signature
        over one must not be mistakable for the other
    """
    _no_delimiters(bundle_id, concept_id, concept_sha256, actor, at, kind)
    return f"{OKF_TRUST_VERSION}|{bundle_id}|{concept_id}|{concept_sha256}|{actor}|{at}|{kind}".encode()


# ── what is signable, read from the NORMALIZED frontmatter ─────────────────
def trust_entries(concept: ConceptRecord) -> list[tuple[str, str, str]]:
    """Every (actor, at, kind) claim a concept's frontmatter makes.

    Single source of truth for "what is signable" -- shared by the signer
    (scripts/sign_trust.py) and the verifier (derive_authenticated_tier)
    below, so the two can never disagree about which entries exist. §5.2
    permits `verified`/`generated` as a bare mapping OR a list of mappings
    (_as_list handles both). Reads concept["frontmatter"], which is already
    the NORMALIZED form (dates -> ISO-Z strings, NFC) that fed the concept's
    own digest -- never re-parse raw YAML here, or signer and verifier could
    sign/verify different bytes for the same logical `at`.
    """
    fm = concept["frontmatter"]
    entries: list[tuple[str, str, str]] = []
    for e in _as_list(fm.get("verified")):
        if isinstance(e, dict) and e.get("by"):
            entries.append((str(e["by"]), str(e.get("at", "")), "verified"))
    for e in _as_list(fm.get("generated")):
        if isinstance(e, dict) and e.get("by"):
            entries.append((str(e["by"]), str(e.get("at", "")), "generated"))
    return entries


def index_trust_signatures(sigs: list[TrustSignature]) -> dict[tuple[str, str, str, str], TrustSignature]:
    """Index by (concept_id, actor, at, kind) -- the same tuple trust_entries() yields.

    A duplicate key is a hard error: two signatures claiming to cover the
    same (concept, actor, timestamp, kind) is either a bug in the signer or
    an attempt to smuggle a second, different signature in past the first.
    """
    index: dict[tuple[str, str, str, str], TrustSignature] = {}
    for s in sigs:
        key = (s["concept_id"], s["actor"], s["at"], s["kind"])
        if key in index:
            raise ValueError(f"duplicate trust signature for {key}")
        index[key] = s
    return index


# ── the tier ladder (§5.3), applied to either the raw YAML or the authenticated set ──
def _tier(verified_actors: list[str]) -> str:
    """§5.3's ladder as one adjustable constant. Confirmed against Google's
    own reference renderer (bundles/acme_retail/viz.html's window.BUNDLE,
    see tests/test_trust.py::test_claimed_tier_matches_reference_viz): no
    verified entry -> unverified; any `human:`-prefixed verified actor ->
    human-reviewed; otherwise -> machine-confirmed. `log.md`'s own prose
    ("Initial trust tier: machine-confirmed across the board") reads
    differently for freshly-bootstrapped concepts, but the reference
    renderer's *code* is the interop oracle here, not the changelog prose.
    """
    if not verified_actors:
        return "unverified"
    if any(a.startswith("human:") for a in verified_actors):
        return "human-reviewed"
    return "machine-confirmed"


def claimed_tier(concept: ConceptRecord) -> str:
    """The tier implied by the plaintext `verified` YAML alone -- what
    viz.html shows, and what a signal-trusting (non-verifying) consumer
    would act on. Exists specifically so derive_authenticated_tier() below
    can be compared against it."""
    actors = [by for by, _at, kind in trust_entries(concept) if kind == "verified"]
    return _tier(actors)


def derive_authenticated_tier(
    bundle_id: str,
    concept: ConceptRecord,
    sig_index: dict[tuple[str, str, str, str], TrustSignature],
    keyring: dict[str, nacl.signing.VerifyKey],
) -> TrustAssessment:
    """The gap-closing function: the tier an agent may actually act on.

    Applies the same ladder as claimed_tier(), but only to `verified` actors
    whose entry carries a signature that (a) exists, (b) comes from a key
    this verifier recognizes for that actor, and (c) verifies against the
    concept's CURRENT content digest. Everything else is bucketed by why it
    didn't count, not silently dropped:

      * unbacked      -- claimed actor, no signature present at all (the
                          native-OKF gap this module closes)
      * unknown_actor -- actor absent from the keyring (a key-distribution
                          gap, NOT evidence of forgery -- don't conflate them)
      * invalid       -- signature present, actor known, but verification
                          fails (content changed since signing, or a genuine forgery)
    """
    claimed = claimed_tier(concept)
    authenticated: list[str] = []
    unbacked: list[str] = []
    unknown_actor: list[str] = []
    invalid: list[str] = []

    for actor, at, kind in trust_entries(concept):
        if kind != "verified":
            continue
        sig = sig_index.get((concept["concept_id"], actor, at, "verified"))
        if sig is None:
            unbacked.append(actor)
            continue
        if actor not in keyring:
            unknown_actor.append(actor)
            continue
        if verify_trust_entry(sig, concept["sha256"], keyring):
            authenticated.append(actor)
        else:
            invalid.append(actor)

    tier = _tier(authenticated)
    return {
        "concept_id": concept["concept_id"],
        "claimed_tier": claimed,
        "tier": tier,
        "authenticated": authenticated,
        "unbacked": unbacked,
        "unknown_actor": unknown_actor,
        "invalid": invalid,
        "downgraded": tier != claimed,
    }


# ── signing / verifying one entry ───────────────────────────────────────────
def sign_trust_entry(
    bundle_id: str, concept: ConceptRecord, actor: str, at: str, kind: str, actor_sk: nacl.signing.SigningKey
) -> TrustSignature:
    message = trust_message(bundle_id, concept["concept_id"], concept["sha256"], actor, at, kind)
    return {
        "bundle_id": bundle_id,
        "concept_id": concept["concept_id"],
        "actor": actor,
        "at": at,
        "kind": kind,
        "signature": sign(actor_sk, message),  # REUSE crypto.sign
    }


def verify_trust_entry(sig: TrustSignature, concept_sha256: str, keyring: dict[str, nacl.signing.VerifyKey]) -> bool:
    """Return True iff sig is a valid signature, under the CLAIMED actor's
    keyring key, over trust_message(...) for the given current content digest.
    False (not an exception) if the actor isn't in the keyring -- callers
    that need to distinguish "unknown actor" from "invalid signature" should
    check keyring membership themselves first (derive_authenticated_tier does)."""
    vk = keyring.get(sig["actor"])
    if vk is None:
        return False
    message = trust_message(sig["bundle_id"], sig["concept_id"], concept_sha256, sig["actor"], sig["at"], sig["kind"])
    return verify(vk, message, sig["signature"])  # REUSE crypto.verify


# ── actor identity + keyring (D2) ───────────────────────────────────────────
def actor_kind(actor: str) -> str:
    """§7 actor convention: `human:`/`team:`/`process:` prefix, else a bare
    `<producer>/<version>` agent identity."""
    for prefix, kind in _ACTOR_PREFIX_KIND.items():
        if actor.startswith(prefix):
            return kind
    return "agent"


def _actor_slug(actor: str) -> str:
    """Readable-but-safe filename for an actor's key material. Not the
    identity itself (the keyring JSON's `actor` key is that) -- collisions
    are irrelevant to correctness, only to demo readability, so a short
    content hash suffix is enough to make them practically impossible."""
    base = re.sub(r"[^A-Za-z0-9._-]", "_", actor)[:48]
    digest = hashlib.sha256(actor.encode()).hexdigest()[:8]
    return f"{base}-{digest}"


def _load_keyring_raw(path: Path = ACTOR_KEYRING_PATH) -> dict:
    if not path.exists():
        return {"version": OKF_KEYRING_VERSION, "actors": {}}
    return json.loads(path.read_text())


def _save_keyring_raw(data: dict, path: Path = ACTOR_KEYRING_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True))


def load_keyring(path: Path = ACTOR_KEYRING_PATH) -> dict[str, nacl.signing.VerifyKey]:
    """actor -> VerifyKey, for every actor currently in the keyring. Missing
    file -> {} (every trust entry then lands in `unknown_actor`, not a crash --
    an unpopulated keyring is a key-distribution gap, not fatal)."""
    raw = _load_keyring_raw(path)
    return {
        actor: nacl.signing.VerifyKey(base64.b64decode(rec["verify_key"]))
        for actor, rec in raw.get("actors", {}).items()
    }


def ensure_actor_key(
    actor: str, *, keys_dir: Path = ACTOR_KEYS_DIR, keyring_path: Path = ACTOR_KEYRING_PATH
) -> nacl.signing.SigningKey:
    """Mint a keypair for `actor` if the keyring has none yet, register it,
    and return the signing key. Idempotent: an existing entry's key is
    reused. Only scripts/sign_trust.py (an explicit, offline signing step)
    calls this -- verification code never mints keys."""
    raw = _load_keyring_raw(keyring_path)
    raw.setdefault("version", OKF_KEYRING_VERSION)
    raw.setdefault("actors", {})
    rec = raw["actors"].get(actor)
    if rec is not None:
        sk_path = keys_dir / rec["sk_file"]
        if sk_path.exists():
            return load_signing_key(sk_path)
        # keyring entry survived but the .sk file didn't (e.g. gitignored,
        # never committed on this machine) -- remint under the same slug.

    slug = _actor_slug(actor)
    sk, vk = generate_keypair()  # REUSE crypto.generate_keypair
    keys_dir.mkdir(parents=True, exist_ok=True)
    sk_path = keys_dir / f"{slug}.sk"
    sk_path.write_bytes(bytes(sk))

    raw["actors"][actor] = {
        "key_id": slug,
        "verify_key": base64.b64encode(bytes(vk)).decode(),
        "sk_file": sk_path.name,
        "kind": actor_kind(actor),
    }
    _save_keyring_raw(raw, keyring_path)
    return sk


def load_actor_signing_key(
    actor: str, *, keys_dir: Path = ACTOR_KEYS_DIR, keyring_path: Path = ACTOR_KEYRING_PATH
) -> nacl.signing.SigningKey:
    raw = _load_keyring_raw(keyring_path)
    rec = raw.get("actors", {}).get(actor)
    if rec is None:
        raise KeyError(f"no keyring entry for actor {actor!r} -- run with --mint-missing first")
    return load_signing_key(keys_dir / rec["sk_file"])
