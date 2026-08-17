# Threat model

This repository carries two tracks on one crypto substrate, and they face different adversaries.
Part 1 covers the arXiv provenance engine — a corpus the operator ingests and serves itself.
Part 2 covers OKF knowledge bundles — a corpus that arrives from another organization, maintained
by agents, and is consumed at runtime. Read Part 2 for the OKF-Verify work; Part 1's key-management
and freshness analysis applies to both and is not repeated.

---

## Part 1 — the arXiv provenance engine

This system makes one precise, narrow claim: **it proves the provenance of an answer, not its truth.** Given an answer and the relevant public keys, any party can verify offline that the answer was produced over a specific, signed snapshot of the source corpus, citing a specific set of source chunks, none of which were altered after that snapshot was signed. It does not, and cannot, certify that the underlying sources are correct, that retrieval surfaced the *right* sources, or that the generated answer is faithful to them. Stating that boundary first is deliberate — most of the value here is in claiming exactly the right amount.

### Assets and security properties

The asset under protection is the *integrity of the source-to-answer chain*, not the confidentiality of the data. Concretely, the system targets four properties:

- **Source integrity** — indexed content cannot be modified after signing without detection.
- **Citation authenticity** — an answer is cryptographically bound to the exact chunks placed in its generation context.
- **Answer non-repudiation** — the signing service cannot later deny having produced a given answer over a given chunk set.
- **Independent verifiability** — verification requires only the public keys and runs with no access to the live system.

Confidentiality and availability are explicit non-goals.

### Trust boundaries and assumptions

There are two distinct signing authorities, kept separate on purpose:

- The **publisher key** signs the per-document Merkle root at ingestion. It attests to the *origin and integrity of sources*.
- The **service key** signs the per-answer attestation at generation. It attests to *what the system did with those sources*.

Separating them means "was a source altered?" and "was an answer forged?" are answerable independently, and compromise of one key does not silently implicate the other.

The system assumes that private keys are generated and held securely and never exposed; that SHA-256 is collision-resistant and Ed25519 is unforgeable under chosen-message attack; that the ingestion host is trustworthy *at the moment of signing* (it is inside the trusted computing base then); and that verifiers obtain authentic public keys through a trusted channel. Key distribution is assumed, not solved here.

### What it defends against

| Adversary | Capability | Mechanism | Status |
|---|---|---|---|
| Corpus tamperer | Alters stored chunk text or vectors after ingestion | Read-hook re-hash + Merkle proof against the signed root | Detected |
| Citation forger | Misrepresents which sources an answer used | Attestation binds the answer to the actual chunk hashes | Detected |
| Answer tamperer | Modifies the answer after generation | Signed `answer_sha256` inside the attestation | Detected |

### What it does not defend against

These are deliberate exclusions, not oversights:

- **Malicious or negligent publisher.** A publisher can sign false content. The system makes that publisher *accountable* — the signature is non-repudiable — but it does not adjudicate truth. Provenance is not correctness.
- **Key compromise.** Theft of either private key breaks the corresponding guarantee. Mitigations (custody discipline, rotation, hardware-backed or threshold signing) are operational and out of scope for the MVP.
- **Retrieval-selection attacks.** An adversary who influences the query or the embedding space can cause retrieval of *authentic but misleading* chunks. Integrity does not imply honest selection.
- **Prompt injection of the generation step.** Instructions smuggled through retrieved content can subvert the answer while every integrity check still passes. This is the domain of a separate adversarial-evaluation harness, not of this layer.
- **Confidentiality and availability.** There is no protection of source secrecy and no resistance to denial of service.

### Known gaps and residual risk

The most interesting residual risk is **freshness / rollback**. Because each ingestion produces an independently signed snapshot, an adversary positioned between the store and the verifier could serve an older, *authentically signed* snapshot to conceal that newer (for example, corrected) content exists. Every signature still verifies; the staleness itself is the attack. The MVP does not address this. The standard remedy is a signed, monotonically increasing timestamp/snapshot role of the kind TUF defines — a natural next increment, and a direct point of contact with the in-toto / TUF / gittuf line of work this project is meant to build toward.

Two smaller gaps are worth naming. Key rotation and revocation are unhandled: a rotated key invalidates prior attestations with no transparency log to reconcile them. And the trust placed in the ingestion host at signing time is a real assumption — anything that corrupts a chunk *before* its hash is computed is signed in as authentic, and no downstream check can recover from that.

**Key management, concretely.** Both signing keys are raw 32-byte Ed25519 seeds held as plain files under `data/keys/*.sk`, readable by anyone with filesystem access to the ingestion/service host — there is no HSM, KMS, or OS keychain integration, and no passphrase or at-rest encryption. Exactly one active key exists per role at a time; nothing enforces or records rotation. A real deployment would need: (1) private keys held in an HSM or cloud KMS (AWS KMS, GCP Cloud KMS, or a hardware token) so raw key material is never on disk; (2) threshold signing (e.g. the publisher role split across ≥2 of 3 keyholders) so compromise of a single machine cannot forge a root signature; (3) a signed, append-only transparency log of key-rotation events — which key IDs were valid over which time ranges — so a verifier checking an old attestation can tell whether the signing key was still trusted *at attestation time*, not merely whether the signature is cryptographically valid today. None of this is implemented; `service_key_id`/`publisher_key_id` are currently opaque strings (`"service_v1"`, `"publisher_v1"`) with no registry behind them.

Day 12 adds a genuine in-toto Attestation Framework (ITE-6) export — a first, concrete step toward the TUF/in-toto/gittuf direction named above. `src/intoto.py::sign_real_ite6_statement()` / `verify_real_ite6_statement()` target the current in-toto Attestation Framework Link predicate spec — https://github.com/in-toto/attestation/blob/main/spec/predicates/link.md — producing a DSSE-enveloped Statement (`_type`/`subject`/`predicateType`/`predicate`, materials as an array of `ResourceDescriptor` objects) using the `in-toto-attestation` package's protobuf-backed classes and `securesystemslib`'s DSSE `Envelope`, both reference implementations for their respective specs. Confirmed working end to end (sign, tamper, re-verify-fails, and verified immune to `securesystemslib.signer.Signature.from_dict()`'s documented destructive-pop side effect via a defensive deep-copy) against Python 3.12 with the optional `intoto` extra (`uv sync --extra intoto`). It is wired into the live system: the Streamlit UI's "Download in-toto link" button signs it using the service private key already in scope at generation/render time (the same trust boundary the ordinary attestation signature already relies on — no new key exposure), and `verify.py --verify-ite6-statement PATH` independently checks it using only the service **public** key, consistent with this file's own verifier ethos. This is a *format* bridge only — it maps the existing Ed25519-signed attestation into in-toto's vocabulary and does not itself add a timestamp/snapshot role or otherwise close the freshness/rollback gap described above, which still requires a genuine TUF-style monotonic snapshot role layered on top, remaining future work.

---

## Part 2 — OKF knowledge bundles: adversary, surfaces, and residual risk

Part 1's corpus is one the operator fetched and signed itself. An OKF bundle is not: it is
maintained by agents, exchanged between organizations, and consumed by an agent at runtime. That
changes who the adversary is and where the trust boundary sits.

The claim here is correspondingly narrow: **a concept that reaches the model is byte-identical to
what the publisher signed, every `verified` claim it carries was actually signed by the actor it
names, and any Attested Computation it triggers runs code the publisher pinned.** As in Part 1, none
of this certifies that the content is *true*.

### Adversary

**Primary: a write-capable actor on a bundle in transit.** Between the moment a bundle is signed and
the moment an agent consumes it, the bundle is a directory of files that moves between
organizations, gets re-serialized by agents, and is stored somewhere the consumer does not control.
The adversary can modify any file: concept bodies, frontmatter, the `# Computation` fence, and the
attester code. They do **not** hold the publisher key.

**Stronger, and separately modelled: the malicious re-publisher.** For the forged-trust case the
adversary *also* holds the publisher key and re-signs the bundle after editing it (this is
`tamper_okf.py forge-tier --resign`, demo act 3). The Merkle root recomputes, the root signature is
valid, and the pins check out — every publisher-level control passes. The forged
`verified: {by: human:attacker}` entry is still refused, because `human:attacker` never signed
anything, and the per-actor signature is over `(concept digest, actor, timestamp, kind)` under that
actor's own key. This is the case that shows why per-actor trust is not a restatement of the root
signature: it survives compromise of the publisher role.

Out of scope: an adversary who compromises the publisher *before* signing (the Part 1 assumption,
unchanged — anything corrupted before its digest is computed is signed in as authentic), and an
adversary who steals an actor's private key.

### Two surfaces, checked independently

A tampered bundle has two distinct copies, and conflating them hides attacks:

| Surface | What it is | Who reads it | Check |
|---|---|---|---|
| **Disk** | the bundle directory as it sits on the filesystem | a *run* — the executor and attester read from here | `integrity_on_disk` |
| **Store** | the Chroma row written at ingest time | the *model* — retrieval serves these bytes into the context | `integrity` |

Both are compared against the same publisher-signed digest, never against each other. An adversary
who edits the bundle on disk without triggering a re-ingest moves only the disk surface; one who
reaches the vector store moves only the store surface. Because each is independently anchored to the
signed digest, compromising one does not move the other, and passing both means the two are
necessarily identical — so no third store-versus-disk comparison is needed. Demo act 4 shows the two
diverging on screen.

Every at-rest verifier that exists for OKF checks the directory. Nothing before this checked the
bytes the model actually reads.

### What is detected

Enforcement happens at the point of use: [`src/enforce.py`](../src/enforce.py)'s `admit_concept`
runs eight named checks and a refused concept never enters the LLM's context. It deliberately does
not short-circuit — a concept that is simultaneously tampered, trust-forged, and stale reports all
three, because naming every reason is the product.

| Attack | Mechanism that catches it | Check |
|---|---|---|
| Edit a concept's body or frontmatter | canonical digest ≠ publisher-signed digest; Merkle proof fails against the signed root | `integrity`, `integrity_on_disk` |
| Swap the `# Computation` fence | digest of the canonicalized computation ≠ publisher-signed pin, checked *before* execution | `pins` |
| Swap the attester code | digest of the attester resource ≠ publisher-signed pin, checked *before* the module is imported | `pins` |
| Forge a `verified` entry (even with a re-signed root) | no valid per-actor signature over `(concept digest, actor, at, kind)` | `trust_authentic` |
| Add or remove a concept | signed concept set ≠ on-disk concept set | verifier row `[3]` |
| Serve a deprecated or expired concept | `status: deprecated`; `today > stale_after` | `status`, `freshness` |
| Cite a tampered or absent bundle-local source | the source's own digest is re-checked | `sources` |
| Benign agent re-serialization (**must NOT be detected**) | canonicalization absorbs key reordering, line endings, NFC, YAML style, date spelling | none — stays admitted |

That last row is a security property in both directions. A verifier that fires on legitimate agent
rewrites trains its operator to ignore it.

Two distinctions in the trust check are load-bearing:

- **Unbacked or invalid signatures are refusals; an unknown actor is a warning.** An actor missing
  from the keyring means the claim is *unevaluated*, not *disproved* — a key-distribution gap, not
  evidence of forgery. Reporting it as forgery would make every unfamiliar collaborator look like an
  attacker.
- **Forgery detection is wider than tier movement.** Adding `verified: {by: human:attacker}` to a
  concept a real human already verified leaves the tier at `human-reviewed`, so a check that gated
  on tier *downgrade* would silently admit it. The gate refuses on the presence of any unbacked
  claim, whether or not it moved the tier.

The policy floor (`--min-tier`) is separate and defaults to the most permissive value,
`unverified` — both because §5.3 says trust tiers are "advisory signals, not access control" and
consumers "MUST NOT reject" a concept with no trust frontmatter, and so that every refusal in the
demo fires under stock policy rather than a hand-tuned threshold.

### What is not defended against

- **No attester sandbox.** The pins decide *which* attester runs; they do not contain it. The
  attester module is imported in-process, so a publisher who signs a malicious attester still gets
  arbitrary code execution in the consumer. §12 defers the attester ABI, portability, and
  sandboxing; so does this implementation. The pin check strictly precedes the import, which is what
  makes the ordering a control rather than a report, but it is not isolation.
- **Source closure is one level deep and tamper-only.** A cited source is checked for tampering and
  presence; a source that is merely stale or deprecated produces a warning, not a refusal, because
  cascading staleness would refuse most of a bundle the day a policy expires. Following a source's
  own sources needs a cycle guard and a policy for diamond dependencies — real design questions, not
  a one-line extension.
- **No bundle-level freshness or rollback defense.** `data/okf_roots.json` has no TUF-style
  monotonically increasing snapshot role, so an older, authentically signed bundle still verifies.
  This is the same residual risk Part 1 names, and it has the same standard remedy; it is not
  re-argued here.
- **No key rotation, revocation, delegation, or thresholds.** Actor keys are raw Ed25519 seeds under
  `data/keys/actors/` and the keyring is a flat actor→key map with no notion of *which* identities
  are permitted to sign *which* concepts, no expiry, and no transparency log. Part 1's key-management
  paragraph applies verbatim, and the multiplication is the point: one publisher key and one service
  key become one key per claimed actor. **Which identities may sign which concepts, and how that
  trust is delegated, rotated, revoked, and threshold-protected, is the open research problem this
  work is meant to motivate** — TUF's delegation model applied to knowledge bundles.
- **Trust in the publisher at signing time**, and **retrieval-selection attacks**, and **prompt
  injection through admitted content**: unchanged from Part 1, still true here. Every integrity
  check can pass on a concept whose prose is adversarial.

### Relation to `signed-okf`

`signed-okf` is the closest prior work and does something real: a whole-bundle, single-issuer,
raw-byte Ed25519 signature with at-rest CLI verification, which does partially mitigate third-party
tampering of concept files. Stated as security deltas rather than features, it leaves four things
open:

1. **Raw-byte hashing** breaks on the benign re-serializations §5.1 explicitly anticipates ("agents
   constantly rewrite these documents"), so in an agent-maintained corpus its failures and its
   attacks look identical.
2. **One issuer over the whole bundle** means `verified: human:alice` remains a string alice never
   signed; the malicious-re-publisher case above passes it entirely.
3. **The attester is not a concept file**, so a whole-bundle signature over `.md` files does not
   cover the code that decides whether a computation's result may be displayed — see
   [`FINDING-attestation-integrity.md`](FINDING-attestation-integrity.md).
4. **It verifies at rest, not at the point of use**, and never touches the run, so it cannot refuse
   a concept as it enters a model's context.

None of these make it wrong for what it targets. They are the axes this project adds.
