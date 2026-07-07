## Threat model

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
