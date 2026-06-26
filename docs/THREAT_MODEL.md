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
