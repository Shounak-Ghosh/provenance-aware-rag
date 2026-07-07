"""Build and verify a genuine in-toto Attestation Framework (ITE-6) Statement.

`sign_real_ite6_statement()` / `verify_real_ite6_statement()` build and
DSSE-sign a Statement with a Link predicate, matching
https://github.com/in-toto/attestation/blob/main/spec/predicates/link.md
exactly: `_type`/`subject`/`predicateType`/`predicate`, with `materials` as
an array of ResourceDescriptor objects. Uses the `in-toto-attestation`
package's protobuf-backed Statement/ResourceDescriptor classes to build the
payload and securesystemslib's DSSE Envelope to sign it — both reference
implementations for their respective specs (ITE-6 and DSSE). Re-keys our raw
PyNaCl Ed25519 keys into securesystemslib key objects.

Requires the optional `intoto` extra (`uv sync --extra intoto`) — imports
are done lazily inside these functions so importing this module never
requires it to be installed. See docs/THREAT_MODEL.md and README.md's
"in-toto export" section for the full writeup.
"""

_LINK_NAME_DEFAULT = "generate-answer"
_ITE6_PREDICATE_TYPE = "https://in-toto.io/attestation/link/v0.3"
_ITE6_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def chunk_materials_from_hashes(chunk_hashes: list[str]) -> list[dict]:
    """Degraded-path materials: bare sha256 only, no chunk_id/doc_id/merkle_root.

    Used when no enriched chunk data is available.
    """
    return [{"sha256": h} for h in chunk_hashes]


def sign_real_ite6_statement(
    attestation: dict,
    materials: list[dict] | None,
    signing_key,
    key_id: str,
    name: str = _LINK_NAME_DEFAULT,
) -> dict:
    """Build and DSSE-sign a genuine in-toto Attestation Framework (ITE-6)
    Statement with a Link predicate — matches
    https://github.com/in-toto/attestation/blob/main/spec/predicates/link.md
    exactly: `_type`/`subject`/`predicateType`/`predicate`, with `materials`
    as an array of ResourceDescriptor objects. Uses the `in-toto-attestation`
    package's protobuf-backed Statement/ResourceDescriptor classes to build
    the payload and securesystemslib's DSSE Envelope to sign it — both are
    reference implementations for their respective specs (ITE-6 and DSSE).

    Re-keys our raw PyNaCl Ed25519 `signing_key` (a nacl.signing.SigningKey)
    into a securesystemslib key object. Requires the optional `intoto`
    extra: `uv sync --extra intoto`.
    """
    import json as _json

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from google.protobuf.json_format import MessageToDict
    from in_toto_attestation.v1.resource_descriptor import ResourceDescriptor
    from in_toto_attestation.v1.statement import Statement
    from securesystemslib.dsse import Envelope
    from securesystemslib.signer import CryptoSigner, SSlibKey

    if materials is None:
        materials = chunk_materials_from_hashes(attestation["chunk_hashes"])

    subject = ResourceDescriptor(name="answer", digest={"sha256": attestation["answer_sha256"]})
    materials_rd = [
        MessageToDict(
            ResourceDescriptor(
                name=(m.get("chunk_id") or m["sha256"]), digest={"sha256": m["sha256"]}
            ).pb
        )
        for m in materials
    ]
    predicate = {
        "name": name,
        "command": [],
        "materials": materials_rd,
        "byproducts": {},
        "environment": {
            "model": attestation["model"],
            "timestamp": attestation["timestamp"],
            "query_sha256": attestation["query_sha256"],
        },
    }
    statement = Statement([subject.pb], _ITE6_PREDICATE_TYPE, predicate)
    statement.validate()
    payload = _json.dumps(MessageToDict(statement.pb)).encode()

    private_key = Ed25519PrivateKey.from_private_bytes(bytes(signing_key))
    sslib_key = SSlibKey(
        keyid=key_id,
        keytype="ed25519",
        scheme="ed25519",
        keyval={"public": bytes(signing_key.verify_key).hex()},
    )
    signer = CryptoSigner(private_key, sslib_key)

    envelope = Envelope(payload=payload, payload_type=_ITE6_PAYLOAD_TYPE, signatures={})
    envelope.sign(signer)
    return envelope.to_dict()


def verify_real_ite6_statement(envelope_dict: dict, verify_key, key_id: str) -> bool:
    """Verify a DSSE-enveloped ITE-6 Statement produced by
    sign_real_ite6_statement(), using securesystemslib's own DSSE verify
    path, given our raw PyNaCl `verify_key` (a nacl.signing.VerifyKey).
    Requires the optional `intoto` extra.

    Deep-copies envelope_dict before handing it to Envelope.from_dict():
    securesystemslib.signer.Signature.from_dict() documents "Side Effect:
    Destroys the metadata dict passed by reference" (it .pop()s keyid/sig
    off each signature entry), so without the copy, calling this twice on
    the same dict (e.g. Streamlit re-rendering the same session_state
    object) would silently corrupt it after the first call.
    """
    import copy

    from securesystemslib.dsse import Envelope
    from securesystemslib.signer import SSlibKey

    envelope = Envelope.from_dict(copy.deepcopy(envelope_dict))
    pubkey = SSlibKey(
        keyid=key_id, keytype="ed25519", scheme="ed25519", keyval={"public": bytes(verify_key).hex()}
    )
    try:
        envelope.verify([pubkey], threshold=1)
        return True
    except Exception:
        return False


def decode_ite6_payload(envelope_dict: dict) -> dict:
    """Return the decoded ITE-6 Statement (dict) from a DSSE envelope's
    base64 `payload` field — for DISPLAY only, not verification. Pure
    stdlib (base64 + json), no `intoto` extra required, so it's always
    available even where sign/verify aren't. Decoding does not confirm the
    signature is valid; pair with verify_real_ite6_statement() for that.
    """
    import base64
    import json

    return json.loads(base64.b64decode(envelope_dict["payload"]))
