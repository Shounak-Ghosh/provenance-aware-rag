import base64
from pathlib import Path

import nacl.signing


def generate_keypair() -> tuple[nacl.signing.SigningKey, nacl.signing.VerifyKey]:
    sk = nacl.signing.SigningKey.generate()
    return sk, sk.verify_key


def save_keypair(sk: nacl.signing.SigningKey, sk_path: Path, vk_path: Path) -> None:
    sk_path.parent.mkdir(parents=True, exist_ok=True)
    sk_path.write_bytes(bytes(sk))
    vk_path.write_bytes(bytes(sk.verify_key))


def load_signing_key(path: Path) -> nacl.signing.SigningKey:
    return nacl.signing.SigningKey(path.read_bytes())


def load_verify_key(path: Path) -> nacl.signing.VerifyKey:
    return nacl.signing.VerifyKey(path.read_bytes())


def sign(sk: nacl.signing.SigningKey, message: bytes) -> str:
    """Return base64-encoded detached Ed25519 signature."""
    return base64.b64encode(sk.sign(message).signature).decode()


def verify(vk: nacl.signing.VerifyKey, message: bytes, signature_b64: str) -> bool:
    """Return True if signature is valid, False otherwise."""
    try:
        vk.verify(message, base64.b64decode(signature_b64))
        return True
    except Exception:
        return False
