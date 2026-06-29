#!/usr/bin/env python3
"""Generate publisher + service Ed25519 keypairs. Run once; commit the .vk files."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import (
    PUBLISHER_SIGNING_KEY_PATH,
    PUBLISHER_VERIFY_KEY_PATH,
    SERVICE_SIGNING_KEY_PATH,
    SERVICE_VERIFY_KEY_PATH,
)
from src.crypto import generate_keypair, save_keypair


def _generate(sk_path: Path, vk_path: Path, name: str) -> None:
    if sk_path.exists() or vk_path.exists():
        print(f"[SKIP] {name} keys already exist — delete manually to regenerate.")
        return
    sk, _ = generate_keypair()
    save_keypair(sk, sk_path, vk_path)
    print(f"[OK]   {name} private key → {sk_path}")
    print(f"[OK]   {name} public key  → {vk_path}")


def main() -> None:
    _generate(PUBLISHER_SIGNING_KEY_PATH, PUBLISHER_VERIFY_KEY_PATH, "publisher")
    _generate(SERVICE_SIGNING_KEY_PATH, SERVICE_VERIFY_KEY_PATH, "service")
    print("\nNext: commit the .vk files; keep .sk files out of git.")


if __name__ == "__main__":
    main()
