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
    if sk_path.exists() and vk_path.exists():
        print(f"[SKIP] {name} keys already exist — delete manually to regenerate.")
        return
    if vk_path.exists() != sk_path.exists():
        present, missing = (vk_path, sk_path) if vk_path.exists() else (sk_path, vk_path)
        sys.exit(
            f"[ERROR] {name}: {present} exists but {missing} does not. This looks like a "
            f"fresh checkout, not a fresh machine — {vk_path.name} is committed to git but "
            f"{sk_path.name} never is. Generating a new keypair here would not match the "
            f"committed {vk_path.name} or any data already signed with the original key. "
            f"Transfer the real {sk_path.name} from wherever these keys were first generated "
            f"(a password manager or direct machine-to-machine copy — never git)."
        )
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
