"""Keys for the test.

Private keys live outside the repository, one per file, as base64url of the 32 raw Ed25519 octets.
The deterministic keys from the sketch are for the harness's own tests and dry runs only."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from .reference import ref

DOMAIN_KEY_ENV = "COLOPHON_SURVIVAL_DOMAIN_KEY"
AGENT_KEY_ENV = "COLOPHON_SURVIVAL_AGENT_KEY"


@dataclass(frozen=True)
class Keys:
    domain: Ed25519PrivateKey
    agent: Ed25519PrivateKey
    source: str

    @property
    def domain_public(self) -> str:
        return ref.public_x(self.domain)

    @property
    def agent_public(self) -> str:
        return ref.public_x(self.agent)

    def dns_record(self) -> str:
        return ref.dns_record(self.domain)


def test_keys() -> Keys:
    return Keys(
        ref.test_key("header-survival domain s1"),
        ref.test_key("header-survival agent"),
        "deterministic test keys",
    )


def read_private(path: Path) -> Ed25519PrivateKey:
    raw = ref.unb64u(path.read_text(encoding="ascii").strip())
    if len(raw) != 32:
        raise ValueError(f"{path}: not a 32-octet key")
    return Ed25519PrivateKey.from_private_bytes(raw)


def write_private(path: Path, key: Ed25519PrivateKey) -> None:
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    path.write_text(ref.b64u(raw) + "\n", encoding="ascii")
    os.chmod(path, 0o600)


def generate(directory: Path) -> Keys:
    """Fresh random keys in a directory outside the repository. Refuses to overwrite."""
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    domain_path, agent_path = directory / "domain.key", directory / "agent.key"
    for path in (domain_path, agent_path):
        if path.exists():
            raise FileExistsError(path)
    keys = Keys(Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), str(directory))
    write_private(domain_path, keys.domain)
    write_private(agent_path, keys.agent)
    return keys


def from_files(domain_path: Path, agent_path: Path) -> Keys:
    return Keys(read_private(domain_path), read_private(agent_path), f"{domain_path}, {agent_path}")


def from_environment() -> Keys | None:
    domain_path, agent_path = os.environ.get(DOMAIN_KEY_ENV), os.environ.get(AGENT_KEY_ENV)
    if not domain_path or not agent_path:
        return None
    return from_files(Path(domain_path), Path(agent_path))
