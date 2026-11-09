"""The receivers under test, from `receivers.json` (never committed; see receivers.example.json).

A receiver is a mailbox we own or were given. `address` is where the harness sends; `capture` says
how to fetch what arrived. When mail reaches the mailbox through a forwarding hop (Cloudflare Email
Routing, a Gmail forward), `hops` names them so the result is reported as a recorded forward, not
as the provider's direct behaviour."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Capture:
    kind: str  # imap, graph, s3, or file
    options: dict = field(default_factory=dict)

    def secret(self, name: str) -> str:
        """A credential read from the file named by `<name>_file` in the options, else from the
        environment variable named by `<name>_env`. Never from the options themselves.

        The file holds either the bare value or dotenv lines (`NAME=value`); with dotenv lines
        the variable is the one named by `<name>_key`, else the only assignment in the file."""
        path = self.options.get(f"{name}_file")
        if path:
            text = Path(path).expanduser().read_text(encoding="utf-8").strip()
            if not text:
                raise ValueError(f"{path} is empty")
            return self._from_dotenv(text, self.options.get(f"{name}_key"), path)
        var = self.options.get(f"{name}_env")
        if not var:
            raise ValueError(f"capture needs {name}_file or {name}_env in receivers.json")
        value = os.environ.get(var)
        if not value:
            raise ValueError(f"environment variable {var} is not set")
        return value

    @staticmethod
    def _from_dotenv(text: str, key: str | None, path: str) -> str:
        pairs = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip().removeprefix("export ").strip()
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                v = v[1:-1]
            pairs[k] = v
        if not pairs:
            return text
        if key:
            if key not in pairs:
                raise ValueError(f"{path} has no {key} assignment")
            return pairs[key]
        if len(pairs) != 1:
            raise ValueError(f"{path} has several assignments; name one with _key")
        return next(iter(pairs.values()))


@dataclass(frozen=True)
class Receiver:
    name: str
    provider: str
    address: str
    mailbox: str
    addresses: frozenset[str]
    capture: Capture
    authserv_ids: tuple[str, ...] = ()
    hops: tuple[str, ...] = ()
    account_type: str = ""
    notes: str = ""

    @property
    def direct(self) -> bool:
        return not self.hops


@dataclass(frozen=True)
class Plan:
    sender: str
    display: str
    region: str
    receivers: tuple[Receiver, ...]

    def receiver(self, name: str) -> Receiver:
        for r in self.receivers:
            if r.name == name:
                return r
        raise KeyError(name)


def load(path: Path) -> Plan:
    doc = json.loads(path.read_text(encoding="utf-8"))
    receivers = []
    for name, r in doc["receivers"].items():
        cap = r.get("capture") or {"kind": "file"}
        receivers.append(
            Receiver(
                name=name,
                provider=r["provider"],
                address=r["address"],
                mailbox=r.get("mailbox", f"{name}:{r['address']}"),
                addresses=frozenset(r.get("addresses", [r["address"]])),
                capture=Capture(cap["kind"], {k: v for k, v in cap.items() if k != "kind"}),
                authserv_ids=tuple(r.get("authserv_ids", ())),
                hops=tuple(r.get("hops", ())),
                account_type=r.get("account_type", ""),
                notes=r.get("notes", ""),
            )
        )
    return Plan(
        sender=doc["sender"],
        display=doc.get("display", "Colophon header test"),
        region=doc.get("region", "us-east-2"),
        receivers=tuple(receivers),
    )
