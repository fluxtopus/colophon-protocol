"""Shared fixtures. The vectors and the reference sketch come from the specification checkout:
``COLOPHON_SPEC_DIR``, or the repository this directory sits in."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SPEC_DIR = Path(os.environ.get("COLOPHON_SPEC_DIR", Path(__file__).resolve().parents[2]))


def load_sketch() -> ModuleType:
    path = SPEC_DIR / "reference" / "colophon_v0.py"
    if "colophon_v0_sketch" in sys.modules:
        return sys.modules["colophon_v0_sketch"]
    spec = importlib.util.spec_from_file_location("colophon_v0_sketch", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["colophon_v0_sketch"] = module
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class Delivery:
    accepted_at: int
    dkim_pass_domains: list[str]
    mailbox: str
    mailbox_addresses: list[str]
    dns_txt: dict[str, list[str] | None]
    expected: str
    expected_authentication_results: str


@dataclass(frozen=True)
class Case:
    name: str
    message: bytes
    deliveries: list[Delivery]


def load_cases() -> list[Case]:
    doc: dict[str, Any] = json.loads((SPEC_DIR / "reference" / "vectors.json").read_text())
    out = []
    for case in doc["cases"]:
        deliveries = [
            Delivery(
                accepted_at=d["accepted_at"],
                dkim_pass_domains=d["dkim_pass_domains"],
                mailbox=d["mailbox"],
                mailbox_addresses=d["mailbox_addresses"],
                dns_txt=d["dns_txt"],
                expected=d["expected"],
                expected_authentication_results=d["expected_authentication_results"],
            )
            for d in case["deliveries"]
        ]
        out.append(Case(case["name"], base64.b64decode(case["message"]), deliveries))
    return out


@pytest.fixture(scope="session")
def sketch() -> ModuleType:
    return load_sketch()


@pytest.fixture(scope="session")
def cases() -> list[Case]:
    return load_cases()
