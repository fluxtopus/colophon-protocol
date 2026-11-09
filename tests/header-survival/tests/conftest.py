import re
import time
from email.utils import formatdate

import pytest

from survival import messages
from survival.keys import test_keys

RUN_ID = "test-run"
DNS_NAME = f"{messages.SELECTOR}._colophon.colophon-protocol.org"
AUTHRES = (
    "Authentication-Results: mx.example.net;\r\n"
    " dkim=pass header.i=@colophon-protocol.org header.s=abc header.b=xyz;\r\n"
    " dkim=pass (2048-bit key) header.d=amazonses.com header.s=def;\r\n"
    " spf=pass smtp.mailfrom=amazonses.com\r\n"
)


@pytest.fixture(scope="session")
def keys():
    return test_keys()


@pytest.fixture(scope="session")
def dns(keys):
    return {DNS_NAME: [keys.dns_record()]}


@pytest.fixture(scope="session")
def now():
    return int(time.time())


@pytest.fixture(scope="session")
def built(keys, now):
    return {
        label: messages.build(
            label,
            keys=keys,
            sender="test@colophon-protocol.org",
            recipient="box@example.net",
            run_id=RUN_ID,
            now=now,
        )
        for label in messages.LABELS
    }


HEADER = re.compile(r"Colophon-Signature:((?:.|\r\n[ \t])*)\r\n")


def header_block(raw: bytes) -> str:
    return HEADER.search(raw.decode()).group(0)


def received(raw: bytes, when: float | None = None, authres: str = AUTHRES) -> bytes:
    """The message as a receiver would store it: its Received and Authentication-Results on top."""
    top = f"Received: from a.amazonses.com by mx.example.net with ESMTPS; {formatdate(when, usegmt=True)}\r\n"
    return (top + authres).encode() + raw
