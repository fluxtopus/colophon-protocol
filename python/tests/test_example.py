"""The library reproduces the draft's example (Appendix A) byte for byte."""

from __future__ import annotations

from types import ModuleType

from colophon_protocol import Verified, sign, verify
from colophon_protocol.replay import MemoryReplayStore

from helpers import AGENT_KEY, DOMAIN_KEY, ISSUER, NONCE, SIGNED, credential, receipt, resolver


def test_keys_match_the_sketch(sketch: ModuleType) -> None:
    assert ISSUER.dns_record == sketch.dns_record(sketch.DOMAIN_KEY)
    assert ISSUER.dns_name == sketch.DNS_NAME
    assert AGENT_KEY.public_jwk()["x"] == sketch.public_x(sketch.AGENT_KEY)
    assert DOMAIN_KEY.public_jwk()["x"] == sketch.public_x(sketch.DOMAIN_KEY)


def test_credential_matches_the_sketch(sketch: ModuleType) -> None:
    expected = sketch.issue_credential(sketch.DOMAIN_KEY, "s1", sketch.example_claims())
    assert credential() == expected


def test_signed_message_matches_the_sketch(sketch: ModuleType) -> None:
    ours = sign(
        sketch.example_unsigned(),
        credential=credential(),
        agent_key=AGENT_KEY,
        signed_at=SIGNED,
        nonce=NONCE,
    )
    assert ours == sketch.signed()


def test_example_verifies(sketch: ModuleType) -> None:
    verdict = verify(
        sketch.signed(), receipt(), resolver=resolver(), replay_store=MemoryReplayStore()
    )
    assert isinstance(verdict, Verified)
    assert verdict.agent.iss == "acme.example"
    assert verdict.agent.sub == "ag_7Hq2"
    assert verdict.agent.address == "maple-tiger-27@acme.example"
    assert verdict.agent.key_thumbprint == AGENT_KEY.thumbprint()
    assert verdict.signed_at == SIGNED
    assert verdict.nonce == NONCE
