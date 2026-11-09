import json
from email import policy
from email.parser import BytesParser

from survival import messages
from survival.reference import ref
from tests.conftest import DNS_NAME, RUN_ID


def test_three_messages_within_the_caps(built):
    for label, b in built.items():
        assert b.header_octets <= ref.MAX_HEADER_BYTES, label
        assert b.credential_octets <= ref.MAX_CREDENTIAL_BYTES, label
    assert built["cap"].header_octets == ref.MAX_HEADER_BYTES
    assert built["cap"].credential_octets == ref.MAX_CREDENTIAL_BYTES
    assert built["minimal"].header_octets < 800


def test_each_verifies_as_sent(built, dns, now):
    for label, b in built.items():
        arrival = ref.Arrival(
            accepted_at=now + 5,
            dkim_pass_domains={"colophon-protocol.org"},
            mailbox="box",
            mailbox_addresses={"box@example.net"},
            dns=dns,
        )
        verdict = ref.verify(b.raw, arrival)
        assert verdict.verified, (label, verdict.reason)
        assert verdict.agent["sub"] == messages.AGENT_ID


def test_tracking_and_subject(built):
    for label, b in built.items():
        msg = BytesParser(policy=policy.compat32).parsebytes(b.raw)
        assert msg[messages.TRACKING_HEADER] == f"{RUN_ID}/{label}"
        assert label in msg["Subject"] and RUN_ID in msg["Subject"]
        assert msg["To"] == "box@example.net"


def test_attachments_are_present(built):
    msg = BytesParser(policy=policy.compat32).parsebytes(built["attachments"].raw)
    names = [p.get_filename() for p in msg.walk() if p.get_filename()]
    assert names == ["test.csv", "blank.pdf"]
    msg = BytesParser(policy=policy.compat32).parsebytes(built["minimal"].raw)
    assert not msg.is_multipart()


def test_nonces_differ_between_builds(keys, now):
    a = messages.build(
        "minimal",
        keys=keys,
        sender="t@colophon-protocol.org",
        recipient="b@example.net",
        run_id="r",
        now=now,
    )
    b = messages.build(
        "minimal",
        keys=keys,
        sender="t@colophon-protocol.org",
        recipient="b@example.net",
        run_id="r",
        now=now,
    )
    assert a.nonce != b.nonce


def test_selector_names_the_key(keys, now):
    for label in messages.LABELS:
        built = messages.build(
            label,
            keys=keys,
            sender="t@colophon-protocol.org",
            recipient="b@example.net",
            run_id="r",
            now=now,
            selector="s2",
        )
        header = built.credential.split(".")[0]
        assert json.loads(ref.unb64u(header))["kid"] == "s2"
        if label == "cap":
            assert built.header_octets == ref.MAX_HEADER_BYTES


def test_exact_octets():
    assert len(messages.exact_octets("héllo", 20).encode()) == 20
    assert len(messages.exact_octets("x" * 50, 20).encode()) == 20


def test_dns_name_matches_selector(keys):
    assert DNS_NAME == "s1._colophon.colophon-protocol.org"
    assert keys.dns_record().startswith("v=COLOPHON0; k=ed25519; p=")
