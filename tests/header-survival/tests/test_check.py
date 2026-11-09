import re

from survival import check
from survival.reference import ref
from tests.conftest import AUTHRES, DNS_NAME, header_block, received


def inputs(dns, **changes):
    base = {"mailbox": "box", "addresses": {"box@example.net"}, "dns": dns}
    base.update(changes)
    return check.ReceiverInputs(**base)


def test_identical_header_verifies(built, dns, now):
    sent = built["minimal"].raw
    out = check.check(received(sent, now + 3), inputs(dns), sent)
    assert out.verified, out.reason
    assert out.header.status == "identical" and out.header.intact
    assert out.dkim_pass_domains == ["amazonses.com", "colophon-protocol.org"]
    assert out.authserv_id == "mx.example.net"
    assert out.arrival == now + 3 and out.arrival_source == "topmost Received"
    assert out.dns_name == DNS_NAME and out.dns_source == "given"
    assert out.signed_fields_changed == []


def test_refolded_header_still_verifies(built, dns, now):
    sent = built["cap"].raw
    block = header_block(sent)
    flat = re.sub(r"[ \t\r\n]+", "", block.split(":", 1)[1])
    refolded = (
        "Colophon-Signature: "
        + "\r\n ".join(flat[i : i + 76] for i in range(0, len(flat), 76))
        + "\r\n"
    )
    captured = received(sent.replace(block.encode(), refolded.encode()), now + 3)
    out = check.check(captured, inputs(dns), sent)
    assert out.verified, out.reason
    assert out.header.status == "refolded"
    assert out.header.captured_octets == out.header.sent_octets == ref.MAX_HEADER_BYTES
    assert out.header.captured_lines != out.header.sent_lines


def test_missing_header(built, dns, now):
    sent = built["minimal"].raw
    captured = received(sent.replace(header_block(sent).encode(), b""), now + 3)
    out = check.check(captured, inputs(dns), sent)
    assert not out.verified and out.reason == "no_signature"
    assert out.header.status == "missing" and out.header.captured_count == 0


def test_truncated_header(built, dns, now):
    sent = built["cap"].raw
    block = header_block(sent)
    cut = block[:900].rstrip() + "\r\n"
    out = check.check(
        received(sent.replace(block.encode(), cut.encode()), now + 3), inputs(dns), sent
    )
    assert not out.verified
    assert out.header.status == "truncated"
    assert out.header.detail.startswith("cut after")


def test_altered_header(built, dns, now):
    sent = built["minimal"].raw
    block = header_block(sent)
    altered = block.replace("b=", "b=A", 1)
    out = check.check(
        received(sent.replace(block.encode(), altered.encode()), now + 3), inputs(dns), sent
    )
    assert not out.verified
    assert out.header.status == "altered"


def test_duplicated_header(built, dns, now):
    sent = built["minimal"].raw
    block = header_block(sent).encode()
    out = check.check(received(sent.replace(block, block + block), now + 3), inputs(dns), sent)
    assert not out.verified and out.reason == "multiple_signatures"
    assert out.header.status == "duplicated" and out.header.captured_count == 2


def test_signed_field_change_is_reported(built, dns, now):
    sent = built["attachments"].raw
    captured = received(sent.replace(b"Subject: Colophon", b"Subject: Fwd: Colophon"), now + 3)
    out = check.check(captured, inputs(dns), sent)
    assert not out.verified and out.reason == "signature_invalid"
    assert out.header.status == "identical"
    assert out.signed_fields_changed == ["subject"]


def test_dkim_not_aligned_skips_dns(built, now):
    sent = built["minimal"].raw
    authres = "Authentication-Results: mx.example.net; dkim=pass header.d=amazonses.com\r\n"
    out = check.check(received(sent, now + 3, authres), inputs(None), sent)
    assert not out.verified and out.reason == "dkim_unaligned"
    assert out.dns_source.startswith("skipped")
    assert out.dkim_pass_domains == ["amazonses.com"]


def test_given_inputs_override_the_capture(built, dns, now):
    sent = built["minimal"].raw
    out = check.check(
        received(sent, now + 3, authres=""),
        inputs(dns, arrival=now + 9, dkim_pass_domains={"colophon-protocol.org"}),
        sent,
    )
    assert out.verified, out.reason
    assert out.arrival == now + 9 and out.arrival_source == "given"
    assert out.dkim_note == "given"


def test_capture_alone(built, dns, now):
    sent = built["minimal"].raw
    out = check.check(received(sent, now + 3), inputs(dns))
    assert out.verified
    assert out.header.status == "captured-only"


def test_failed_lookup_is_reported(built, now):
    sent = built["minimal"].raw
    out = check.check(received(sent, now + 3), inputs({DNS_NAME: None}), sent)
    assert not out.verified and out.reason == "dns_error"


def test_authres_fixture_is_from_the_receiver():
    assert AUTHRES.startswith("Authentication-Results: mx.example.net;")


def test_exported_file_is_found_and_normalised(tmp_path, built):
    from survival import capture
    from survival.receivers import Capture

    raw = built["minimal"].raw.replace(b"\r\n", b"\n")  # an export with LF endings
    (tmp_path / "Colophon header test.eml").write_bytes(raw)
    (tmp_path / "other.eml").write_bytes(b"Subject: nothing\n\nbody\n")
    got = capture.file(Capture("file"), "test-run/minimal", tmp_path)
    assert got.raw == built["minimal"].raw
    assert got.kind == "file" and got.where.endswith("Colophon header test.eml")
    try:
        capture.file(Capture("file"), "test-run/cap", tmp_path)
    except capture.NotFound as missing:
        assert "(2 files)" in str(missing)
    else:
        raise AssertionError("expected NotFound")


def test_secret_from_file_then_environment(tmp_path, monkeypatch):
    from survival.receivers import Capture

    secret = tmp_path / "pw"
    secret.write_text("s3cret\n")
    assert Capture("imap", {"password_file": str(secret)}).secret("password") == "s3cret"
    secret.write_text('# written by a secrets form\nGMAIL_APP_PASSWORD="abcd efgh"\n')
    assert Capture("imap", {"password_file": str(secret)}).secret("password") == "abcd efgh"
    cap = Capture("imap", {"password_file": str(secret), "password_key": "GMAIL_APP_PASSWORD"})
    assert cap.secret("password") == "abcd efgh"
    try:
        Capture("imap", {"password_file": str(secret), "password_key": "OTHER"}).secret("password")
    except ValueError as err:
        assert "no OTHER" in str(err)
    else:
        raise AssertionError("expected ValueError")
    monkeypatch.setenv("PW_TEST", "from-env")
    assert Capture("imap", {"password_env": "PW_TEST"}).secret("password") == "from-env"
    try:
        Capture("imap", {}).secret("password")
    except ValueError as err:
        assert "password_file or password_env" in str(err)
    else:
        raise AssertionError("expected ValueError")


def test_missing_password_file_is_reported_not_fatal(tmp_path):
    from survival.receivers import Capture

    cap = Capture("imap", {"password_file": str(tmp_path / "absent")})
    try:
        cap.secret("password")
    except OSError:
        pass
    else:
        raise AssertionError("expected the missing file to raise")


def test_hand_export_wins_over_live_capture(tmp_path, built):
    from survival import capture
    from survival.receivers import Capture

    (tmp_path / "from-gmail.eml").write_bytes(built["cap"].raw)
    cap = Capture("imap", {"host": "imap.invalid", "user": "x", "password_env": "UNSET_PW"})
    got = capture.fetch(cap, "test-run/cap", since=0, state_dir=tmp_path, export_dir=tmp_path)
    assert got.kind == "file" and got.raw == built["cap"].raw


def test_shared_mailbox_exports_are_told_apart_by_recipient(tmp_path, keys, now):
    from survival import capture, messages
    from survival.receivers import Capture

    direct = messages.build(
        "minimal",
        keys=keys,
        sender="test@example.org",
        recipient="me@example.com",
        run_id="test-run",
        now=now,
        display="Test",
    )
    hop = messages.build(
        "minimal",
        keys=keys,
        sender="test@example.org",
        recipient="alias@hop.example",
        run_id="test-run",
        now=now,
        display="Test",
    )
    shared = tmp_path / "exports" / "gmail"
    other = tmp_path / "exports" / "hop"
    shared.parent.mkdir()
    shared.mkdir()
    other.mkdir()
    (shared / "a.eml").write_bytes(hop.raw)
    (shared / "b.eml").write_bytes(direct.raw)
    got = capture.file(Capture("file"), "test-run/minimal", other, "alias@hop.example")
    assert got.raw == hop.raw  # found in the sibling directory, by recipient
    got = capture.file(Capture("file"), "test-run/minimal", shared, "me@example.com")
    assert got.raw == direct.raw
    assert capture.addressed_to(b"To: Someone <ME@example.com>\r\n\r\n", "me@example.com")
    assert not capture.addressed_to(
        b"Delivered-To: me@example.com\r\nTo: x@y\r\n\r\n", "me@example.com"
    )


def test_headers_markdown_reproduces_only_the_colophon_field(built):
    from survival import report

    sent = built["minimal"].raw
    stored = b"Received: from a by b; Mon, 9 Nov 2026 15:49:41 +0000\r\n" + sent
    copies = [("box", "minimal", sent, stored), ("box", "cap", built["cap"].raw, None)]
    text = report.headers_markdown(copies, "run-1")
    fields = report.header_fields(sent)
    assert len(fields) == 1 and fields[0].startswith("Colophon-Signature: v=0;")
    assert fields[0] in text
    assert "(not captured)" in text
    assert "To:" not in text and "Subject:" not in text and "Received" not in text


def test_private_domains_are_redacted_from_published_rows():
    from survival import report

    row = report.Row(
        "hop",
        "Gmail",
        "",
        ["Cloudflare Email Routing"],
        "cap",
        "identical",
        True,
        "verified",
        2560,
        2560,
        30,
        30,
        ["amazonses.com", "cloudflare-email.net", "colophon-protocol.org", "fwd.example"],
        [],
        "topmost Received",
        "live lookup",
        "file",
    )
    out = report.redact([row], {"fwd.example": "<forwarding domain>"})[0]
    assert out.dkim_pass_domains == [
        "amazonses.com",
        "cloudflare-email.net",
        "colophon-protocol.org",
        "<forwarding domain>",
    ]
    assert report.redact_text(
        "signed by FWD.example today", {"fwd.example": "<forwarding domain>"}
    ) == ("signed by <forwarding domain> today")
    assert report.redact([row], {}) == [row]
