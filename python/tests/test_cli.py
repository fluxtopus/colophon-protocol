"""The command line, end to end on files, with a DNS file instead of live DNS."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import ModuleType

import pytest

from colophon_protocol import Credential
from colophon_protocol.cli import main

from helpers import ARRIVED, ISSUER


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = main(list(argv))
    return code, capsys.readouterr().out


def _json(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict[str, object]]:
    code, out = _run(capsys, *argv, "--json")
    return code, json.loads(out)


def test_keygen_writes_a_private_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "domain.jwk"
    code, data = _json(capsys, "keygen", "--out", str(out))
    assert code == 0
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    assert json.loads(out.read_text())["d"] not in json.dumps(data)
    assert main(["keygen", "--out", str(out)]) == 2  # never overwrites
    assert "exists" in capsys.readouterr().err


def test_full_flow(tmp_path: Path, capsys: pytest.CaptureFixture[str], sketch: ModuleType) -> None:
    domain, agent = tmp_path / "d.jwk", tmp_path / "a.jwk"
    main(["keygen", "--out", str(domain)])
    main(["keygen", "--role", "agent", "--out", str(agent)])
    capsys.readouterr()

    code, record = _json(
        capsys, "dns", "--key", str(domain), "--host", "acme.example", "--selector", "s1"
    )
    assert code == 0
    assert record["name"] == "s1._colophon.acme.example"
    dns_file = tmp_path / "dns.json"
    dns_file.write_text(json.dumps({record["name"]: [record["value"]]}))

    cred_file = tmp_path / "cred.txt"
    code, _ = _run(
        capsys,
        "issue",
        "--domain-key",
        str(domain),
        "--host",
        "acme.example",
        "--selector",
        "s1",
        "--sub",
        "ag_7Hq2",
        "--address",
        "maple-tiger-27@acme.example",
        "--agent-key",
        str(agent),
        "--principal",
        "pseudonymous:p_Xk29",
        "--scope",
        "Books tables.",
        "--issued-at",
        "2026-11-05T08:00:00Z",
        "--out",
        str(cred_file),
    )
    assert code == 0
    assert Credential.parse(cred_file.read_text().strip()).issued_at == 1793865600

    unsigned, signed = tmp_path / "m.eml", tmp_path / "s.eml"
    unsigned.write_bytes(sketch.example_unsigned())
    code, _ = _run(
        capsys,
        "sign",
        str(unsigned),
        "--credential",
        str(cred_file),
        "--agent-key",
        str(agent),
        "--signed-at",
        "1793870100",
        "--out",
        str(signed),
    )
    assert code == 0

    verify_args = [
        "verify",
        str(signed),
        "--arrival",
        str(ARRIVED),
        "--dkim-pass",
        "acme.example",
        "--address",
        "reservations@bistro.example",
        "--dns-file",
        str(dns_file),
    ]
    code, verdict = _json(capsys, *verify_args)
    assert code == 0
    assert verdict["verdict"] == "verified"
    code, human = _run(capsys, *verify_args)
    assert code == 0
    assert human.startswith("verified")
    assert "pseudonymous, id p_Xk29" in human

    assert main([*verify_args[:-2], "--dns-file", str(tmp_path / "none.json")]) == 2


def test_verify_with_authentication_results(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sketch: ModuleType
) -> None:
    message, dns_file = tmp_path / "s.eml", tmp_path / "dns.json"
    message.write_bytes(sketch.signed())
    dns_file.write_text(json.dumps({ISSUER.dns_name: [ISSUER.dns_record]}))
    common = [
        "verify",
        str(message),
        "--arrival",
        "2026-11-05T09:15:10Z",
        "--address",
        "reservations@bistro.example",
        "--dns-file",
        str(dns_file),
    ]
    ar = "mx.bistro.example; dkim=pass header.d=acme.example"
    code, verdict = _json(
        capsys, *common, "--authentication-results", ar, "--authserv-id", "mx.bistro.example"
    )
    assert (code, verdict["verdict"]) == (0, "verified")
    code, verdict = _json(
        capsys, *common, "--authentication-results", ar, "--authserv-id", "mx.other.example"
    )
    assert (code, verdict["reason"]) == (1, "dkim_unaligned")
    assert main([*common, "--authentication-results", ar]) == 2


def test_verify_not_verified(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sketch: ModuleType
) -> None:
    message, dns_file = tmp_path / "s.eml", tmp_path / "dns.json"
    message.write_bytes(sketch.signed())
    dns_file.write_text(json.dumps({ISSUER.dns_name: None}))
    code, human = _run(
        capsys,
        "verify",
        str(message),
        "--arrival",
        str(ARRIVED),
        "--dkim-pass",
        "acme.example",
        "--address",
        "reservations@bistro.example",
        "--dns-file",
        str(dns_file),
    )
    assert code == 1
    assert human.startswith("not verified: dns_error")


def test_dns_revoke(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key = tmp_path / "d.jwk"
    main(["keygen", "--out", str(key)])
    capsys.readouterr()
    code, out = _run(
        capsys, "dns", "--key", str(key), "--host", "acme.example", "--selector", "s1", "--revoke"
    )
    assert code == 0
    assert out.strip().endswith('"v=COLOPHON0; k=ed25519; p="')


@pytest.mark.network
def test_check_live(capsys: pytest.CaptureFixture[str]) -> None:
    code, data = _json(capsys, "check", "example.com", "s1")
    assert code == 1
    assert data["result"] in {"key_not_found", "dns_error"}
