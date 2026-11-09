"""The ``colophon-protocol`` command. A thin layer over the library; live DNS happens only here
(``check``, and ``verify`` without ``--dns-file``), through the ``dns`` extra."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

from colophon_protocol import __version__
from colophon_protocol._codec import b64url_decode
from colophon_protocol._credential import jwk_thumbprint
from colophon_protocol._record import select_domain_key
from colophon_protocol.authres import dkim_pass_domains
from colophon_protocol.blocking import TxtResolver, verify
from colophon_protocol.dns import StaticResolver
from colophon_protocol.errors import ColophonError, DnsLimited
from colophon_protocol.issuer import Issuer
from colophon_protocol.keys import AgentKey, DomainKey
from colophon_protocol.model import (
    KeyQuery,
    Named,
    Principal,
    Pseudonymous,
    Receipt,
    Verdict,
    Verified,
    Withheld,
)
from colophon_protocol.replay import MemoryReplayStore
from colophon_protocol.signer import sign

EXIT_OK, EXIT_NO, EXIT_USAGE = 0, 1, 2


class _Usage(Exception):
    pass


def _fail(message: str) -> NoReturn:
    raise _Usage(message)


def _time(value: str) -> int:
    """Unix seconds, ``now``, or ISO 8601 with a zone (``2026-11-05T09:15:10Z``)."""
    if value == "now":
        return int(datetime.now(timezone.utc).timestamp())
    if value.lstrip("-").isdigit():
        return int(value)
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a time: {value!r}") from None
    if moment.tzinfo is None:
        raise argparse.ArgumentTypeError("an ISO 8601 time needs a zone, such as Z")
    return int(moment.timestamp())


def _shown(text: str) -> str:
    """Sender-written text, with anything that moves the cursor or reading order escaped."""
    return "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode() for ch in text)


def _read_jwk(path: str) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _fail(f"cannot read the key file {path}: {exc}")
    if not isinstance(data, dict):
        _fail(f"{path} is not a JWK")
    return data


def _domain_key(path: str) -> DomainKey:
    try:
        return DomainKey.from_jwk(_read_jwk(path))
    except ValueError as exc:
        _fail(f"{path}: {exc}")


def _agent_key(path: str) -> AgentKey:
    try:
        return AgentKey.from_jwk(_read_jwk(path))
    except ValueError as exc:
        _fail(f"{path}: {exc}")


def _write_secret(path: str, text: str) -> None:
    """Create the file, mode 0600; never overwrite one."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        _fail(f"{path} exists; not overwriting a key")
    except OSError as exc:
        _fail(f"cannot create {path}: {exc}")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


def _emit(args: argparse.Namespace, data: dict[str, Any], human: str) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2) if args.json else human)


# ---------------------------------------------------------------- commands


def cmd_keygen(args: argparse.Namespace) -> int:
    key = (DomainKey if args.role == "domain" else AgentKey).generate()
    _write_secret(args.out, json.dumps(key.private_jwk()) + "\n")
    data = {"role": args.role, "file": args.out, "public_jwk": key.public_jwk()}
    data["thumbprint"] = key.thumbprint()
    _emit(
        args,
        data,
        f"wrote a private {args.role} key to {args.out} (mode 0600)\n"
        f"public key  {key.public_jwk()['x']}\nthumbprint  {key.thumbprint()}",
    )
    return EXIT_OK


def cmd_dns(args: argparse.Namespace) -> int:
    try:
        issuer = Issuer(args.host, args.selector, _domain_key(args.key))
    except ColophonError as exc:
        _fail(str(exc))
    record = issuer.revoked_record if args.revoke else issuer.dns_record
    _emit(
        args,
        {"name": issuer.dns_name, "type": "TXT", "value": record},
        f'{issuer.dns_name}. 3600 IN TXT "{record}"',
    )
    return EXIT_OK


def _live_resolver() -> TxtResolver:
    try:
        from colophon_protocol.dnspython import DnspythonResolver  # noqa: PLC0415
    except ImportError as exc:
        _fail(str(exc))
    return DnspythonResolver()


def cmd_check(args: argparse.Namespace) -> int:
    query = KeyQuery(args.selector, args.host.lower().rstrip("."))
    try:
        answer = _live_resolver().resolve_txt(query)
    except (ColophonError, OSError) as exc:
        _emit(
            args,
            {"name": query.name, "result": "dns_error", "detail": str(exc)},
            f"{query.name}: dns_error ({exc})",
        )
        return EXIT_NO
    result = select_domain_key(answer)
    records = [r.decode("latin-1") for r in answer.records]
    if isinstance(result, bytes):
        data = {
            "name": query.name,
            "result": "key",
            "thumbprint": jwk_thumbprint(result),
            "records": records,
            "ttl": answer.ttl,
        }
        _emit(args, data, f"{query.name}: domain key found\nthumbprint  {data['thumbprint']}")
        return EXIT_OK
    data = {"name": query.name, "result": result.value, "records": records, "ttl": answer.ttl}
    lines = [f"{query.name}: {result.value}"] + [f"  record  {_shown(r)}" for r in records]
    _emit(args, data, "\n".join(lines))
    return EXIT_NO


def _principal(value: str) -> Principal:
    mode, _, rest = value.partition(":")
    if mode == "withheld" and not rest:
        return Withheld()
    if mode == "pseudonymous" and rest:
        return Pseudonymous(rest)
    if mode == "named" and rest:
        return Named(rest)
    _fail("--principal is withheld, pseudonymous:<id> or named:<name>")


def cmd_issue(args: argparse.Namespace) -> int:
    agent: AgentKey | bytes
    if args.agent_key:
        agent = _agent_key(args.agent_key)
    else:
        try:
            agent = b64url_decode(args.agent_public)
        except ValueError:
            _fail("--agent-public is the base64url public key")
    try:
        issuer = Issuer(args.host, args.selector, _domain_key(args.domain_key))
        credential = issuer.issue(
            sub=args.sub,
            address=args.address,
            agent_key=agent,
            issued_at=args.issued_at,
            principal=_principal(args.principal),
            scope=args.scope,
            lifetime=args.lifetime,
        )
    except ColophonError as exc:
        _fail(str(exc))
    if args.out:
        Path(args.out).write_text(credential.token + "\n", encoding="ascii")
    data = {"credential": credential.token, "expires_at": credential.expires_at}
    _emit(args, data, credential.token)
    return EXIT_OK


def _read_message(path: str) -> bytes:
    try:
        return sys.stdin.buffer.read() if path == "-" else Path(path).read_bytes()
    except OSError as exc:
        _fail(f"cannot read {path}: {exc}")


def cmd_sign(args: argparse.Namespace) -> int:
    try:
        token = Path(args.credential).read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        _fail(f"cannot read the credential file: {exc}")
    try:
        signed = sign(
            _read_message(args.message),
            credential=token,
            agent_key=_agent_key(args.agent_key),
            signed_at=args.signed_at,
            min_remaining=args.min_remaining,
        )
    except ColophonError as exc:
        _fail(str(exc))
    if args.out and args.out != "-":
        Path(args.out).write_bytes(signed)
    else:
        sys.stdout.buffer.write(signed)
    return EXIT_OK


def _dns_file(path: str) -> TxtResolver:
    try:
        table = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _fail(f"cannot read the DNS file: {exc}")
    if not isinstance(table, dict):
        _fail("the DNS file maps names to lists of records, or null for a failed lookup")
    return StaticResolver(table)


def _human(verdict: Verdict) -> str:
    if not isinstance(verdict, Verified):
        detail = f" ({verdict.detail})" if verdict.detail else ""
        return f"not verified: {verdict.reason.value}{detail}"
    agent = verdict.agent
    principal = agent.principal
    if isinstance(principal, Pseudonymous):
        shown = f"pseudonymous, id {principal.id}"
    elif isinstance(principal, Named):
        shown = f"named, as the issuer attests: {_shown(principal.name)}"
    else:
        shown = "withheld"
    lines = [
        "verified",
        f"  from       {_shown(agent.address)}",
        f"  issuer     {agent.iss}",
        f"  agent ID   {agent.sub}",
        f"  principal  {shown}",
    ]
    if agent.scope is not None:
        lines.append(f"  scope      {_shown(agent.scope)}  (the issuer's words)")
    lines.append(f"  agent key  {agent.key_thumbprint}")
    return "\n".join(lines)


def cmd_verify(args: argparse.Namespace) -> int:
    if args.authentication_results is not None:
        if not args.authserv_id:
            _fail("--authentication-results needs --authserv-id: only trust your own server's")
        domains = set(args.dkim_pass) | dkim_pass_domains(
            args.authentication_results, authserv_id=args.authserv_id, use_header_i=args.header_i
        )
    else:
        domains = set(args.dkim_pass)
    if not args.address:
        _fail("give the mailbox's addresses with --address (one or more)")
    try:
        receipt = Receipt(
            arrival=args.arrival,
            dkim_pass_domains=domains,
            mailbox=args.mailbox or args.address[0],
            mailbox_addresses=args.address,
        )
    except (TypeError, ValueError) as exc:
        _fail(str(exc))
    resolver = _dns_file(args.dns_file) if args.dns_file else _live_resolver()
    if not args.dns_file:
        from colophon_protocol.dns import GuardedResolver  # noqa: PLC0415

        resolver = GuardedResolver(resolver)
    verdict = verify(
        _read_message(args.message), receipt, resolver=resolver, replay_store=MemoryReplayStore()
    )
    _emit(args, verdict.to_json(), _human(verdict))
    return EXIT_OK if verdict.verified else EXIT_NO


# ---------------------------------------------------------------- parser


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(
        prog="colophon-protocol",
        description="Colophon v0 agent signatures for email (draft, not for production).",
    )
    top.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = top.add_subparsers(dest="command", required=True)

    def command(name: str, help_text: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text, description=help_text)
        p.add_argument("--json", action="store_true", help="machine-readable output")
        return p

    p = command("keygen", "Generate an Ed25519 key and write it as a private JWK, mode 0600.")
    p.add_argument("--role", choices=["domain", "agent"], default="domain")
    p.add_argument("--out", required=True, help="file to create; an existing one is refused")
    p.set_defaults(run=cmd_keygen)

    p = command("dns", "Print the TXT record for a domain key.")
    p.add_argument("--key", required=True, help="the domain key JWK file")
    p.add_argument("--host", required=True)
    p.add_argument("--selector", required=True)
    p.add_argument("--revoke", action="store_true", help="print the revoking record (p=)")
    p.set_defaults(run=cmd_dns)

    p = command("check", "Look up a selector in live DNS and say what a verifier would find.")
    p.add_argument("host")
    p.add_argument("selector")
    p.set_defaults(run=cmd_check)

    p = command("issue", "Issue a credential for an agent address.")
    p.add_argument("--domain-key", required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--selector", required=True)
    p.add_argument("--sub", required=True, help="the agent ID")
    p.add_argument("--address", required=True, help="the agent's From address")
    who = p.add_mutually_exclusive_group(required=True)
    who.add_argument("--agent-key", help="the agent key JWK file")
    who.add_argument("--agent-public", help="the agent's public key, base64url")
    p.add_argument("--principal", default="withheld", help="withheld, pseudonymous:<id>, named:<n>")
    p.add_argument("--scope")
    p.add_argument("--issued-at", type=_time, default="now", help="Unix seconds or ISO 8601")
    p.add_argument("--lifetime", type=int, default=86400)
    p.add_argument("--out", help="also write the credential to this file")
    p.set_defaults(run=cmd_issue)

    p = command("sign", "Sign a message file and write the signed octets.")
    p.add_argument("message", help="the .eml file, or - for stdin")
    p.add_argument("--credential", required=True, help="file holding the credential")
    p.add_argument("--agent-key", required=True)
    p.add_argument("--signed-at", type=_time, default="now")
    p.add_argument("--min-remaining", type=int, default=6 * 3600, help=argparse.SUPPRESS)
    p.add_argument("--out", help="output file; stdout by default")
    p.set_defaults(run=cmd_sign)

    p = command("verify", "Verify a message as one receiver's delivery (§7).")
    p.add_argument("message", help="the .eml file as your server accepted it, or - for stdin")
    p.add_argument(
        "--arrival",
        type=_time,
        required=True,
        help="when your server accepted it in SMTP: Unix seconds, ISO 8601 or now",
    )
    p.add_argument(
        "--dkim-pass",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="d= of a DKIM signature your server's check passed (repeatable)",
    )
    p.add_argument(
        "--authentication-results",
        metavar="VALUE",
        help="your server's Authentication-Results value, to read dkim=pass from",
    )
    p.add_argument("--authserv-id", help="your server's authserv-id in that field")
    p.add_argument(
        "--header-i",
        action="store_true",
        help="also read the domain of header.i (for servers that omit header.d)",
    )
    p.add_argument("--mailbox", help="the mailbox's stable ID; the first --address by default")
    p.add_argument(
        "--address",
        action="append",
        default=[],
        help="an address the mailbox receives at (repeatable)",
    )
    p.add_argument("--dns-file", help="JSON: name -> [records] or null; live DNS otherwise")
    p.set_defaults(run=cmd_verify)
    return top


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result: int = args.run(args)
    except _Usage as exc:
        print(f"colophon-protocol: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except DnsLimited as exc:  # pragma: no cover - verify turns it into a verdict
        print(f"colophon-protocol: {exc}", file=sys.stderr)
        return EXIT_NO
    return result
