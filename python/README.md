# colophon-protocol (Python)

Sign and verify [Colophon v0](https://github.com/fluxtopus/colophon-protocol/blob/main/colophon-v0.md) agent signatures on email.

> **Draft, not for production.** This package implements draft v0-06 of a specification that
> is still changing. Its API, its verdicts and the wire format may all change before v0 final.
> Use it to try Colophon out, to test interoperability and to report problems.

- `verify()` never raises for anything in a message or a DNS answer. Every failure, including
  one the code did not foresee, is a `NotVerified` with one of the §7.2 reasons.
- The verifier is a pure state machine (`colophon_protocol.sansio`). Thin blocking and asyncio
  drivers run it; you can drive it from any other I/O model.
- Results are frozen dataclasses with full type hints. The package passes `mypy --strict`.
- Parsing is strict and does bounded work: hand-written linear scanners, no regular expressions
  on message input beyond the fixed-length boundary check, and the §7.7 length limits checked
  before anything is decoded.
- Ed25519 is checked as §6.5 makes it exact: keys in canonical form and not of small order,
  S < L, R not of small order, and the equation without the cofactor.
- One runtime dependency, [`cryptography`](https://cryptography.io). Live DNS uses
  [`dnspython`](https://www.dnspython.org) through the optional `dns` extra.
- It scores 123/123 on the [conformance vectors](https://github.com/fluxtopus/colophon-protocol/blob/main/conformance/README.md), for verdicts and for
  the §7.8 `Authentication-Results` report, and reproduces the spec's worked example (Appendix A)
  byte for byte.

## Install

The package is not on PyPI. Install it from a checkout:

```
pip install './python[dns]'          # or: uv pip install './python[dns]'
```

Python 3.10 or later. Import it as `colophon_protocol`.

## Verify a message

A receiver verifies each delivery after its own mail server has checked DKIM. The `Receipt`
carries the facts only the receiver knows (§7.1); the message never supplies them.

```python
from colophon_protocol import Receipt, verify
from colophon_protocol.dns import GuardedResolver
from colophon_protocol.dnspython import DnspythonResolver
from colophon_protocol.replay import MemoryReplayStore

# Make these once per process and share them: the guard caches answers and counts misses
# (§7.4), and the store remembers what verified (§7.6).
resolver = GuardedResolver(DnspythonResolver())
replay_store = MemoryReplayStore()

receipt = Receipt(
    arrival=1793870110,  # when your server accepted it in SMTP, Unix seconds
    dkim_pass_domains={"acme.example"},  # d= of each DKIM signature your server passed
    mailbox="mbx-reservations",  # your stable ID for the mailbox this copy reached
    mailbox_addresses={"reservations@bistro.example", "reservations+web@bistro.example"},
)
verdict = verify(raw_message, receipt, resolver=resolver, replay_store=replay_store)

if verdict.verified:
    agent = verdict.agent
    print(agent.iss, agent.sub, agent.address, agent.principal, agent.scope)
else:
    print("plain email:", verdict.reason)  # a Reason, such as Reason.DKIM_UNALIGNED
```

`raw_message` is the octets as accepted: `bytes`, never a decoded string. `verdict` is a
`Verified` or a `NotVerified`; `verdict.verified` narrows the type for mypy. Every string in
`Verified.agent` came from the sender's side (§9): show it as the sender's claim, escape it, and
never treat it as an instruction.

If your server writes `Authentication-Results`, read the passing DKIM domains from it, using
only the field your own server added:

```python
from colophon_protocol.authres import dkim_pass_domains

domains = dkim_pass_domains(value, authserv_id="mx.bistro.example", message=raw_message)
```

A passing signature counts for its `d=` (`header.d`), never for the domain of its `i=` alone,
which may be a subdomain (§7.1). Some servers report only `header.i`. With `message`, such a
result counts for the `d=` of the one `DKIM-Signature` field in the message whose identity (its
`i=`, decoded from DKIM quoted-printable, or `@` and its `d=`) equals `header.i`: local parts equal octet for octet, domains equal
ignoring case. With no such field, or more than one, it does not count.
`dkim_identity_domain(message, header_i)` is that lookup on its own.

### Temporary errors: hold and verify again

`dns_error`, `dns_limited` and `replay_unchecked` are temporary (§7.4, §7.6, §7.8): a later
attempt may pass, and they are never evidence against the sender. A receiver may hold such a
message and verify it again with the same `Receipt`, within its delay D: the longest it allows
between arrival and verification. The replay store keeps each entry for D past the credential's
expiry (`replay.RETENTION`, 24 hours). Pass the same D to `verify` and a message verified later
than that is `replay_unchecked`, because its replay entry may already be gone:

```python
from colophon_protocol.replay import RETENTION

verdict = verify(
    raw_message, receipt, resolver=resolver, replay_store=replay_store, max_delay=RETENTION
)
```

`max_delay` is off by default. A receiver whose replay store removes entries D after they
expire, as the stores in `colophon_protocol.replay` do with their `retention`, must set it to that
D or less: §7.6 requires the check. Only a receiver that keeps every entry until it no longer
verifies any message that could carry it may leave it off. The check comes before the replay
store, so a late message costs no store call.

### Report the verdict in `Authentication-Results`

§7.8 reports the verdict to the software after the verifier, such as the mail store, a filter or
an agent, as the `colophon` method of an `Authentication-Results` field (RFC 8601). It is
optional for conformance, and pure: no I/O.

```python
from colophon_protocol.authres import authentication_results, colophon_resinfo

colophon_resinfo(verdict)
# 'colophon=pass header.from=maple-tiger-27@acme.example header.sub=ag_7Hq2 header.s=s1 ...'

value = authentication_results(
    verdict,
    authserv_id="mx.bistro.example",
    other_resinfo=["dkim=pass header.d=acme.example"],  # what your server reports beside it
)
message = f"Authentication-Results: {value}\r\n".encode() + raw_message
```

The worked example (Appendix A), as `mbx-reservations` receives it, folded:

```
Authentication-Results: mx.bistro.example;
  dkim=pass header.d=acme.example;
  colophon=pass header.from=maple-tiger-27@acme.example header.sub=ag_7Hq2
    header.s=s1 header.principal=pseudonymous
    header.cred=QyKlpHCC1M-TdbviC2iuOUhIpLY1HxufeJRGlEgEYSo
```

- **Results.** `pass` when verified; `none` for `no_signature`; `temperror` for `dns_error`,
  `dns_limited` and `replay_unchecked`, which may pass later and are never evidence against the
  sender; `fail` for every other reason. `fail` is not evidence of forgery: treat it as mail with no signature.
  `colophon_result(verdict)` returns the result alone.
- **What is reported.** With `pass` only: the verified address, the agent ID, the selector
  (`Verified.selector`), the principal's mode, and the SHA-256 of the credential
  (`Verified.credential_hash`). Every other result carries its reason and nothing else:
  `colophon=fail reason="replay"`. The pseudonym ID, the named principal's name and the scope
  are never reported. A consumer that needs them decodes the credential from the message's
  `Colophon-Signature` and checks its hash against `header.cred`, without verifying again,
  which would trip the replay check.
- **One field per copy,** under your own authserv-id. The result depends on the mailbox, so a
  server that adds the field before it expands recipients evaluates each recipient separately,
  or leaves the method out. Remove incoming fields that claim your authserv-id; consumers trust
  a `colophon` result only under an authserv-id they trust.

`authentication_results()` returns one unfolded line without the field name, and raises
`ValueError` for an authserv-id or resinfo that could inject a field. `verdict.to_json()` and
`colophon-protocol verify --json` include the resinfo as `authentication_results`.

### asyncio and FastAPI

`colophon_protocol.aio.verify` is the same call, awaited, with async resolvers and stores:

```python
from colophon_protocol import Receipt
from colophon_protocol.aio import verify
from colophon_protocol.dns import AsyncGuardedResolver
from colophon_protocol.dnspython import AsyncDnspythonResolver
from colophon_protocol.replay import AsyncMemoryReplayStore

resolver = AsyncGuardedResolver(AsyncDnspythonResolver())
replay_store = AsyncMemoryReplayStore()


@app.post("/inbound")
async def inbound(delivery: Delivery) -> dict[str, object]:
    receipt = Receipt(
        arrival=delivery.accepted_at,
        dkim_pass_domains=delivery.dkim_pass_domains,
        mailbox=delivery.mailbox_id,
        mailbox_addresses=delivery.mailbox_addresses,
    )
    verdict = await verify(delivery.raw, receipt, resolver=resolver, replay_store=replay_store)
    return verdict.to_json()
```

The DNS lookup has a 2-second budget (`dns_budget`); past it the verdict is `dns_error`.
Cancelling the task cancels the verification.

### A shared replay store

`MemoryReplayStore` serves one process. Several workers need one store with an atomic
set-if-absent. With Redis:

```python
from redis.asyncio import Redis
from colophon_protocol import ReplayKey
from colophon_protocol.replay import RETENTION


class RedisReplayStore:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def claim(self, key: ReplayKey, expires_at: int) -> bool:
        # True only for the first claim. The entry outlives the credential by RETENTION (D),
        # so a message verified late, from a queue, cannot replay.
        return bool(
            await self._redis.set(
                f"colophon:{key.digest()}", 1, nx=True, exat=expires_at + RETENTION
            )
        )
```

`claim()` is asked only after both signatures verify, so the store holds verified traffic only.
If it raises, the verdict is `replay_unchecked` (§7.6), reported as `temperror`: the message is
not verified, and verifying it again once the store is back, within D, may pass. Cancellation
still propagates from the asyncio driver.

### Without the drivers: the sans-IO core

`colophon_protocol.sansio` does no I/O and reads no clock. It stops twice and asks: once for
the DNS answer, once for the replay check.

```python
from colophon_protocol import DnsFailure, TxtAnswer
from colophon_protocol.sansio import NeedKey, NeedReplayCheck, start

step = start(raw_message, receipt)  # steps 1 to 8
if isinstance(step, NeedKey):
    # step.query.name is "<selector>._colophon.<host>"; look up its TXT records your way
    step = step.resume(TxtAnswer([b"v=COLOPHON0; k=ed25519; p=..."], ttl=300))
    # or step.resume(DnsFailure.ERROR) when the lookup failed
if isinstance(step, NeedReplayCheck):
    # step.key, step.expires_at: claim the key atomically in your store
    step = step.resume(first_time=True)
    # or step.unchecked() when the store cannot be read or written, or when
    # step.late(now, max_delay) says this is more than D after step.arrival
verdict = step  # Verified | NotVerified
```

Both drivers are this loop and a few lines of error handling; the test suite runs every vector
through all three.

## Send a signed message

The sending domain holds a domain key and publishes it in DNS (§4). It issues a short-lived
credential to each agent key (§5). The agent signs each message it sends (§6).

```python
from colophon_protocol import AgentKey, DomainKey, Issuer, Named, sign
from colophon_protocol.compose import compose_message

# Once per domain: a domain key and its DNS record.
issuer = Issuer(host="acme.example", selector="s1", key=DomainKey.generate())
print(issuer.dns_name, "TXT", issuer.dns_record)
# s1._colophon.acme.example TXT v=COLOPHON0; k=ed25519; p=...

# Once a day or so: a credential for the agent's key, for at most 24 hours (§5.1).
agent_key = AgentKey.generate()
credential = issuer.issue(
    sub="ag_7Hq2",
    address="booking-agent@acme.example",
    agent_key=agent_key.public_bytes,
    issued_at=now,
    principal=Named("Maria Ortiz"),  # or Withheld() (the default), or Pseudonymous(...)
    scope="Book a table for four on Friday",
)

# Each message: build the final message, then sign it last.
message = compose_message(
    sender="Booking agent <booking-agent@acme.example>",
    to=["reservations@bistro.example"],
    subject="Table for four, Friday 8 pm",
    text="Hello,\n\nCould you hold a table for four this Friday at 8 pm?\n",
)
signed = sign(message, credential=credential, agent_key=agent_key, signed_at=now)
```

`signed` is the message's octets with `Colophon-Signature` added. Send them unchanged as a raw
message; the mail system then adds DKIM with `d=` the From host. With Amazon SES:

```python
ses.send_email(
    FromEmailAddress="booking-agent@acme.example",
    Destination={"ToAddresses": ["reservations@bistro.example"]},
    Content={"Raw": {"Data": signed}},
)
```

§6.2 requires that the issuer's DKIM signature cover `Colophon-Signature`. Amazon SES Easy DKIM
signs a fixed list of header fields, `From:To:Subject:Message-ID:Date:Content-Type:Content-Transfer-Encoding:MIME-Version`,
so its signature does not cover `Colophon-Signature`. A sender that relies on Easy DKIM alone
does not meet that rule of §6.2. Verifiers do not check it, and such messages still verify.

Anything that changes the signed parts after `sign()` (§6.2) breaks the signature: footers,
banners, subject tags and HTML parts belong in the message before it is signed. `sign()` raises
`SigningError` when a verifier would reject the result for something in the sender's hands, such
as a From that is not the credential's address or a credential too close to expiry. The draft's
header-survival test (§15, issue 1) found the header intact at Amazon SES inbound, Gmail (Google
Workspace) and Fastmail, and through a Cloudflare Email Routing forward to Gmail. Other mail
systems have not been tested.

Keys are Ed25519. `DomainKey.private_jwk()` and `DomainKey.from_jwk()` store and load them;
keep private keys in a secret store, never in the repository or in logs.

## Command line

The package installs `colophon-protocol`. Every command takes `--json`; exit status is 0 for
success, 1 for a message that did not verify and 2 for a usage error.

```
colophon-protocol keygen --role domain --out domain.jwk      # written with mode 0600
colophon-protocol dns --key domain.jwk --host acme.example --selector s1
colophon-protocol check acme.example s1                      # live DNS: what a verifier finds
colophon-protocol keygen --role agent --out agent.jwk
colophon-protocol issue --domain-key domain.jwk --host acme.example --selector s1 \
    --sub ag_7Hq2 --address booking-agent@acme.example --agent-key agent.jwk \
    --principal named:"Maria Ortiz" --out cred.jwt
colophon-protocol sign message.eml --credential cred.jwt --agent-key agent.jwk --out signed.eml
colophon-protocol verify received.eml --arrival 2026-11-08T21:15:10Z \
    --dkim-pass acme.example --address reservations@bistro.example
```

`verify` reads live DNS unless `--dns-file` gives the answers as JSON. It takes the DKIM result
either as `--dkim-pass` domains or as your server's `--authentication-results` value with its
`--authserv-id`; a result with only `header.i` counts as §7.1 says, from the message's
`DKIM-Signature` fields.

## Development

```
cd python
uv run pytest               # unit, vector, property and differential tests
uv run mypy                 # strict, over src and tests
uv run ruff check && uv run ruff format --check
uv run pytest -m network    # also the live-DNS test
```

The tests read the vectors and the reference sketch from the repository root, or from
`COLOPHON_SPEC_DIR` when set. The differential test mutates the worked example thousands of
ways and checks that this package and the sketch give the same verdict and reason on each.

See [CHANGELOG.md](CHANGELOG.md) for what changed between drafts.
