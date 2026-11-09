# TypeScript library: plan

Status: plan only, nothing built. The npm name is `colophon-protocol`; version 0.0.0 holds the name
and has no code. The TypeScript library follows the Python library in [`python/`](../python), so a
receiver or sender can switch languages without relearning the API.

## Shape

- **One package, ESM only, no runtime dependencies** if WebCrypto Ed25519 is enough (see the
  decisions below). It targets current Node, Deno, Bun and edge runtimes. Message octets are
  `Uint8Array` throughout; times are Unix seconds as `number`.
- **Entry points.** `colophon-protocol` holds `verify`, `sign`, `Issuer` and the types.
  `colophon-protocol/core` is the sans-IO state machine. `colophon-protocol/node` holds the
  `node:dns` resolver, and `colophon-protocol/doh` a DNS-over-HTTPS resolver for runtimes without
  a DNS API. The core never imports anything runtime-specific.
- **Results are discriminated unions** of frozen plain objects, so `if (v.verified)` narrows:

```ts
type Verdict =
  | { readonly verified: true; readonly agent: Agent; readonly selector: string;
      readonly credentialHash: string; ... }
  | { readonly verified: false; readonly reason: Reason; readonly detail: string };
type Reason = "no_signature" | "multiple_signatures" | "malformed" | ... | "replay";
```

## API

```ts
import { verify, sign, Issuer, DomainKey, AgentKey } from "colophon-protocol";
import { NodeResolver, GuardedResolver } from "colophon-protocol/node";

const resolver = new GuardedResolver(new NodeResolver());  // §7.4 cache and miss limit
const verdict = await verify(raw, {
  arrival: 1793870110,
  dkimPassDomains: ["acme.example"],
  mailbox: "mbx-reservations",
  mailboxAddresses: ["reservations@bistro.example"],
}, { resolver, replayStore });  // replayStore.claim(key, expiresAt): Promise<boolean>

const issuer = new Issuer({ host: "acme.example", selector: "s1", key: await DomainKey.generate() });
const credential = await issuer.issue({ sub: "ag_7Hq2", address: "booking-agent@acme.example",
                                        agentKey: agentKey.publicBytes, issuedAt: now });
const signed: Uint8Array = await sign(message, { credential, agentKey, signedAt: now });
```

```ts
import { start } from "colophon-protocol/core";   // no I/O, no clock
let step = start(raw, receipt);
if (step.kind === "need_key") step = step.resume(answerOrFailure);  // TxtAnswer | "dns_error" | ...
if (step.kind === "need_replay_check") step = step.resume(firstTime);
```

```ts
import { colophonResinfo, authenticationResults } from "colophon-protocol";  // §7.8, pure
colophonResinfo(verdict);  // 'colophon=pass header.from=... header.cred=...'
authenticationResults(verdict, { authservId: "mx.bistro.example",
                                 otherResinfo: ["dkim=pass header.d=acme.example"] });
```

`verify()` never rejects for anything in the message or the DNS answer, as in Python. It rejects
only when the replay store does. `sign()` and `issue()` throw `SigningError` and `IssueError`
with the reason a verifier would give.

## Rules that differ from writing Python

- **Never decode the message to a string.** `TextDecoder` replaces invalid UTF-8 with U+FFFD.
  Parse MIME over bytes with hand-written scanners, as the Python `_mime` module does.
- **No `RegExp` on message input.** JavaScript regular expressions backtrack. Grammar checks on
  short, already length-capped fields may use anchored expressions without nested quantifiers;
  a lint rule enforces it.
- **`JSON.parse` is not I-JSON.** It keeps the last duplicate member and turns large integers into
  floats silently. Credentials and signature headers need a small strict parser: unique names,
  integers within 2^53 - 1 without fraction or exponent, no lone surrogates or noncharacters.
- **JCS.** RFC 8785 is defined on ECMAScript's own serialization: `JSON.stringify` writes strings
  and safe integers as it requires, and the default string sort compares UTF-16 code units. Only
  the member ordering and the I-JSON checks need code.
- **Prototype safety.** Parsed objects are `Object.create(null)` or `Map`, so that a claim named
  `__proto__` stays data.
- **Node's `resolveTxt` returns strings, not octets,** so a record with non-UTF-8 bytes cannot be
  seen exactly. This is harmless for a well-formed record, but the Python library keeps
  octets; the vectors should settle what a verifier compares (see the §4.1 note in the report).

## Testing and CI

- The shared vectors through the conformance runner, using a `conformance/adapters/typescript.mjs`
  adapter: 80/80 on verdicts and on the §7.8 resinfo is the bar, in the same workflow as the
  sketch and the Python library.
- The worked example reproduced byte for byte, with the test seeds the sketch uses.
- Cross-implementation differential tests: the Python mutation generator writes mutated messages,
  and both libraries must give the same verdict through the conformance contract.
- Property tests (fast-check): random bytes and DNS answers never make `verify()` reject.
- `tsc --strict` with `exactOptionalPropertyTypes` and `noUncheckedIndexedAccess`.

## Decisions before building

1. **Ed25519 verification.** WebCrypto Ed25519 keeps the package
   dependency-free. But implementations differ on non-canonical encodings and small-order keys,
   which §7.2 does not settle yet. If the spec chooses RFC 8032's strict rules and a runtime does
   not follow them, use `@noble/curves`, which can be configured to follow them, as the one
   dependency.
2. **Runtime floor.** The oldest Node whose WebCrypto Ed25519 is stable, checked when building;
   anything older needs the dependency.
3. **Sender-side MIME.** Python's `compose_message` uses the standard library. TypeScript has no
   equivalent, so either a minimal composer (text/plain and multipart/mixed only, as §6.1 allows)
   or no composer, and `sign()` only.
