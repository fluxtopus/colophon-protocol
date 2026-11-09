# Conformance

`run.py` checks a Colophon v0 verifier against the test vectors in
[`reference/vectors.json`](../reference/vectors.json). It works with an implementation in any
language: the runner starts a command you give it, and the two talk JSON over stdin and stdout.

```
python conformance/run.py -- <command> [args...]
```

The runner needs Python 3.10 or later and nothing else. It prints one line per delivery and a
score, and exits 0 only when every delivery passes. Options: `--vectors <path>` (default
`reference/vectors.json`), `--timeout <seconds>` per vector (default 20), `--only <text>` to run
the vectors whose name contains the text, and `--quiet` to print failures and the score only.

The two adapters in this directory score 80/80:

```
# The reference sketch, from the repository root
python3 conformance/run.py -- uv run --with cryptography --no-project python conformance/adapters/sketch.py

# The Python library in python/
cd python && uv run python ../conformance/run.py -- uv run python ../conformance/adapters/library.py
```

## The contract: `colophon-conformance/1`

For each vector the runner starts the command once, writes one JSON object to its stdin, closes
stdin, waits for it to exit, and reads one JSON object from its stdout. Stderr is ignored, except
that its last line is shown when the command fails.

### Input

```json
{
  "contract": "colophon-conformance/1",
  "name": "replay: one mailbox, its alias, and a second mailbox",
  "message": "Q29sb3Bob24tU2lnbmF0dXJlOiB2PTA7...",
  "deliveries": [
    {
      "accepted_at": 1793870110,
      "dkim_pass_domains": ["acme.example"],
      "envelope_recipient": "reservations@bistro.example",
      "mailbox": "mbx-reservations",
      "mailbox_addresses": ["reservations+web@bistro.example", "reservations@bistro.example"],
      "dns_txt": {
        "s1._colophon.acme.example": ["v=COLOPHON0; k=ed25519; p=fKF-JHnT8l0RiMibgA4oUYQKwUzyDxroUgxaRM6i6lI"]
      }
    }
  ]
}
```

- `message`: the message's octets as accepted, in standard base64 with padding (RFC 4648 §4).
  The octets are exact: line endings, folding and 8-bit content all matter. Decode to bytes and
  hand the bytes to the verifier; do not round-trip through a string type.
- `deliveries`: one or more deliveries of that same message, **in order**. They share one replay
  store (§7.6), created empty for the vector. A replay vector delivers the same message to one
  mailbox twice, or to two mailboxes, and expects `replay` only for the second copy in the same
  mailbox.
- `accepted_at`: §7.1's arrival time, Unix seconds. Verify as if the clock read this; never read
  the real clock.
- `dkim_pass_domains`: the `d=` of every DKIM signature the receiver's own checks passed.
- `mailbox`: the receiver's stable identifier for the mailbox this copy reached; the replay key
  uses it.
- `mailbox_addresses`: every address that mailbox receives at (§7.5).
- `envelope_recipient`: the SMTP `RCPT TO` of this copy. Informative: §7.5 decides on the
  mailbox's addresses, not on the envelope, and a conforming verifier may ignore it.
- `dns_txt`: the DNS as the verifier sees it, by query name. A name that is present maps to its
  TXT records, each with its character strings already joined (§4.1); an empty list is a name with
  no TXT records. A name that is **absent** is NXDOMAIN. A name that maps to **`null`** is a lookup
  that failed (a timeout or SERVFAIL), which is `dns_error`. Answer from this map only: no real
  DNS, no cache shared between vectors, and no §7.4 miss limit (no vector expects
  `dns_limited`).

Ignore members you do not know; later versions of the contract may add some. A different
`contract` value is a different contract: fail.

### Output

```json
{"deliveries": [{"verdict": "verified", "agent": {"iss": "acme.example", "sub": "ag_7Hq2"}},
                {"verdict": "not_verified", "reason": "replay"}]}
```

One entry per input delivery, in the same order. `verdict` is `"verified"` or
`"not_verified"`; a `not_verified` entry has `reason`, one of the §7.2 codes: `no_signature`,
`multiple_signatures`, `malformed`, `dkim_unaligned`, `unsupported_version`,
`credential_invalid`, `dns_error`, `dns_limited`, `key_not_found`, `key_revoked`,
`credential_expired`, `from_mismatch`, `layout`, `signature_invalid`, `not_addressed`, `replay`.
Other members, such as `agent` or a `detail` string, are allowed and ignored.

Exit 0 after writing the result. A non-zero exit, a timeout, output that is not one JSON object,
or the wrong number of entries fails every delivery of the vector. A verifier that crashes on a
hostile message fails; a not-verified verdict is the right answer to anything it cannot parse.

## Writing an adapter

An adapter is a short program around the implementation's verify call: decode the input, build
the receipt for each delivery, give the verifier a resolver that reads `dns_txt` and the one
replay store, and print the verdicts. The two Python adapters here are about 50 lines each.

**TypeScript (Node).** Read stdin to the end (`for await (const chunk of process.stdin)`), then
`JSON.parse`. Decode the message with `Buffer.from(message, "base64")` and keep it a
`Uint8Array`. Do not turn it into a string: a `TextDecoder` replaces invalid UTF-8 with U+FFFD and
would change the octets the signature covers. Treat `dns_txt` with `Object.hasOwn(map, name)`, so
that an absent name (NXDOMAIN) and `null` (a failed lookup) stay apart, and so that a name such as
`__proto__` cannot reach the prototype. Write the result with `process.stdout.write`, and let the
process end on its own rather than calling `process.exit`, which can cut off buffered output to a
pipe. Run it as `node adapter.mjs` or `npx tsx adapter.ts`.

**Go.** Decode into a struct whose `DNSTXT` field is `map[string]*[]string`, so that `null`
decodes to a nil pointer while an absent name is a missing key; `json.RawMessage` works as well.
`encoding/json` decodes the base64 for you when the field is `[]byte`. Check `contract` before
using anything else. Build the binary once and pass its path: `go run` per vector compiles each
time and is slow against the 20 second default timeout.

**Anything else.** The runner sends at most a few hundred kilobytes per vector. Read all of stdin
before writing anything, write all of stdout before exiting, and keep diagnostic output on
stderr.
