# Header-survival test

The harness for issue 1 of specification section 15: does a `Colophon-Signature` header reach
real mailboxes intact? It builds three signed messages, sends them through Amazon SES, fetches
what each receiver stored, runs the reference verifier on the stored message with the receiver's
own inputs, and writes a results table.

Nothing here changes `reference/colophon_v0.py`. The harness imports the sketch and calls its
`sign` and `verify`; the tests check that the sketch's outputs still reproduce byte for byte.

## The three messages

| Label | What it tests | Header value, whitespace removed |
| --- | --- | --- |
| `minimal` | a short header: principal withheld, no scope | about 700 octets |
| `cap` | the largest header the spec allows: a 128-octet named principal, a 280-octet scope, a credential of exactly 2,048 octets and a value of exactly 2,560 | 2,560 octets |
| `attachments` | a pseudonymous principal with a scope, plus a CSV and a PDF attachment | about 1,000 octets |

Each message carries an `X-Colophon-Test: <run-id>/<label>` header and the same token in its
subject, so the capture tool can find it in any folder, including spam.

The cap message reaches 2,560 octets only with an extension member in the agent signature's
protected header, which the verifier ignores. With the four members of section 6.5 alone, a
2,048-octet credential gives a value of about 2,310 octets; see the note in the results.

## What is reported

For every receiver and message:

- **Header state.** `identical` (the octets as sent), `refolded` (same value, other line
  breaks; allowed by section 3.1), `missing`, `truncated`, `altered` or `duplicated`.
- **Verdict.** The sketch's verdict on the stored message with these inputs (section 7.1):
  arrival time from the receiver's topmost `Received`; DKIM pass domains from the receiver's
  own `Authentication-Results` (`header.d`, else the domain of `header.i`); the mailbox and its
  addresses from the receivers file; the domain key from a live TXT lookup, or a record given on
  the command line.
- **Signed fields that changed in transit**, when the header is intact but the signature fails
  (a forwarder that rewrote the subject, for instance).

Deliveries through a forwarding hop (Cloudflare Email Routing, a Gmail forward) are reported in
a second table as recorded forwards: they show what the whole path did, not one provider.

## Running it

Python 3.10 or later and [uv](https://docs.astral.sh/uv/). All commands from this directory.

```
uv run pytest                                   # the harness's own tests
uv run python -m survival keys ../../../colophon-keys        # private keys, outside the repo
uv run python -m survival build --key-dir ../../../colophon-keys
uv run python -m survival send --run-id <run-id> --profile <aws-profile>
uv run python -m survival capture --run-id <run-id>
uv run python -m survival report --run-id <run-id>
```

`receivers.json` (never committed; copy `receivers.example.json`) names the sender address and
each receiver: where to send, how to capture (`imap`, `graph`, `s3` or `file`), the receiver's
authserv-id, and any forwarding hops. Credentials are never in that file: an IMAP password is
named by an environment variable (`password_env`), and Microsoft Graph signs in with the device
code flow against an app registration whose client id is in the file.

`send` refuses to run while the SES account is in the sandbox unless `--allow-sandbox` is given,
because sandboxed accounts deliver only to verified addresses.

`check` runs the raw-message mode on one stored message, with or without the message as sent:

```
uv run python -m survival check stored.eml --sent sent.eml \
  --mailbox gmail:someone@example.com --address someone@example.com \
  --authserv mx.google.com \
  --dns-record 's1._colophon.colophon-protocol.org=v=COLOPHON0; k=ed25519; p=...'
```

## What the sender domain needs

For a sender `test@<host>` the harness needs, besides the host being a verified SES identity
with DKIM:

```
s1._colophon.<host>.  TXT  "v=COLOPHON0; k=ed25519; p=<domain public key from `keys`>"
```

The private keys never enter the repository. The deterministic keys the tests use
(`--test-keys`) are public knowledge and are for dry runs only.

## Capture notes

- **IMAP** fetches with `BODY.PEEK[]`, which does not mark the message read, and searches
  every selectable folder, inbox first.
- **Microsoft Graph** returns MIME that Exchange regenerates from its store. The header's content
  is what Exchange kept; its folding is Exchange's. A `refolded` result from Graph therefore says
  the value survived, not that the octets did.
- **S3** reads what an SES receipt rule stored. SES writes the message unmodified with its own
  `Authentication-Results` on top.
- **file** reads `.eml` files exported by hand (Proton Mail, a webmail "show original").

Runs live under `runs/` (ignored by git). A run worth keeping is copied to `results/` with its
captures, so the table can be checked against the stored messages.
