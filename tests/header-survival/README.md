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

A typical header is about 700 octets. The 2,560-octet cap stays; the room above what the four
members of section 6.5 need (about 2,310 octets with a 2,048-octet credential) is for extensions.
The cap message fills it with an extension member in the agent signature's protected header,
which the verifier ignores.

## What is reported

For every receiver and message:

- **Header state.** `identical` (the octets as sent), `refolded` (same value, other line
  breaks; allowed by section 6.2), `missing`, `truncated`, `altered` or `duplicated`.
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
read from a file outside the repository (`password_file`, a bare value or a dotenv line) or
from an environment variable (`password_env`), and Microsoft Graph signs in with the device code flow against an app
registration whose client id is in the file.

Most providers need no API access at all. A receiver with `"capture": {"kind": "file"}` is
collected by hand: open the delivered message in the provider's own client, export its raw
source, and drop the file into `runs/exports/<receiver>/` (any file name; `build` creates the
directory and `capture` finds the message by its run token). The verifier then runs on the
exported octets exactly as it does on an IMAP or S3 capture, with the arrival time and the
DKIM results taken from the provider's own `Received` and `Authentication-Results` headers.
Where to find the raw source:

| Provider | Export |
|---|---|
| Microsoft 365, Outlook.com | Outlook on the web: open the message, More actions, View, View message source; save as `.eml` |
| iCloud Mail | Apple Mail: File, Save As, format Raw Message Source |
| Fastmail | More, Show raw message; save the page as `.eml` |
| Yahoo Mail | More, View raw message; save as `.eml` |
| Proton Mail | More, Export; the download is the full `.eml` (the "view headers" `.txt` is not enough) |
| Zoho Mail | More options, Show original; save as `.eml` |

Line endings are normalised to CRLF on read, so an export saved with LF is fine. An export
dropped into a receiver's directory is used even when that receiver is set up for IMAP or
Graph. Receivers that share a mailbox (a direct address and a forwarding hop) may be exported
into one directory; the harness tells the copies apart by the `To` header. Only Gmail is
collected over IMAP with an app password; the password file lives in the operator's private
storage, never in the repository or the shell history.

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
- **file** reads messages exported by hand into `runs/exports/<receiver>/` (`.eml`, `.txt` or
  `.mime`), found by the run token. Each provider's export is its own serialisation of the
  stored message, so a `refolded` result here, like one from Graph, says the value survived.

Runs live under `runs/` (ignored by git). The stored messages are personal data: they name
real mailboxes and carry `Received` chains, provider headers and storage keys. They stay
private. What a run publishes is `report --out results/<run-id>`: `results.md`, `results.json`
and `headers.md`, the last holding each copy's `Colophon-Signature` field as sent and as
stored, which names no mailbox, host or storage key. `.gitignore` keeps captures, sent copies
and run metadata out of `results/`. Domains the operator owns besides the sender's go in
`private_domains` in the receivers file, each with the neutral label that replaces it in the
published files (a forwarding domain appears among the DKIM signers of a forwarded copy).
