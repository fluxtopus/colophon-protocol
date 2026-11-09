# Colophon v0, draft for review

Colophon lets an AI agent sign the email it sends. A receiver can then check, from DNS, the message and its own delivery facts (arrival time, DKIM result, mailbox):
- which agent wrote it;
- which domain stands behind that agent;
- who the agent acts for, as far as that person allows;
- what the domain says the agent may do.

To anyone who does not know Colophon, it is still ordinary email.

**Status:** draft v0-04, 2026-11-08. Every open issue but one is settled. The one blocker for v0 final is whether the header survives real mail systems (§15, issue 1). Appendix E lists the changes. Shared for analysis and comment. Do not deploy it. Anything here may change before v0 final.

## What is here

| File | What it is |
| --- | --- |
| [`colophon-v0.md`](colophon-v0.md) | The specification. |
| [`reference/colophon_v0.py`](reference/colophon_v0.py) | A reference sketch that signs and verifies exactly as the draft says, and runs the test vectors. It is not a library. |
| [`reference/example.txt`](reference/example.txt) | The sketch's output: the worked example of Appendix A and the vector results. |
| [`reference/vectors.json`](reference/vectors.json) | The test vectors of Appendix B, machine-readable: each message as base64 of its octets, the receiver's inputs, and the expected verdict and reason. |
| [`figures/`](figures/) | The specification's figures, as SVG. They are informative: the text is normative. |
| [`tests/header-survival/`](tests/header-survival/) | The harness for the header-survival test of §15, issue 1: builds and sends the three messages, captures what receivers stored, verifies and reports. `PRIOR-EVIDENCE.md` there collects what public sources say. |

Run the sketch (Python 3.10 or later):

```
uv run --with cryptography python reference/colophon_v0.py            # vectors only
uv run --with cryptography python reference/colophon_v0.py --example  # example, then vectors
uv run --with cryptography python reference/colophon_v0.py --json > reference/vectors.json
```

## How to read it

- **The core in ten minutes:** §3 Overview, then §7.2, the verifier's steps.
- **To implement it:** §4 to §7, with Appendix A open beside them.
- **To attack it:** §9 Security and §10 Privacy, then try to make two verifiers disagree.

## What feedback helps most

1. Places where two careful implementers would build different things from the same text. §12 treats each one as a bug in the spec.
2. Attacks: a message that verifies when it should not, or a way to link an agent across counterparties.
3. Claims that are stronger than the mechanism.
4. Evidence for §15 issue 1: raw messages showing whether the header survives a mail system.

## Licence

Apache 2.0, for the text and the code.

A royalty-free patent promise is planned; until then the Apache-2.0 license covers the reference code.

## Contributing and security

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Report security flaws privately, as [SECURITY.md](SECURITY.md) describes.
