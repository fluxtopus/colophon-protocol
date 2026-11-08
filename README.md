# CREST v0, draft for review

CREST lets an AI agent sign the email it sends. A receiver can then check, from DNS and the message alone:
- which agent wrote it;
- which domain stands behind that agent;
- who the agent acts for, as far as that person allows;
- what the domain says the agent may do.

To anyone who does not know CREST, it is still ordinary email.

**Status:** draft v0-00, 2026-11-08. Shared for analysis and comment. Do not deploy it. Anything here may change.

## What is here

| File | What it is |
| --- | --- |
| [`crest-v0.md`](crest-v0.md) | The specification. |
| [`reference/crest_v0.py`](reference/crest_v0.py) | A short reference sketch that signs and verifies exactly as the draft says, and runs the test vectors. It is not a library. |
| [`reference/example.txt`](reference/example.txt) | The sketch's output: the worked example of Appendix A and the vector results. |

Run the sketch (Python 3.10 or later):

```
uv run --with cryptography python reference/crest_v0.py            # vectors only
uv run --with cryptography python reference/crest_v0.py --example  # example, then vectors
```

## How to read it

- **The core in ten minutes:** §3 Overview, then §7.2, the verifier's steps.
- **To implement it:** §4 to §7, with Appendix A open beside them.
- **To attack it:** §9 Security and §10 Privacy, then try to make two verifiers disagree.

## What feedback helps most

1. Places where two careful implementers would build different things from the same text. §12 treats each one as a bug in the spec.
2. Attacks: a message that verifies when it should not, or a way to link an agent across counterparties.
3. Claims that are stronger than the mechanism.
4. Answers to the open issues in §15, especially issue 1, the addressing check, and issue 3, whether the header survives real mail systems.

## Licence

Apache 2.0, for the text and the code.
