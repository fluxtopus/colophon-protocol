# Security

Report a security flaw privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**, or go to <https://github.com/fluxtopus/colophon-protocol/security/advisories/new>. Do not open a public issue for it.

Flaws in the protocol count, not only in the code. Examples:
- a message that verifies when it should not;
- a way to link an agent across its counterparties;
- a place where two verifiers that follow the text reach different verdicts on the same message.

The reference sketch in `reference/` exists to check the text and produce the test vectors. It is not production code, and the draft is not ready for deployment.
