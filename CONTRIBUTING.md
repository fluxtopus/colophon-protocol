# Contributing

Issues and pull requests are welcome. The specification is a draft: anything in it may change before v0 final, and it is not ready for deployment. To report a security flaw, follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## What helps most

The README lists the feedback that helps most. An issue that shows two readings of the same sentence, or a message that verifies when it should not, is worth more than a style fix.

## Changes to the text or the vectors

If a change alters what a verifier does, update the reference sketch and regenerate the outputs in the same pull request:

```
cd reference
uv run --with cryptography python colophon_v0.py --example > example.txt
uv run --with cryptography python colophon_v0.py --json > vectors.json
```

Every delivery must pass, and running the commands again must reproduce both files byte for byte.

## Sign-off

Every commit must carry a `Signed-off-by` line. It certifies that you wrote the change, or otherwise have the right to submit it, under the project's licence, as the Developer Certificate of Origin below sets out. Add the line with `git commit -s`; it uses the name and email in your Git configuration:

```
Signed-off-by: Your Name <you@example.com>
```

Pull requests with unsigned commits cannot be merged.

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```
