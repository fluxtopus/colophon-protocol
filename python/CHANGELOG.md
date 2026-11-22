# Changelog

## 0.1.0: draft v0-07

The first release on PyPI. Version 0.0.0 there is a placeholder that holds the name.

`SPEC_VERSION` is `"v0-07"`. The package scores 134/134 on the v0-07 conformance vectors, for
verdicts and for the §7.8 resinfo.

### Verifying

- **Local parts, §6.4.** A fixed list of characters is no longer allowed in a local part: C1
  controls, invisible and zero-width characters, bidirectional controls, variation selectors and
  tag characters. An address that holds one is `malformed`. Before, such an address could verify,
  and `colophon_resinfo()` then raised on it.
- **Counting signatures, §7.2.** Steps 1 and 2 count `Colophon-Signature` lines before the
  header section is checked, so unsigned or doubly signed mail is `no_signature` or
  `multiple_signatures` even when another header line is bad. Before, it was `malformed`.

### Hardening

These change no verdict.

- **Body canonicalisation, §6.4.** Quoted-printable decoding, the text steps and the multipart
  split work on whole buffers in C, with no object per line. On an 8 MB body of short lines,
  peak memory falls from about 33 times the body to 4 times or less, and quoted-printable
  decoding runs about 5 times faster (0.15 s rather than 0.9 s).
- **DNS miss limit, §7.4.** A lookup in flight holds a place in its host's miss count, once
  per name. Concurrent lookups of many names at one host no longer all pass a limit that had
  one place left, and a burst of messages that need one name is still not limited. A lookup
  that is cancelled counts as a miss in `AsyncGuardedResolver`, so an `aio.verify` lookup that
  runs past its DNS budget now counts toward the limit.
- **CNAME TTLs, §7.4.** `DnspythonResolver` caches an answer reached through CNAMEs for the
  least TTL on the chain, not only the TXT RRset's.
- **Issuing, §5.5.** `Issuer.issue` rejects an agent key that is not canonical or is of small
  order before the domain key signs. It raises only `IssueError`, also for an agent key of the
  wrong type and for an extension name that is not a string.
- **Credential.parse** raises `ValueError`, not `KeyError`, for a token with no `iss`, so
  `sign()` reports it as a `SigningError`.

### Authentication-Results, §7.1

- `dkim_pass_domains` reads the field by the RFC 8601 grammar. A quoted string is one value, so
  spaces inside a quoted `header.i` no longer start a new property. The authserv-id may be
  followed only by version `1`. A `dkim` result counts only with method version absent or `1`.
  A result with a repeated property counts for nothing. A field that does not lex counts for
  nothing.
- `dkim_identity_domain` (recovering d= from `header.i`) requires the identity to be d= or under
  it, as RFC 6376 §3.5 does, and returns `None` when any DKIM-Signature field in the message has
  no identity it can read.

## draft v0-06

Not published on its own. Its changes ship in 0.1.0, above.

`SPEC_VERSION` is `"v0-06"`. The package scores 123/123 on the v0-06 conformance vectors, for
verdicts and for the §7.8 resinfo, and agrees with the reference sketch on every message the
differential test makes.

### Verifying

- **Header sections and MIME, §6.1.** Lines end at CRLF or LF; a bare CR or a line that is not a
  field is `malformed`. Content-Type parameters follow RFC 2045 §5.1 strictly, and are read only
  at the top level and in the body part; attachment parameters are not read, so an RFC 2231
  filename or an attachment parameter that does not parse no longer fails the message. The RFC
  2231 form of `boundary`, `charset` or `format` is `layout`. Multipart follows RFC 2046 §5.1.1
  strictly: a missing or invalid boundary (1 to 70 characters), a line that starts with the
  delimiter but is not one, a delimiter after the close delimiter, two delimiter lines in a
  row, no close delimiter and no parts are `malformed` (several were `layout`). A transfer
  encoding other than 7bit, 8bit or binary on the multipart is `layout`.
- **DNS, §4.1 and §7.4.** A TXT record with an octet above 0x7F is skipped, as not a Colophon
  record.
- **Ed25519, §6.5.** A domain key that is not canonical or is of small order is
  `key_not_found`; such an agent key (`cnf.jwk.x`) is `credential_invalid`. A signature whose R
  is of small order fails. S < L and the equation without the cofactor were already enforced.
- **Replay, §7.6.** New reason `Reason.REPLAY_UNCHECKED`, reported as `temperror`.

### API changes

- **Breaking: a replay store that raises no longer raises out of `verify`.** Both drivers return
  `NotVerified(Reason.REPLAY_UNCHECKED)`. Cancellation still propagates from `aio.verify`.
- `verify` and `aio.verify` take `max_delay` (D, in seconds) and `clock`. With `max_delay` set,
  a message verified more than D after `Receipt.arrival` is `replay_unchecked`. Off by default.
- `sansio.NeedReplayCheck` has `arrival`, `late(now, max_delay)` and `unchecked(detail)`.
- **Breaking: `authres.dkim_pass_domains` drops `use_header_i`,** which counted the domain of
  `header.i` and could count a subdomain of `d=`. It takes `message` instead: a result with only
  `header.i` counts for the `d=` of the one `DKIM-Signature` field whose identity equals it
  (§7.1). New `authres.dkim_identity_domain(message, header_i)`.
- `authres.colophon_result` maps `replay_unchecked` to `temperror`.
- CLI: `verify --header-i` is gone; with `--authentication-results`, `header.i` is read as §7.1
  says.

### Conformance runner

- The contract stays `colophon-conformance/1`. Each delivery has two more members,
  `dns_misses` and `replay_store_available`, and `replay_unchecked` is a valid reason. Both
  adapters read the new members, with defaults of 0 and true.
- A third member, `dkim_pass_identities`, holds the `header.i` of passing DKIM signatures
  reported without `header.d`. Both adapters recover its `d=` from the message (§7.1), and
  default it to empty. Five vectors use it.

## draft v0-05

The first version of the package.
