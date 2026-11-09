# Changelog

## Unreleased: draft v0-06

`SPEC_VERSION` is `"v0-06"`. The package scores 118/118 on the v0-06 conformance vectors, for
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

## draft v0-05

The first version of the package.
