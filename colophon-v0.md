# Colophon v0: Agent Signatures for Email

Draft v0-04, 2026-11-08. For review. Not for production use.
Editor: Jorge Vivas (Fluxtopus).
Licence: Apache 2.0.

## Abstract

Colophon lets an AI agent sign the email it sends.

A receiver can then check three things, from DNS, the message, and its own delivery facts (when the message arrived, which DKIM signatures passed, and which mailbox it was delivered to):
- which agent wrote the message;
- which domain issued that agent and stands behind it;
- what the domain says the agent acts for: its principal, as far as the principal allows, and a short statement of its authority.

Colophon adds one header to an ordinary email. A receiver that does not know Colophon sees a normal message.

v0 is the identity layer only. Tasks, offers and agreements come later, in a separate document, Colophon Tasks, built on this one.

## Contents

1. Introduction
2. Conventions and terms
3. Overview
4. Domain keys in DNS
5. The agent credential
6. The signed message
7. Verifying
8. First contact and receiver control
9. Security considerations
10. Privacy considerations
11. Versioning and extensions
12. Conformance
13. Registrations
14. Relation to A2A and Colophon Tasks
15. Open issues

Appendices:
- A. Worked example
- B. Test vectors
- C. Formal model
- D. Decision log
- E. Changes

## 1. Introduction

Agents already send email: they book, buy, schedule, follow up and hand work to one another. A receiver cannot tell an agent's message from a person's. If it is an agent's, the receiver cannot tell whose agent it is or what it may do.

DKIM proves that a domain's mail system sent a message. It does not say which agent of that domain wrote it, who that agent acts for, or what it is allowed to do.

Colophon adds that. It is built on what email already has:
- DKIM, for the domain;
- DNS, for keys;
- MIME, for the message;
- JOSE (JWS, JWK, EdDSA) and JCS, for signatures.

It needs no central registry, no HTTPS fetch, and no service run by any one company.

### 1.1 Principles

1. **Plain email first.** A signed message is a valid, readable email. A receiver that ignores Colophon loses nothing.
2. **Verifiable by anyone.** Any implementation checks a message from DNS, the message itself, and the receiver's own delivery facts: arrival time, DKIM result and mailbox.
3. **Built on what exists.** DKIM, DNS, MIME and JOSE before anything new.
4. **Receiver in control.** The receiver decides who gets in and what to act on. A sender cannot force its way in.
5. **Agents act on a person's authority.** A person delegates authority to an agent, and the agent acts on its own within it. Every credential traces to that person.
6. **Least disclosure.** An agent reveals who it acts for only as much as its principal allows.
7. **Small core.** v0 does signed messages and first contact. Everything else is an extension or a later document.

### 1.2 What v0 does not do

v0 has:
- no task states;
- no offers or agreements;
- no machine-readable request format;
- no discovery or directory of agents;
- no payments;
- no transport other than email.

It does not judge whether an agent is trustworthy, and it does not enforce what an agent may do. It states who spoke, for whom, with what stated authority, and whether the message is intact.

## 2. Conventions and terms

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

| Term | Meaning |
| --- | --- |
| Agent | Software that sends email on someone's behalf and signs it with its own key. |
| Principal | The person, or organisation, whose authority the agent carries. |
| Issuer | The domain that issues credentials to agents. It is the host of the agent's address, and its mail system sends the agent's mail. Usually it is a mail provider acting for the domain. |
| Domain key | An Ed25519 key pair of the issuer. The public key is published in DNS under a selector. |
| Selector | A DNS label that names one domain key, as in DKIM. |
| Agent key | An Ed25519 key pair held for one agent address. |
| Credential | A short-lived statement, signed with a domain key. It binds an agent key to one address, a principal disclosure and an optional scope. |
| Agent signature | A signature by the agent key over the message's signing input. |
| Signing input | A JSON object built from the message. Signer and verifier build it the same way. |
| Signer | The software that signs a message with an agent key, before the message leaves the issuer's mail system. |
| Verifier | The software at the receiver that checks a message. |
| Receiver | The mail system and mailbox that accepted the message. |
| Arrival time | The moment the receiver's mail server accepted the message in SMTP (the end of the DATA phase). |
| Verdict | The verifier's result: **verified**, or **not verified** with a reason. |

Values written in `code` are exact. "JCS" is the JSON Canonicalization Scheme (RFC 8785). Times are integer seconds since the Unix epoch, UTC.

"base64url" is the URL-safe alphabet without padding (RFC 4648 §5), decoded strictly. A value with padding, with `+` or `/`, with any other character, or with unused bits that are not zero is invalid. This holds everywhere Colophon uses base64url, the DNS record included.

A grammar written as a regular expression must match the whole value. A value with anything before or after the match, a line break included, does not match.

The figures are informative. Where a figure and the text differ, the text is right.

## 3. Overview

A Colophon message carries two proofs. A receiver believes "agent X of acme.example" only when both hold.

1. **The domain's mail system sent it.** The message passes DKIM, and the DKIM signing domain is exactly the `From` host.
2. **This agent wrote it.** The message carries a credential and an agent signature in one header, `Colophon-Signature`:
   - the credential is signed by a domain key that the `From` host publishes in DNS;
   - the agent signature, made with the key the credential names, covers the message's addresses, subject, text and attachments.

![Two boxes, side by side, lead to one verdict. Proof 1, the domain's mail system sent it: a DKIM signature passes, its d= is exactly the From host, and it covers the Colophon-Signature header. It is checked at step 4, before any DNS lookup. Proof 2, this agent wrote it, is a chain of three: the domain key published in DNS at s1._colophon.acme.example signs the credential c, which lasts at most 24 hours and binds an agent key to one address; that agent key makes the agent signature b, over From, To, Cc, Reply-To, Subject, the text and the attachments. Both proofs lead to: verified, both proofs hold. A note says c and b travel together in one header: Colophon-Signature: v=0; c=…; b=….](figures/figure-1-two-proofs.svg)

*Figure 1. The two proofs. The credential is in §5, the agent signature in §6.5, and the order of the checks in §7.2.*

The issuer reissues each credential automatically, at least once a day. To revoke an agent, the issuer stops reissuing its credential. The credential then lapses within 26 hours: its 24-hour life plus a 2-hour grace for mail in transit.

![A timeline of one credential, from iat to exp, which is at most 24 hours later, and on to exp plus 2 hours. Four bars. The credential is valid from iat to exp. The signer uses it from iat until 6 hours are left; it should not sign in the last 6 hours. A message may arrive from iat minus 5 minutes to exp plus 2 hours. The replay record for a verified message is kept from the moment it verifies to exp plus 2 hours. A bracket under the whole span says: revoke by not reissuing; the last credential's mail stops verifying within 26 hours.](figures/figure-2-credential-times.svg)

*Figure 2. One credential's times. The limits are in §7.7; the arrival check is step 14 of §7.2, and the replay record is in §7.6.*

Revocation does not end a stolen agent key by itself. Every message carries a credential, so whoever holds the key can reuse one. A stolen key stays usable until the issuer stops certifying it, and for up to 26 hours after (§5.2, §9).

The verifier checks the message as its own mail server accepted it. The result is **verified**, or **not verified** with a reason. A message that is not verified is still delivered as plain email. Colophon never blocks delivery.

## 4. Domain keys in DNS

### 4.1 The record

An issuer publishes each domain key as a TXT record at:

```
<selector>._colophon.<host>
```

Here `<host>` is the domain of the agent addresses: the right-hand side of the `@`.

The record is a tag list in the style of DKIM (RFC 6376 §3.2):

```
v=COLOPHON0; k=ed25519; p=<base64url of the 32-byte Ed25519 public key>
```

- `v` MUST be `COLOPHON0`.
- `k` MUST be `ed25519`.
- `p` is the raw 32-octet public key (RFC 8032), in base64url. An empty `p=` means the key is revoked.
- The record is parsed like the header (§6.2): all whitespace is removed, then it is a list of `name=value` items separated by `;`. Unknown tags are ignored. A record with a duplicate tag is not a Colophon record.
- If a TXT record has several character strings, they are joined with nothing between them before parsing, as in DKIM.

A selector is one DNS label: lowercase letters, digits and hyphens, from 1 to 63 characters, not starting or ending with a hyphen. Its grammar is `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`.

Other TXT records may share the name. §7.4 says exactly which record a verifier uses, and what it concludes when there is none, or more than one. An issuer MUST publish exactly one Colophon record at each selector.

### 4.2 Rotation and removal

- Several selectors MAY be live at once, so keys rotate as DKIM keys do.
- A retired selector SHOULD stay published for at least 7 days after the last credential it signed.
- A compromised domain key MUST be removed, or set to an empty `p=`, at once.
- The record's TTL SHOULD be at most 1 hour. The TTL is the most time a removal can take to reach verifiers.

### 4.3 Domains run by a provider

A domain whose mail a provider runs SHOULD publish a small fixed set of selectors, for example `s1` and `s2`. Each is a CNAME to a name the provider controls:

```
s1._colophon.customer.example.  CNAME  s1.customer-example.colophon-keys.provider.example.
s2._colophon.customer.example.  CNAME  s2.customer-example.colophon-keys.provider.example.
```

The provider then rotates keys under those names, and the customer never touches DNS again. This is how many providers handle DKIM.

A single CNAME at `_colophon.<host>` does not work: a CNAME does not redirect the names below it (RFC 1034 §3.6.2).

## 5. The agent credential

### 5.1 Format

A credential is a JWS in compact serialization (RFC 7515), with an Ed25519 signature (`EdDSA`, RFC 8037) by a domain key.

**Protected header**

| Member | Value |
| --- | --- |
| `alg` | `EdDSA` |
| `typ` | `colophon-cred+jwt` |
| `kid` | the selector of the domain key |

A verifier MUST reject a protected header that contains `crit`. It ignores any other member.

**Claims (payload)**

| Claim | Required | Value |
| --- | --- | --- |
| `iss` | yes | A string: the issuer host, in lowercase. It MUST equal the host of `from`. |
| `sub` | yes | A string: the agent ID, unique within the issuer. Grammar: `[A-Za-z0-9._-]{1,64}`. |
| `from` | yes | A string: the one address the agent sends from, already in canonical form (§6.4). |
| `cnf` | yes | An object: `{"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "<base64url public key>"}}`, where `x` decodes to 32 octets. This is the agent key, as a proof-of-possession key (RFC 7800). |
| `principal` | yes | An object: the disclosure (§5.3). |
| `scope` | no | A string: a statement of the agent's authority, in plain words (§5.4). |
| `iat` | yes | An integer: the time the credential was issued. |
| `exp` | yes | An integer: the time it expires. `exp - iat` MUST be more than 0 and at most 86,400 (24 hours). |

Each claim MUST have the JSON type its row gives, and match its grammar where one is given. Otherwise the credential is invalid (§7.2 step 13). A string is never read as a number, nor a number as a string.

**JSON rules.** The payload, and the protected headers of both JWS in a message, MUST be I-JSON (RFC 7493), with these rules made exact:
- member names are unique;
- every number is an integer between -(2^53 - 1) and 2^53 - 1, written without a fraction or an exponent. `1.0`, `1e3`, `NaN` and `Infinity` are not allowed.

JSON that breaks these rules makes the message malformed (§7.2 step 7).

The payload SHOULD be serialized with JCS. A verifier does not depend on this: it checks the signature over the bytes as sent.

The whole credential in compact form MUST be at most 2,048 octets, and the whole header value at most 2,560 (§6.2). Each field cap in this section is a maximum on its own. Not every field can be at its cap at once: a credential with every field at its maximum, made of characters that JSON escapes, comes to about 2,600 octets. The total caps bind, and the issuer MUST keep within them. The credential in Appendix A is 590 octets.

A verifier MUST ignore claims it does not know. Claim names without a colon (`:`) are reserved for this specification. An extension claim name MUST contain a colon, for example `example.com:tier` (§11).

### 5.2 One credential per address

A credential names exactly one address. Each address has its own credential, agent ID and agent key, in every disclosure mode. To a receiver, an agent is an address.

The issuer:
- MUST NOT give two addresses the same `sub` or the same agent key;
- SHOULD keep an address's `sub` stable across reissues, so a counterparty sees the same agent each time;
- SHOULD replace the agent key regularly, for example every 30 days, and at once when it may have been compromised. A new key under the same `sub` is the same agent to a counterparty. Regular replacement bounds how long an unnoticed theft lasts (§9). This is guidance: verifiers check nothing about a key's age;
- decides how it groups addresses that belong to one agent. That grouping is outside the protocol.

### 5.3 Principal disclosure

`principal` is one of three objects. No other members are allowed in them.

| Mode | Object | What the receiver learns |
| --- | --- | --- |
| withheld | `{"mode": "withheld"}` | The issuer says it knows the principal. Nothing more. **This is the default.** |
| pseudonymous | `{"mode": "pseudonymous", "id": "<id>"}` | A pseudonym for the principal that only this counterparty sees. Grammar: `[A-Za-z0-9._-]{1,64}`. |
| named | `{"mode": "named", "name": "<name>"}` | The principal's name or address, as the issuer attests it. 1 to 128 UTF-8 octets, without the characters §5.4 forbids. |

Rules for issuers:
- **No credential without a principal.** An issuer MUST NOT issue a credential it cannot trace to the principal whose authority it carries. Withheld mode hides that link from the receiver. The link must still exist.
- **The principal chooses.** Anything above withheld is the principal's choice.
- **Pseudonyms are pairwise.** In pseudonymous mode, the agent writes to each counterparty from its own address, so it has its own credential, agent ID, agent key and `id` for each (§5.2). The issuer MUST NOT reuse an `id` across counterparties. What counts as one counterparty is the issuer's choice.
- **Only the issuer raises disclosure.** Disclosure is set by the credential. A sender cannot raise it per message.

Email's own headers limit what a mode can hide. A `From` address that names the principal names them whatever the credential says. Anonymity needs an alias address.

A disclosed principal is only as reliable as the issuer that attests it.

### 5.4 Scope

`scope` is an optional statement, in plain words, of what the agent may do. For example: "Books restaurant tables for one person, up to $500 per booking."

- 1 to 280 UTF-8 octets.
- None of these characters: the controls U+0000 to U+001F and U+007F to U+009F, and the bidirectional controls U+061C, U+200E, U+200F, U+202A to U+202E and U+2066 to U+2069. They can make text display in an order other than the one signed. Other format characters, such as U+200D ZERO WIDTH JOINER, are allowed: emoji need them.
- It is part of the credential, so the domain signs it and the agent cannot change it per message.
- A change takes effect only as credentials are replaced. Messages under an earlier credential still verify, with the earlier scope, until that credential lapses: up to 26 hours.

Colophon never decides whether a message fits its scope. A receiver shows the scope and applies its own policy.

### 5.5 Issuing

- An issuer SHOULD issue credentials that last about 24 hours, and reissue them before they expire.
- An issuer MUST certify only an agent key it has proof of possession for, or one it holds itself.
- Before revealing a withheld principal, to whom and when, an issuer follows law and its own terms. That is outside the protocol.

## 6. The signed message

### 6.1 Message layout

A signed message MUST have one of two layouts.

1. The whole message is one `text/plain` part, not marked `Content-Disposition: attachment`.
2. The top level is `multipart/mixed`, and:
   - its first child is `text/plain` and is not marked `Content-Disposition: attachment`. This is the body.
   - every other child is a single part, neither `multipart/*` nor `message/*`, with `Content-Disposition: attachment`. These are the attachments.

Nothing else is allowed. In particular, a signed message has no `text/html` alternative and no nested multiparts. HTML is what a person would see in place of the signed text, and it is what gateways rewrite most.

Media types, subtypes, parameter names, the `Content-Disposition` value and transfer encodings are compared case-insensitively. So are the `charset` and `format` values. A missing `Content-Type` means `text/plain` (RFC 2045 §5.2).

The body part:
- MUST use charset `utf-8` or `us-ascii`, by exactly those names. A missing charset means `us-ascii`. Aliases such as `utf8` are not accepted.
- MUST NOT use `format=flowed`. Verifiers do not undo it.

Every part MUST use one of the transfer encodings `7bit`, `8bit`, `binary`, `quoted-printable` or `base64`. A missing `Content-Transfer-Encoding` means `7bit`. For the body, `quoted-printable` or `base64` is RECOMMENDED, because they survive relays that rewrap long lines.

A forwarded email cannot be a `message/*` attachment: libraries serialize those parts differently. In v0 it is quoted in the text, or attached under another type.

In every part, the top level included, `Content-Type`, `Content-Transfer-Encoding` and `Content-Disposition` each appear at most once, and `Content-Type` starts with `type/subtype`. A part that breaks this makes the message malformed.

### 6.2 The `Colophon-Signature` header

A signed message carries exactly one `Colophon-Signature` header field. It is a tag list:

```
Colophon-Signature: v=0; c=<credential>; b=<agent signature>
```

| Tag | Value |
| --- | --- |
| `v` | `0` |
| `c` | the credential, compact JWS (§5) |
| `b` | the agent signature, detached compact JWS (§6.5) |

- The signer MAY fold the header anywhere, including inside values (RFC 5322 §2.2.3).
- Before parsing, a verifier removes all whitespace: SP, HTAB, CR and LF.
- The value is then a list of items separated by `;`. Empty items are ignored. Every other item is `name=value`: the name matches `[a-z][a-z0-9_]*`, and the value may be empty. An item without `=`, a name that does not match (`V`, for example), or a duplicate name makes the header malformed. Unknown tags are ignored.
- With whitespace removed, the value MUST be at most 2,560 octets, and `c` at most 2,048. A larger one is malformed. In practice the value is about 800 octets.
- The issuer's DKIM signature MUST cover `Colophon-Signature`, and SHOULD use relaxed header canonicalization (RFC 6376 §3.4.2) so that refolding in transit does not break DKIM. Verifiers do not check this.

### 6.3 The signing input

The signing input is this JSON object, serialized with JCS:

| Member | Value |
| --- | --- |
| `v` | `0` (a number) |
| `from` | the canonical `From` address (§6.4). There MUST be exactly one. |
| `to` | the canonical `To` addresses, an array |
| `cc` | the canonical `Cc` addresses, an array |
| `reply_to` | the canonical `Reply-To` addresses, an array |
| `subject` | the canonical subject (§6.4) |
| `text` | base64url of SHA-256 over the canonical text (§6.4), encoded as UTF-8 |
| `attachments` | an array with one entry per attachment, in MIME order: `{"type": ..., "sha256": ...}` |
| `credential` | base64url of SHA-256 over the `c` tag value after whitespace removal (§6.2): the credential in compact form, as ASCII |

An attachment entry is:
- `type`: the media type and subtype, lowercase, without parameters. A missing `Content-Type` means `text/plain`.
- `sha256`: base64url of SHA-256 over the part's body after its transfer encoding is decoded, as §6.4 says for the text. For `7bit`, `8bit` and `binary` these are the body octets as they appear, line endings included. The line ending just before the next boundary belongs to the boundary (RFC 2046 §5.1.1).

Not covered:
- `Message-ID` and `Date`, which some providers replace on sending;
- display names, which servers re-encode;
- attachment file names, which libraries decode differently. A receiver SHOULD NOT present a file name as part of what the agent signed;
- `In-Reply-To` and `References`, which servers rewrite, and which nothing in v0 depends on;
- all other headers.

DKIM still covers whatever the issuer's DKIM signature lists.

![Two columns. On the left, the lines of the worked example message; on the right, what each line becomes in the signing input. From, with display name Booking agent, becomes from: the address only, lowercased. To becomes to: addresses only. Cc and Reply-To, absent here, become cc and reply_to, empty arrays when absent. Subject becomes subject: raw, as on the wire. Message-ID, Date, In-Reply-To and References are not signed. Colophon-Signature gives v and credential, the SHA-256 of c. DKIM-Signature is not in the input: it is proof 1, and it covers Colophon-Signature. In the body, multipart/mixed is one of the two allowed layouts; the text/plain part becomes text, the SHA-256 of the canonical text; the text/csv attachment becomes an attachments entry with its type and SHA-256, and its file name is not signed. Notes: grey text is not signed; a signed message has no text/html part, no nested multipart and no message part; Bcc is not signed either, and a recipient only on the envelope gets not verified, not_addressed.](figures/figure-3-signed-parts.svg)

*Figure 3. What the agent signature covers, shown on the message of Appendix A.*

### 6.4 Canonical forms

**Header fields.** A verifier reads `From`, `To`, `Cc`, `Reply-To`, `Subject` and `Colophon-Signature`. Field names are compared case-insensitively. Each value is unfolded first: every CRLF followed by SP or HTAB is removed. The octets MUST be valid UTF-8 (RFC 6532); otherwise the message is malformed.

**Addresses.** `From`, `To`, `Cc` and `Reply-To` use a strict subset of RFC 5322, so that every verifier reads them alike. A value outside the subset makes the message malformed. Verifiers do not repair it.
1. The value is a list of mailboxes separated by commas. Each mailbox, with SP and HTAB trimmed at both ends, is either an addr-spec alone, or a display name followed by an addr-spec in angle brackets.
2. A display name is made of atext, `.`, SP, HTAB, non-ASCII characters and quoted strings. Anything else in it, an unquoted `@` for example, is malformed.
3. An addr-spec is `local@domain`, with no whitespace:
   - the local part is a dot-atom of atext and non-ASCII characters (RFC 6532). A quoted local part, such as `"john doe"@example.com`, is malformed;
   - the domain is two or more labels separated by `.`. Each label is 1 to 63 ASCII letters, digits and hyphens, and does not start or end with a hyphen. An internationalized domain MUST be written as A-labels (`xn--...`). Verifiers do not convert or check A-labels. A non-ASCII domain, a domain literal such as `[192.0.2.1]`, and a trailing dot are malformed.
4. Outside quoted strings, `(`, `)`, `:`, `;`, `[`, `]` and `\` are malformed, and so is any `<` or `>` beyond one pair per mailbox. This rules out comments, groups (`undisclosed-recipients:;` included), domain literals and route syntax. An empty member, as in `a@x.example, , b@x.example`, is malformed too.
5. Canonical form: lowercase the ASCII letters A to Z in the local part and the domain. Leave all other octets as they are. Apply no Unicode normalization and no other case folding. Two addresses are equal when their canonical forms are equal octet for octet.
6. Keep header order. Drop later duplicates.
7. If the header is absent, the list is `[]`. If it appears more than once, or is empty, the message is malformed.

**Subject.** The subject is signed raw, as it appears on the wire, the way DKIM's relaxed header canonicalization treats it (RFC 6376 §3.4.2):
1. Unfold, as above.
2. Each run of SP and HTAB becomes one SP, and SP is trimmed at both ends.

RFC 2047 encoded words are not decoded: `=?utf-8?q?caf=C3=A9?=` is signed as those 21 characters. The issuer's DKIM signature covers `Subject`, so the verifier sees the octets the signer saw, and no verifier needs a decoder to agree with another. A receiver decodes the subject only to show it (§9).

An absent `Subject` is `""`. More than one `Subject` makes the message malformed.

**Text.**
1. Decode the body part's transfer encoding, strictly. Attachments are decoded the same way.
   - `quoted-printable` follows RFC 2045 §6.7. SP and HTAB at the end of a line are removed. A line that then ends in `=` joins the next. Every other line end decodes to CRLF. An `=` that is not followed by two hex digits is malformed.
   - `base64`: remove SP, HTAB, CR and LF, then decode as RFC 4648 §4, padding required. Any other character, or wrong padding, is malformed. Unused bits are ignored.
   - `7bit`, `8bit` and `binary` are taken as they are.
2. Decode the charset to Unicode. Bytes that are invalid in the charset make the message malformed. A byte order mark is text, and is kept.
3. Split into lines at CRLF, CR or LF.
4. Remove trailing SP and HTAB from each line.
5. Remove empty lines at the end.
6. Join the lines, ending each with CRLF. Empty text is the empty string.
7. Encode as UTF-8. Apply no Unicode normalization.

### 6.5 The agent signature

The agent signature is a JWS with a detached payload (RFC 7515 Appendix F), signed with the agent key, `EdDSA`. The payload is the JCS signing input. It is not sent: the verifier rebuilds it from the message.

It travels as `<protected header>..<signature>`, the compact form with the payload left out.

**Protected header**

| Member | Value |
| --- | --- |
| `alg` | `EdDSA` |
| `typ` | `colophon-sig` |
| `iat` | when the signer signed, an integer |
| `nonce` | a random value, at least 96 bits, in base64url. Grammar: `[A-Za-z0-9_-]{16,64}`. |

A verifier MUST reject `crit`, and ignores other members.

The signature is computed as in RFC 7515: Ed25519 over `ASCII(BASE64URL(header) || "." || BASE64URL(JCS(signing input)))`.

### 6.6 Signing

The signer:
1. builds the message in its final form, as it will leave the issuer's mail system. Footers, banners and subject tags are added first, and the subject is encoded as it will be sent.
2. picks the credential for the `From` address. It SHOULD NOT sign with a credential that has less than 6 hours left before `exp`, so the message has time to arrive. Verifiers do not check this.
3. builds the signing input from those bytes, signs it, and adds `Colophon-Signature`.
4. hands the message to the mail system, which adds DKIM with `d=` equal to the `From` host.

Anything that changes a covered part after signing makes the message not verified. A relay that appends a footer is the most common case.

## 7. Verifying

### 7.1 Inputs

A verifier works on four inputs from the receiving system, never from the message:

1. **The message as accepted.** These are the bytes the receiver's mail server accepted, before anything at the receiver changes them, such as banners, subject tags or rewritten links.
2. **The arrival time.** This is when the receiver's mail server accepted the message in SMTP. A verifier MUST use it, not the time it happens to run. A queued, delayed or reprocessed message keeps its arrival time.
3. **The DKIM results.** These come from the receiver's own checks, in one of two ways:
   - the verifier checks the message's DKIM signatures itself (RFC 6376);
   - the verifier reads an `Authentication-Results` field (RFC 8601) added by the receiver's own boundary mail server, identified by its authserv-id. It MUST ignore any such field that came with the message.
4. **The mailbox.** This is the mailbox this copy was delivered to: a stable identifier the receiver chooses, and every address the mailbox receives at, its own and its aliases. The receiver maps the envelope recipient (RCPT TO) to the mailbox. Two envelope recipients that reach one mailbox, such as an address and its `+tag` form, are one mailbox.

A verifier SHOULD verify soon after arrival. The domain key in DNS may change later.

### 7.2 Steps

A verifier runs these steps in order. The first step that fails gives the verdict **not verified**, with the reason shown.

![A column of seven stages between the message, as this receiver's server accepted it, and the verdict verified. Steps 1 to 3, structure: one Colophon-Signature header, one From address. Step 4, aligned DKIM: a DKIM pass for the From host, before any DNS lookup. Steps 5 to 8, parse: the header and the credential; iss is the From host. Steps 9 to 11, the one DNS lookup: the domain key at kid._colophon.From host. Steps 12 to 15, credential: its signature, claims and time window; from is From. Steps 16 to 19, message: layout, signing input, agent signature. Steps 20 and 21, this mailbox: listed in To or Cc; not verified here before. Every stage has a dashed line marked fails to one verdict: not verified, with the reason of the first failing step.](figures/figure-4-verifier-stages.svg)

*Figure 4. The steps below, in stages.*

| # | Check | Reason if it fails |
| --- | --- | --- |
| 1 | The message has a `Colophon-Signature` header. | `no_signature` |
| 2 | It has exactly one. | `multiple_signatures` |
| 3 | `From` has exactly one address. Let H be its host. | `malformed` |
| 4 | At least one DKIM signature passed with `d=` equal to H (compared case-insensitively). If none did, stop here, before any DNS lookup. | `dkim_unaligned` |
| 5 | With whitespace removed, the header value is at most 2,560 octets, parses as a tag list (§6.2), and has a `v` tag. | `malformed` |
| 6 | `v` is `0`. | `unsupported_version` |
| 7 | It has `c` and `b`, and `c` is at most 2,048 octets. Both parse as compact JWS in strict base64url, `b` with an empty payload. Their protected headers and the claims are JSON objects that follow the JSON rules of §5.1. | `malformed` |
| 8 | The credential header has `alg` `EdDSA`, `typ` `colophon-cred+jwt`, a valid selector in `kid`, and no `crit`. `iss` equals H exactly, octet for octet, so it must be lowercase. | `credential_invalid` |
| 9 | Look up TXT at `<kid>._colophon.H` (§7.4). | `dns_error`, `dns_limited` |
| 10 | The answer holds exactly one Colophon record, and it has `k=ed25519` and a `p` tag (§7.4). | `key_not_found` |
| 11 | `p` is not empty, and is 32 octets in strict base64url (§7.4). | `key_revoked` if empty, otherwise `key_not_found` |
| 12 | The credential's signature verifies with that key. | `credential_invalid` |
| 13 | Every claim has its JSON type and grammar (§5.1 to §5.4): `sub`, `from`, `principal`, `scope`, `cnf`, and `0 < exp - iat <= 86400`. | `credential_invalid` |
| 14 | `iat - 300 <= arrival <= exp + 7200`. | `credential_expired` |
| 15 | `from` equals the canonical `From` address. | `from_mismatch` |
| 16 | The layout is valid (§6.1). Parts are checked from the top. For each part, its `Content-*` fields are checked first: a duplicate field or a `Content-Type` that does not parse is `malformed`. Then its type, charset, `format`, transfer encoding and disposition: a failure there is `layout`. | `layout`, `malformed` |
| 17 | The signing input can be built (§6.3, §6.4). | `malformed` |
| 18 | The signature header has `alg` `EdDSA`, `typ` `colophon-sig`, a `nonce` that matches its grammar, an integer `iat`, and no `crit`. `iat <= min(exp, arrival + 300)`. | `signature_invalid` |
| 19 | The agent signature verifies with the key in `cnf`, over the rebuilt signing input. | `signature_invalid` |
| 20 | `To` or `Cc` lists an address of the mailbox (§7.5). | `not_addressed` |
| 21 | The tuple (mailbox, `iss`, `sub`, `nonce`) has not verified before (§7.6). | `replay` |

If every step passes, the verdict is **verified**.

A verifier does at most one DNS lookup and two Ed25519 verifications per message.

The constants:
- 300 seconds allows for clocks that run fast.
- 7,200 seconds is the arrival grace: time in transit after a credential expires.

### 7.3 Verdicts

There are two verdicts.

- **Verified.** The verifier reports the agent:
  - `iss`, the issuing domain;
  - `from`, the address;
  - `sub`, the agent ID;
  - `principal`;
  - `scope`.
- **Not verified**, with one reason from §7.2. A message that is not verified is plain email: the receiver handles it as it would without Colophon.

The reason is for diagnosis. A receiver SHOULD NOT tell the user a different story for each reason. A changed text and a forgery both fail as `signature_invalid`.

A verdict never blocks delivery by itself. Receivers may still apply their own policies.

### 7.4 DNS lookups

- A verifier MUST look up a key only for the domain that passed aligned DKIM (step 4). This keeps unauthenticated mail from making the verifier query any domain it names.
- A verifier MUST NOT make the lookup while the SMTP session is open.
- A lookup has 2 seconds, wall clock, retries included. A timeout or a server failure is `dns_error`.
- Answers are cached for their TTL. A name with no usable record is cached for at least 5 minutes.
- A verifier MUST limit misses: lookups that find no usable record. After 20 misses for one domain in an hour (RECOMMENDED), it refuses uncached lookups for that domain until the hour is over. A refused lookup is `dns_limited`. Lookups that find a key do not count. Any sender at a shared domain can still spend the budget with made-up selectors, so `dns_limited` is a plain not verified: a receiver MUST NOT treat it as evidence against the sender.
- Like DKIM, a lookup tells the sender's DNS operator that a message arrived. See §10.

**Which record is the key.** The answer to the lookup is a set of TXT records. The verifier:
1. joins each record's character strings, with nothing between them;
2. parses each record as a tag list, as §6.2 does;
3. discards every record that does not parse, has a duplicate tag, or has no `v=COLOPHON0` tag. These are not Colophon records;
4. if no Colophon record remains, or more than one, stops with `key_not_found`. NXDOMAIN and an answer with no TXT records count as none;
5. if the record has no `k=ed25519` tag, or no `p` tag, stops with `key_not_found`;
6. if `p` is empty, stops with `key_revoked`;
7. if `p` is not strict base64url of exactly 32 octets, stops with `key_not_found`.

Otherwise `p` is the domain key.

### 7.5 Addressed to this mailbox

A captured message passes DKIM again if it is resent unchanged to someone else. Step 20 stops that. A message verifies only for a mailbox it was addressed to in `To` or `Cc`.

- The mailbox's addresses are its own addresses and aliases (§7.1).
- A receiver MAY also count addresses it knows forward to the mailbox, for example an old address the user set up to forward.
- A recipient that was only on the envelope, such as a `Bcc` recipient or an unknown forward, gets **not verified** (`not_addressed`). A sender that wants a recipient to verify lists them in `To` or `Cc`.

Signed copies for `Bcc` recipients are a possible extension (§11).

### 7.6 Replays

The verifier remembers each (mailbox, `iss`, `sub`, `nonce`) of a message it verified. It keeps the tuple until the credential's `exp` plus the 2-hour grace. After that, step 14 rejects the message anyway.

- The tuple names the mailbox, not the envelope recipient. A message verifies at most once per mailbox: a copy sent again to the same mailbox, through an alias or a `+tag` address, is a replay. One message delivered to two mailboxes at the same receiver verifies for each.
- The check comes after the signatures, so a forged message cannot fill the store.
- A receiver MAY remove duplicate deliveries, such as SMTP retries, by `Message-ID` before verifying. A second copy that reaches the verifier is not verified (`replay`).

### 7.7 Limits

These values are set for v0. A later version may revise them from real traffic. The 30-day agent-key replacement is an example, not a limit (§5.2).

| Item | Limit |
| --- | --- |
| `Colophon-Signature` value, whitespace removed | 2,560 octets |
| Credential (`c`), whitespace removed | 2,048 octets |
| Credential lifetime (`exp - iat`) | at most 24 hours |
| Credential life left when signing | at least 6 hours (SHOULD; not checked) |
| Arrival grace after `exp` | 2 hours |
| Clock skew | 5 minutes |
| `scope` | 1 to 280 UTF-8 octets |
| Named principal | 1 to 128 UTF-8 octets |
| JSON numbers | integers within ±(2^53 - 1) |
| `sub`, pseudonym `id` | 1 to 64 characters, `[A-Za-z0-9._-]` |
| `nonce` | 16 to 64 base64url characters, at least 96 random bits |
| DNS lookup budget | 2 seconds, wall clock, retries included |
| Negative cache | at least 5 minutes |
| DNS misses per domain | 20 per hour (RECOMMENDED) |
| Work per message | at most 1 DNS lookup and 2 Ed25519 verifications |
| Agent key replaced | every 30 days, for example (SHOULD) |
| Domain key TTL | at most 1 hour (SHOULD) |
| Retired selector kept | at least 7 days after last use (SHOULD) |

## 8. First contact and receiver control

v0 has no special message for an introduction. A stranger agent's first message is a signed message like any other.

- **The receiver decides who gets in.** Holding, admitting, asking a person, and blocking are the receiver's policy. Colophon supplies the evidence, never the admission rule.
- **The evidence.** It is the verdict and, when verified, the agent's domain, address, agent ID, principal as far as disclosed, and scope.
- **Anything offered in support is content.** For example: "Bob at partner.example suggested I write", a forwarded message, or a code the receiver gave out. The receiver, or its agent, judges it like any text.
- **A forwarded Colophon message cannot be verified** by the receiver in v0. The receiver may look up keys only for the domain that passed DKIM on the outer message (§7.4). An introducer who wants to be verified writes to the receiver directly, or copies the stranger in.
- **No automatic replies to agents.** A receiver SHOULD NOT tell a sending agent that its message was held. Silence tells address scrapers nothing, and it avoids backscatter.
- **Agent addresses are worth protecting.** An issuer SHOULD keep agent addresses from becoming widely known, for example with an alias per counterparty, and replace an address that is abused. A counterparty knows the agent by its address, so a replacement starts a new pairing.

## 9. Security considerations

**What "verified" means.** The `From` host's mail system sent the message, and the agent key that domain certified for that address signed its addresses, subject, text and attachments. The credential was valid on arrival. The message was addressed to this mailbox in `To` or `Cc`, and had not verified for this mailbox before.

It does not mean:
- that the agent is honest or competent;
- that the request fits its scope;
- that the principal exists outside the issuer's word.

**Sender text is untrusted.** `scope`, a named principal, `sub`, the subject and the text are all written by the sender's side. A receiver MUST show them as the sender's claims. When it passes them to a language model, it MUST mark them as data, never as instructions.

**Display names are not signed.** `From: "Your Bank" <maple-tiger-27@acme.example>` verifies. Receivers SHOULD show the address and the issuing domain, not the display name, next to a verified verdict.

**The subject is signed as octets.** A receiver decodes encoded words to show the subject, and mail libraries disagree on unusual input: a character split across two encoded words, an unknown charset, invalid octets. The signature binds the octets, not one reading of them. A receiver SHOULD show a subject it cannot decode cleanly in its raw form, not a repaired one. A signer SHOULD send an ASCII subject as plain text and encode a non-ASCII subject as whole `utf-8` encoded words, or as UTF-8 (RFC 6532).

**Lookalike domains.** Colophon proves which domain spoke, not that it is the domain the user expects. A receiver SHOULD make internationalized and lookalike domains visible, for example by showing A-labels or by flagging confusable characters.

**A stolen agent key** can sign only for its one address, and still needs the domain's mail system to pass DKIM. It is not bounded by the credential's 24 hours. Credentials are public: every message the agent sent carries one, so a thief who holds the key can attach any current credential for it. The key stays usable for as long as the issuer certifies it, and for up to 26 hours after the issuer stops. Ending it is the issuer's job: it replaces the agent key (§5.2). Regular replacement bounds how long an unnoticed theft lasts.

**A leaked domain key** lets the attacker mint credentials for any address on the host. To pass step 4, the attacker also needs to send through the domain's DKIM-signing mail system. Removing the key reaches verifiers within the record's TTL.

**A compromised mail system and domain key** together let an attacker send as any agent of that domain. That is the issuer's full compromise. Colophon cannot do better than the issuer it trusts.

**Addresses that differ only in case.** Verifiers lowercase the ASCII letters A to Z in local parts, and compare every other octet as it is, with no Unicode normalization or case folding (§6.4). A mail system may still deliver two such addresses to one place, for example by folding the case of non-ASCII letters. An issuer MUST NOT issue credentials for two addresses that are equal after ASCII lowercasing, or that its mail system treats as one address. Distinct addresses that one mailbox receives at, such as an agent's pairwise addresses (§5.3), are allowed: each has its own credential (§5.2).

**Resending a captured message.** DKIM passes again on an unchanged resend. The addressing check (§7.5) and the replay store (§7.6) stop it from verifying anywhere it was not sent.

**Unsigned headers.** `Sender`, `Resent-*` and every other header §6.3 does not list are not signed by the agent. A receiver MUST NOT present them as part of what the agent signed.

**Relays that change messages.** Mailing lists and gateways that change a covered part or break DKIM make a message not verified. This is deliberate: a verdict that could be true for some receivers and false for others would make implementations disagree. ARC (RFC 8617) is not used in v0.

**Strict alignment.** The DKIM domain must equal the `From` host. Relaxed alignment would need the Public Suffix List, and its versions differ between implementations. A provider that signs subdomain mail with the parent domain must sign Colophon mail with the exact host.

**DKIM strength.** Which DKIM signatures pass, including the minimum key size and the accepted algorithms, is left to the receiver's DKIM verifier, which follows RFC 8301. Colophon adds no rule of its own.

**Denial of service.**
- Key lookups happen only after aligned DKIM passes, have a 2-second budget, and misses are rate-limited.
- A message costs at most one DNS lookup and two Ed25519 verifications.
- Size limits (§7.7) bound parsing. Grammars are strict, and verifiers reject what they cannot read rather than repair it.
- JSON must be I-JSON, which rejects duplicate keys, a common source of parser disagreement.

**Time.** Verification uses arrival time, so a signer cannot backdate. The signature's `iat` is only checked not to be later than the credential's `exp`, or than arrival plus 5 minutes.

**Long-term proof is out of scope.** Colophon verifies a message when it arrives. Proving years later what was said is a records question between one party, its archive, and perhaps a court. An extension may add timestamps or key transparency. A receiver that needs proof later SHOULD keep the DNS record it verified against, next to the message.

## 10. Privacy considerations

**Being an agent is always disclosed.** A signed message says an agent wrote it. Who it acts for is disclosed only as far as the principal chooses (§5.3).

**Unlinkability depends on addresses.** A credential names one address, its own agent ID and its own key (§5.2), so its identifiers do not link two of an agent's addresses. Whether counterparties can link an agent depends on whether its issuer gives each counterparty its own address.

**Credentials can still link.** Credentials minted in one batch carry the same `iat` and `exp`, and the same scope wording can repeat across addresses. Two counterparties who compare notes can link them. An issuer SHOULD spread reissue times across an agent's addresses, and SHOULD keep scope wording generic.

**The domain links.** Every message shows its domain, as DKIM already does. Unlinkability across counterparties holds only when many principals share the domain. On a domain with one owner, the domain names the owner.

**Other things link.** Writing style, timing, scope wording, other headers such as `Received` and `Message-ID` formats, and the content itself. Colophon does not hide them.

**Withheld is not anonymous to the issuer.** The issuer knows the principal (§5.3). When it reveals a withheld principal is a matter of law and its terms.

**No directory.** Nothing in Colophon lists a domain's agents or addresses. Selectors name domain keys, not agents.

**DNS lookups.** The sender's DNS operator can see that a receiver looked up a key, as with DKIM. Caching limits what it learns.

**Other agent headers.** A sender MAY also add the `Agent-of` header (draft-chuang-agent-attribution-header-fields), but only in named mode. In the other modes it would reveal the principal.

## 11. Versioning and extensions

- **Version.** The header's `v=0`, the record's `v=COLOPHON0`, and the signing input's `"v": 0` mark this version. A verifier that does not support a message's version returns `unsupported_version`. A later version may add members to the signing input, which is why the signing input carries `v`.
- **Credential claims.** Extensions add claims whose names contain a colon. The domain signs them. Verifiers ignore claims they do not know.
- **Header tags.** Unknown tags are ignored. A tag is not signed, so it MUST NOT carry anything a receiver relies on.
- **JWS header members.** Unknown members are ignored. `crit` is rejected in v0.
- **Possible extensions**, none defined here:
  - a structured scope vocabulary;
  - a published agent card (A2A);
  - DNS records per agent;
  - ARC for trusted forwarders;
  - a structured `note` part for machine-readable data;
  - timestamps for long-term proof;
  - signed `Bcc` copies. The issuer would send each `Bcc` recipient a separate copy whose signing input names that one address, which no header shows. The address has to be in the signing input, because a tag is not signed. A v0 verifier ignores the new tag, rebuilds the signing input without the address, and fails the copy at step 19 as `signature_invalid`, before the addressing check at step 20. It never verifies such a copy wrongly. The extension stays safe for v0 verifiers; only the reason code differs from `not_addressed`.

## 12. Conformance

There are three roles.

| Role | Must |
| --- | --- |
| Issuer | Publish domain keys (§4), and issue credentials that follow §5, including the issuer rules in §5.2, §5.3 and §5.5. |
| Signer | Sign messages that follow §6. |
| Verifier | Follow §7 exactly, and reach the expected verdict on every published test vector. |

Two verifiers given the same four inputs (§7.1) and the same DNS answers MUST reach the same verdict and the same reason. That is the test of this specification. Where it fails, the specification is wrong and should be fixed.

## 13. Registrations

None has been requested yet. Two will be filed when v0 is final:

- **Underscored DNS name:** `_colophon`, for TXT, in the Underscored and Globally Scoped DNS Node Names registry (RFC 8552).
- **Header field:** `Colophon-Signature`, in the Permanent Message Header Field Names registry (RFC 3864), as provisional.

No other registration is sought:
- **JWS `typ` values.** Verifiers match `colophon-cred+jwt` and `colophon-sig` exactly. RFC 7515 §4.1.9 leaves the processing of `typ` to the application, and v0 accepts no other spelling. They are not registered as media types: names in the standards tree need an IETF or other standards-body publication.
- **Claims.** `from`, `principal` and `scope` are defined only for credentials of type `colophon-cred+jwt`.

## 14. Relation to A2A and Colophon Tasks

**A2A.** Colophon is independent of A2A (the Agent2Agent protocol).
- An agent that also speaks A2A may publish an Agent Card. A credential can point to it with an extension claim, whose name contains a colon, for example `a2a:card` (§5.1, §11).
- A bridge, if one is written, will be a separate informative document, after Colophon Tasks.
- Both use JOSE, so keys and signatures move between them without conversion.
- Mapping A2A task states onto email belongs to Colophon Tasks.

**Colophon Tasks.** A later document adds tasks on top of v0:
- a signed, machine-readable task part;
- requests, offers, acceptance and confirmation;
- the rules that decide when an agreement exists over slow, lossy email.

It reuses v0's credential and signature unchanged, and adds the task part to the signing input under a new version.

## 15. Open issues

Issue 1 is the one blocker for v0 final. The others do not block it.

1. **Will the header survive?** Header carriage (§6.2) is the default. Whether a folded header of 800 to 2,560 octets reaches common mail systems intact is untested. Verifiers remove whitespace, so refolding is safe for Colophon; DKIM with simple header canonicalization is not, which is why §6.2 asks for relaxed. The test:
   - **Sender.** A domain whose mail Amazon SES signs with DKIM.
   - **Messages.** Three, signed as §6.6 says: a minimal one, with a header of about 800 octets; one at the 2,560-octet header cap, with a 280-octet scope and a 128-octet named principal; and one with two attachments.
   - **Receivers.** Gmail, Microsoft 365, Outlook.com, iCloud, Fastmail, Yahoo, Proton, Zoho, and Amazon SES inbound.
   - **Forwarding.** One copy also goes through a Gmail automatic forward, and one through Cloudflare Email Routing. These are recorded; the pass rule below is for direct receivers.
   - **Capture.** The raw message as delivered, pulled over IMAP or Microsoft Graph, with the receiver's `Authentication-Results`.
   - **Check.** The reference sketch verifies each capture, with the DKIM results taken from the receiver's `Authentication-Results`.
   - **Pass.** At every direct receiver, the header arrives intact after whitespace removal, DKIM passes aligned, and the verdict is verified.
   - **Fail.** If the header does not survive at Gmail, Microsoft 365 or Outlook.com, iCloud, or Fastmail, v0-05 specifies the fallback: the credential and signature in an `application/colophon-sig` MIME part.
2. **Real mail in the vectors.** The captures from issue 1 are checked in beside `reference/vectors.json`, each with the receiver's `Authentication-Results`, as a corpus of real mail.
3. **The formal model** (Appendix C) is planned. v0 can be final without it. Colophon Tasks waits for it.
4. **Name.** "Colophon" is final for this text, but its trademark clearance is pending. A conflict would force a new version with new wire names. Production deployment waits for the clearance.

## Appendix A. Worked example

The reference sketch in `reference/colophon_v0.py` produces this example. Run `uv run --with cryptography python reference/colophon_v0.py --example` to reproduce it byte for byte. The keys are test keys derived from fixed strings. Never use them for anything else.

**DNS**

```
s1._colophon.acme.example. TXT "v=COLOPHON0; k=ed25519; p=fKF-JHnT8l0RiMibgA4oUYQKwUzyDxroUgxaRM6i6lI"
```

**Credential: protected header and claims**

```json
{"alg":"EdDSA","kid":"s1","typ":"colophon-cred+jwt"}
```

```json
{
  "cnf": {"jwk": {"crv": "Ed25519", "kty": "OKP", "x": "lC9PrkLW2QmPaKqAeeCY94OM3M75MeD9Uyg6oThgOLE"}},
  "exp": 1793952000,
  "from": "maple-tiger-27@acme.example",
  "iat": 1793865600,
  "iss": "acme.example",
  "principal": {"id": "p_Xk29", "mode": "pseudonymous"},
  "scope": "Books restaurant tables for one person, up to $500 per booking.",
  "sub": "ag_7Hq2"
}
```

**Signing input, JCS.** Shown here on several lines. It is one line when signed.

```
{"attachments":[{"sha256":"toHbGVby3dGckYAJkxBXPj9DGUnSCDiuIVwGV4oFR7w","type":"text/csv"}],
"cc":[],"credential":"QyKlpHCC1M-TdbviC2iuOUhIpLY1HxufeJRGlEgEYSo",
"from":"maple-tiger-27@acme.example","reply_to":[],"subject":"Table for 2, Friday 7 November, 19:30",
"text":"JO-XRoNsBAPLwS_XAckdl7Jmo2DmjMagPnYpKzTgLkA","to":["reservations@bistro.example"],"v":0}
```

Note that `From` is written `Maple-Tiger-27@acme.example` in the message and canonicalized to lowercase.

**Message as sent, before the issuer's DKIM signature.** Line endings are CRLF on the wire.

```
Colophon-Signature: v=0;
 c=eyJhbGciOiJFZERTQSIsImtpZCI6InMxIiwidHlwIjoiY29sb3Bob24tY3JlZCtqd3QifQ.eyJj
 bmYiOnsiandrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoibEM5UHJrTFcyUW1QY
 UtxQWVlQ1k5NE9NM003NU1lRDlVeWc2b1RoZ09MRSJ9fSwiZXhwIjoxNzkzOTUyMDAwLCJmcm9tIj
 oibWFwbGUtdGlnZXItMjdAYWNtZS5leGFtcGxlIiwiaWF0IjoxNzkzODY1NjAwLCJpc3MiOiJhY21
 lLmV4YW1wbGUiLCJwcmluY2lwYWwiOnsiaWQiOiJwX1hrMjkiLCJtb2RlIjoicHNldWRvbnltb3Vz
 In0sInNjb3BlIjoiQm9va3MgcmVzdGF1cmFudCB0YWJsZXMgZm9yIG9uZSBwZXJzb24sIHVwIHRvI
 CQ1MDAgcGVyIGJvb2tpbmcuIiwic3ViIjoiYWdfN0hxMiJ9.RXZMLCGGSf1h2H2vm6R62FUeHwEpB
 ltl4vqouA43gL24o5cCzUMx8tskVEgDWEOKcBRYHw8q4PuxNfqmGDNNAw;
 b=eyJhbGciOiJFZERTQSIsImlhdCI6MTc5Mzg3MDEwMCwibm9uY2UiOiJabTl5TFdWNFlXMXdiR1V
 0YjI1c2VRIiwidHlwIjoiY29sb3Bob24tc2lnIn0..lmIvRov2v6U3-dRU-n08mC-Rh4s6lYP36XV
 3ve-OrsEkyXmHCjEIc2jLIgmzncjqL9KBWiF0Qqks4scg9ZS8Aw
From: Booking agent <Maple-Tiger-27@acme.example>
To: Reservations <reservations@bistro.example>
Subject: Table for 2, Friday 7 November, 19:30
Message-ID: <example-1@acme.example>
Date: Thu, 05 Nov 2026 09:15:00 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="=_colophon_example_1"

--=_colophon_example_1
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

Hello,

Could you hold a table for 2 this Friday, 7 November, at 19:30?
One guest is vegetarian.

Thank you

--=_colophon_example_1
Content-Type: text/csv
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="booking.csv"
MIME-Version: 1.0

ZGF0ZSx0aW1lLHBhcnR5CjIwMjYtMTEtMDcsMTk6MzAsMgo=

--=_colophon_example_1--
```

**Verifier inputs**

| Input | Value |
| --- | --- |
| Arrival time | 1793870110 (2026-11-05T09:15:10Z) |
| DKIM | pass, `d=acme.example` |
| Envelope recipient | `reservations@bistro.example` |
| Mailbox | `mbx-reservations`, which receives at `reservations@bistro.example` and `reservations+web@bistro.example` |
| DNS | the record above, at `s1._colophon.acme.example` |

**Verdict:** verified. The agent:
- `iss`: `acme.example`
- `from`: `maple-tiger-27@acme.example`
- `sub`: `ag_7Hq2`
- `principal`: pseudonymous, `p_Xk29`
- the scope above.

## Appendix B. Test vectors

`reference/colophon_v0.py` runs each vector against the example in Appendix A. Run it without arguments: it prints one line per delivery and exits non-zero if any fails. Run it with `--json` to write the vectors as `reference/vectors.json`: each message as base64 of its octets, then one or more deliveries, each with the receiver's inputs and the expected result.

A vector's deliveries run in order and share one replay store. Unless a row says otherwise, each delivery has the inputs of Appendix A.

| Change to the message or inputs | Expected |
| --- | --- |
| None | verified |
| ... delivered again to the same mailbox | `replay` |
| ... delivered again, to the alias `reservations+web@bistro.example` | `replay` |
| ... delivered to a second mailbox, `mbx-tables`, which also receives at `reservations@bistro.example` | verified |
| Colophon-Signature refolded in transit | verified |
| Display name changed | verified |
| Trailing spaces on a body line | verified |
| Charset name in capitals | verified |
| Attachment renamed (names are not signed) | verified |
| Subject refolded in transit | verified |
| Spaces in the subject collapsed | verified |
| Encoded words that decoders disagree on, signed as sent (never decoded) | verified |
| Non-ASCII subject, as the signer encoded it | verified |
| Unrelated TXT beside the record | verified |
| A Colophon record with a duplicate tag beside the record | verified |
| Arrived exactly at exp + grace | verified |
| Signed 1 hour before the credential's iat | verified |
| Subject changed | `signature_invalid` |
| Subject re-encoded as an encoded word after signing | `signature_invalid` |
| Text changed | `signature_invalid` |
| Reply-To added | `signature_invalid` |
| Cc added | `signature_invalid` |
| Attachment changed | `signature_invalid` |
| Body starts with a BOM (a BOM is content) | `signature_invalid` |
| HTML part added | `layout` |
| Body in ISO-8859-1 | `layout` |
| Charset alias utf8 | `layout` |
| Body marked format=flowed | `layout` |
| Unknown transfer encoding | `layout` |
| Message/rfc822 attachment | `layout` |
| Second To field | `malformed` |
| Second Subject field | `malformed` |
| Second Content-Type in the body part | `malformed` |
| Quoted local part in Cc | `malformed` |
| Quoted local part in From | `malformed` |
| Group in To | `malformed` |
| Domain literal in Cc | `malformed` |
| Non-ASCII domain in Cc | `malformed` |
| Comment in To | `malformed` |
| Unquoted @ in a display name | `malformed` |
| Empty member in To | `malformed` |
| Invalid UTF-8 in the subject | `malformed` |
| Bad quoted-printable in the body | `malformed` |
| Bad base64 in the attachment | `malformed` |
| Missing v tag | `malformed` |
| Tag name in capitals | `malformed` |
| Padded base64url in c | `malformed` |
| A fraction in exp | `malformed` |
| A duplicate claim | `malformed` |
| Credential over 2,048 octets | `malformed` |
| Second Colophon-Signature | `multiple_signatures` |
| No Colophon-Signature | `no_signature` |
| DKIM passes only for mail.acme.example | `dkim_unaligned` |
| DKIM passes for mail.acme.example and acme.example | verified |
| DKIM passes for two unaligned domains | `dkim_unaligned` |
| DKIM passes for ACME.EXAMPLE | verified |
| V=1 | `unsupported_version` |
| DNS lookup failed | `dns_error` |
| No record at the selector | `key_not_found` |
| Two Colophon records | `key_not_found` |
| A k=rsa Colophon record beside the record | `key_not_found` |
| Record without p | `key_not_found` |
| Key of the wrong length | `key_not_found` |
| Key in padded base64 | `key_not_found` |
| Record with empty p= | `key_revoked` |
| Record holds a different key | `credential_invalid` |
| Iss in capitals | `credential_invalid` |
| Sub with a trailing newline | `credential_invalid` |
| Sub as a number | `credential_invalid` |
| No from claim | `credential_invalid` |
| From claim not in canonical form | `credential_invalid` |
| Lifetime of 25 hours | `credential_invalid` |
| Bidi control in scope | `credential_invalid` |
| Agent key of 31 octets | `credential_invalid` |
| Arrived 1 second after exp + grace | `credential_expired` |
| From is another address on the same host | `from_mismatch` |
| SMTPUTF8 local part, ASCII letters lowercased (`José@acme.example`, credential `josé@acme.example`) | verified |
| SMTPUTF8 local part with non-ASCII in another case (`JOSÉ@acme.example`, same credential) | `from_mismatch` |
| Signature iat 10 minutes after arrival | `signature_invalid` |
| Delivered to a mailbox not in To or Cc (Bcc) | `not_addressed` |

Some of these changes would also break DKIM in real mail. The vectors test the Colophon checks alone, with the DKIM result given as an input.

The sketch does not check DKIM or query DNS: both are inputs. It handles every address form v0 allows: dot-atom local parts, non-ASCII ones included, and ASCII domains.

## Appendix C. Formal model

A formal model of v0 is planned, in Tamarin. v0 can be final without it. Colophon Tasks waits for it.

- **What it covers.** Steps 4, 12 to 15 and 19 to 21 of §7.2: aligned DKIM, the credential's signature, claims, time and address, the agent signature, the addressing check and the replay check. It assumes perfect cryptography, and an attacker who controls the network, plays one side, or holds a stolen agent key.
- **What it proves.** Two lemmas:
  1. a verified message traces to a credential the domain issued for a delegating principal, and was sent through the domain's DKIM-signing mail system;
  2. a captured message cannot verify for a mailbox it was not addressed to, and verifies at most once per mailbox.
- **Mutants.** Two altered models must yield attack traces: one without step 20, and one without step 4. This shows the lemmas depend on those steps.
- **Where it runs.** In the repository's CI, on every change.

A verifier's bounded work per message is not a model property. §9 states it.

## Appendix D. Decision log

The design was settled one question at a time. Each decision has a longer record, with the options that were rejected.

| Decision | Choice |
| --- | --- |
| Where agent identity lives | A domain key in DNS under a selector, and a short-lived credential in each message. A published card is optional. |
| How a message binds to the agent | An Ed25519 JWS by the agent key over a JCS signing input, on top of DKIM. Plain text only. |
| Principal disclosure | Withheld by default, pseudonymous or named by the principal's choice. |
| No credential without a principal | The issuer must be able to trace every credential to a delegating principal. |
| Long-term proof | Not part of the protocol. |
| Messages with no request | Any agent email may be signed, and v0 has no acts at all. |
| Credentials checked on arrival | The credential must be valid when the receiver's server accepts the message. The signing time is advisory. |
| v0 is the identity layer | Tasks and agreements move to Colophon Tasks. |
| Scope | A plain-words statement, signed by the domain. Software never enforces it. |
| Both proofs required | Aligned DKIM, checked by the receiver's own mail system, plus the agent signature. Without DKIM, no key lookup. |
| A credential belongs to a mailbox | The credential names its address. DKIM alignment is strict. |
| Where the signature travels | A header, with a size cap. Bare addresses are signed, not raw headers. |
| Pseudonymous mode | A pairwise address, credential, agent ID and key per counterparty. |
| First contact | No introduction act. A first contact is a signed message, and support for it is content. |
| Verdicts | Two: verified, or not verified with a reason. The message is checked as the receiver accepted it, and the payload is rebuilt, not sent. |
| One credential per address | A single `from` address with its own agent ID and key, in every mode. |
| Agent key replacement | Guidance only: SHOULD replace regularly, every 30 days for example, and at once on suspected compromise. No key-age claim, and verifiers do not check it. |
| Addressing check | A message verifies only for a mailbox in `To` or `Cc`. `Bcc` copies and unknown forwards are not verified. Signed `Bcc` copies may come later as an extension. |
| Subject and Reply-To | Both signed. The subject is signed raw, not decoded. |
| Limits | Fixed for v0; v1 may revise them from traffic. |
| Tag letters | `c` for the credential and `b` for the agent signature. |
| Encoding | base64url everywhere, the DNS record included, decoded strictly. |
| JWS form | A standard detached JWS, not RFC 7797 unencoded payloads: RFC 7797 needs `crit`, which v0 rejects. |
| Message expiry | None. The credential's `exp` and the arrival time bound a message. |
| Non-ASCII local parts | ASCII letters lowercased, other octets compared as they are, no Unicode normalization or folding. |
| Registrations | `_colophon` (RFC 8552) and a provisional `Colophon-Signature` (RFC 3864), filed at v0 final. No media types. |
| Formal model | Tamarin, planned. Not required for v0 final; required before Colophon Tasks. |
| Licence | Apache 2.0 for spec and code. The founder is editor until a second independent implementation exists. Changes go through public review. |
| Relation to A2A | Independent, with a defined bridge. |

## Appendix E. Changes

### v0-04

- **Open issues.** The numbers, local parts, wire choices and the formal model are settled, and §15 is rewritten. Header survival is the one blocker for v0 final, with a test plan (§15, issue 1). The name is final for this text, pending clearance.
- **Limits.** The values in §7.7 are set for v0.
- **Wire choices.** The tag letters, base64url, the standard detached JWS and the absence of a message-level `exp` are fixed (Appendix D).
- **Local parts.** Non-ASCII octets compare as they are, with no normalization or folding (§6.4). An issuer must not issue credentials for two addresses its mail system treats as one (§9).
- **Clarifications.** `iss` is compared exactly and is lowercase (§5.1, §7.2 step 8). DKIM strength is left to the receiver's DKIM verifier (§9). No change on the wire.
- **Registrations.** Two, filed at v0 final; no media types (§13).
- **A2A.** The hook is an extension claim such as `a2a:card` (§14).
- **Formal model.** Planned in Tamarin, with two lemmas and two mutants (Appendix C).
- **Vectors.** Three for multiple DKIM signatures, two for SMTPUTF8 local parts, and one for `iss` in capitals: 80 deliveries.
- **Figures.** Four informative figures: the two proofs and a credential's times (§3), what the signature covers (§6.3), and the verifier's stages (§7.2). Figure 1 replaces the text diagram in §3. No rule changed.

### v0-03

- **Name.** The protocol was formerly named CREST. It is renamed Colophon before publication, because another organization uses CREST in the security field. No rule changed. The wire names are now:
  - the header `Colophon-Signature`, formerly `Crest-Signature`;
  - the DNS label `_colophon`, formerly `_crest`;
  - the record tag `v=COLOPHON0`, formerly `v=CREST0`;
  - the token types `colophon-sig` and `colophon-cred+jwt`, formerly `crest-sig` and `crest-cred+jwt`.
- **Tasks document.** The later tasks document is named Colophon Tasks (§14).
- **Reference files.** The sketch is `reference/colophon_v0.py`. Its test keys are derived from new fixed strings.
- **Vectors.** Regenerated, since the token types are signed, and the example in Appendix A with them: still 74 deliveries. Earlier signatures do not verify under v0-03.

### v0-02

- **Subject.** The subject is signed raw: unfolded, whitespace collapsed, trimmed, with encoded words left as they are (§6.4). Verifiers no longer need an RFC 2047 decoder. A subject re-encoded after signing no longer verifies; a relay that does this breaks DKIM as well. Receivers decode only for display (§9).
- **Addressing check.** Kept as v0-01 proposed: a message verifies only for a mailbox listed in `To` or `Cc`, and `Bcc` copies and unknown forwards are not verified (§7.5). Signed `Bcc` copies are listed as a possible extension (§11).
- **Agent key replacement.** Stays guidance (SHOULD), with 30 days as an example. Verifiers check nothing about key age (§5.2).
- **Open issues.** §15 issues 1 (addressing check) and 4 (subject) are closed, and the others are renumbered.
- **Vectors.** Five subject vectors replaced: still 74 deliveries.

### v0-01, from v0-00

v0-01 applies the first round of review. The design is unchanged; the changes close places where implementations would disagree, and correct claims the mechanism did not support.

- **Mailbox, not envelope recipient.** The verifier's fourth input is the mailbox. The replay tuple uses it, so a copy resent through an alias is a replay (§7.1, §7.6).
- **Stolen agent keys.** A stolen key is usable while the issuer certifies it, not for at most 24 hours. Issuers SHOULD replace agent keys regularly (§3, §5.2, §9).
- **DNS.** One algorithm picks the key record (§7.4). The rate limit counts misses only, at 20 per domain per hour, and `dns_limited` is never a signal against the sender.
- **Strict parsing.** Grammars match whole values (§2). Claims have exact JSON types, and JSON numbers are integers (§5.1). base64url is strict everywhere. Tag names are lowercase. A missing `v` is malformed (§6.2, §7.2).
- **Addresses.** A strict subset of RFC 5322: no groups, comments, domain literals or quoted local parts. Domains are ASCII, with A-labels for IDNs (§6.4).
- **Subject.** Strict RFC 2047 decoding, word by word, `utf-8` and `us-ascii` only. Signing the raw subject instead is open (§15, issue 4).
- **MIME.** Tokens compare case-insensitively. Fixed charset names, five transfer encodings, no `format=flowed`, no `message/*` attachments, and no duplicate `Content-*` fields (§6.1). Strict quoted-printable and base64 (§6.4).
- **Signing input.** Attachment file names are no longer signed (§6.3).
- **Sizes.** Credential 2,048 octets and header 2,560, with the total caps binding (§5.1, §6.2).
- **Text in claims.** Scope and named principals also forbid bidirectional controls (§5.4).
- **Time.** The lower bound on the signature `iat` is gone, and the 6-hour rule is a SHOULD (§6.6, §7.2).
- **DKIM.** The issuer's DKIM signature MUST cover `Colophon-Signature`, with relaxed header canonicalization RECOMMENDED (§6.2).
- **Privacy.** Batch reissue times and repeated scope wording can link addresses (§10).
- **Vectors.** 74 deliveries in Appendix B, and a machine-readable `reference/vectors.json`.
