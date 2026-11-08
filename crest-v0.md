# CREST v0: Agent Signatures for Email

Draft v0-00, 2026-11-08. For review. Not for production use.
Editor: Jorge Vivas (Fluxtopus).
Licence: Apache 2.0.

## Abstract

CREST lets an AI agent sign the email it sends.

A receiver can then check three things from DNS and the message alone:
- which agent wrote the message;
- which domain issued that agent and stands behind it;
- what the domain says the agent acts for: its principal, as far as the principal allows, and a short statement of its authority.

CREST adds one header to an ordinary email. A receiver that does not know CREST sees a normal message.

v0 is the identity layer only. Tasks, offers and agreements come later, in a separate document, CREST Tasks, built on this one.

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
14. Relation to A2A and CREST Tasks
15. Open issues

Appendices:
- A. Worked example
- B. Test vectors
- C. Formal model
- D. Decision log

## 1. Introduction

Agents already send email: they book, buy, schedule, follow up and hand work to one another. A receiver cannot tell an agent's message from a person's. If it is an agent's, the receiver cannot tell whose agent it is or what it may do.

DKIM proves that a domain's mail system sent a message. It does not say which agent of that domain wrote it, who that agent acts for, or what it is allowed to do.

CREST adds that. It is built on what email already has:
- DKIM, for the domain;
- DNS, for keys;
- MIME, for the message;
- JOSE (JWS, JWK, EdDSA) and JCS, for signatures.

It needs no central registry, no HTTPS fetch, and no service run by any one company.

### 1.1 Principles

1. **Plain email first.** A signed message is a valid, readable email. A receiver that ignores CREST loses nothing.
2. **Verifiable by anyone.** Any implementation checks a message from DNS and the message itself.
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

Values written in `code` are exact. "base64url" is the URL-safe alphabet without padding (RFC 4648 §5). "JCS" is the JSON Canonicalization Scheme (RFC 8785). Times are integer seconds since the Unix epoch, UTC.

## 3. Overview

A CREST message carries two proofs. A receiver believes "agent X of acme.example" only when both hold.

1. **The domain's mail system sent it.** The message passes DKIM, and the DKIM signing domain is exactly the `From` host.
2. **This agent wrote it.** The message carries a credential and an agent signature in one header, `Crest-Signature`:
   - the credential is signed by a domain key that the `From` host publishes in DNS;
   - the agent signature, made with the key the credential names, covers the message's addresses, subject, text and attachments.

```
DNS:   s1._crest.acme.example  TXT  "v=CREST0; k=ed25519; p=<domain public key>"
                                               |
                                               | signs (at most 24 h)
                                               v
Credential:  iss=acme.example, from=maple-tiger-27@acme.example,
             agent key, principal, scope, iat, exp
                                               |
                                               | names the key that signs
                                               v
Agent signature:  over From, To, Cc, Reply-To, Subject, text, attachments
                                               |
Header:  Crest-Signature: v=0; c=<credential>; b=<agent signature>
Message: still passes DKIM with d=acme.example
```

The issuer reissues each credential automatically, at least once a day. To revoke an agent, the issuer stops reissuing its credential. The credential then lapses within 24 hours.

The verifier checks the message as its own mail server accepted it. The result is **verified**, or **not verified** with a reason. A message that is not verified is still delivered as plain email. CREST never blocks delivery.

## 4. Domain keys in DNS

### 4.1 The record

An issuer publishes each domain key as a TXT record at:

```
<selector>._crest.<host>
```

Here `<host>` is the domain of the agent addresses: the right-hand side of the `@`.

The record is a tag list in the style of DKIM (RFC 6376 §3.2):

```
v=CREST0; k=ed25519; p=<base64url of the 32-byte Ed25519 public key>
```

- `v` MUST be `CREST0`.
- `k` MUST be `ed25519`.
- `p` is the raw public key (RFC 8032), in base64url. An empty `p=` means the key is revoked.
- Whitespace around tags and values is ignored. Unknown tags are ignored. A record with a duplicate tag is invalid.
- If a TXT record has several character strings, they are joined with nothing between them before parsing, as in DKIM.

A selector is one DNS label: lowercase letters, digits and hyphens, from 1 to 63 characters, not starting or ending with a hyphen. Its grammar is `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`.

A name with no TXT record whose `v` is `CREST0` has no key. A name with more than one such record is treated the same way.

### 4.2 Rotation and removal

- Several selectors MAY be live at once, so keys rotate as DKIM keys do.
- A retired selector SHOULD stay published for at least 7 days after the last credential it signed.
- A compromised domain key MUST be removed, or set to an empty `p=`, at once.
- The record's TTL SHOULD be at most 1 hour. The TTL is the most time a removal can take to reach verifiers.

### 4.3 Domains run by a provider

A domain whose mail a provider runs SHOULD publish a small fixed set of selectors, for example `s1` and `s2`. Each is a CNAME to a name the provider controls:

```
s1._crest.customer.example.  CNAME  s1.customer-example.crest-keys.provider.example.
s2._crest.customer.example.  CNAME  s2.customer-example.crest-keys.provider.example.
```

The provider then rotates keys under those names, and the customer never touches DNS again. This is how many providers handle DKIM.

A single CNAME at `_crest.<host>` does not work: a CNAME does not redirect the names below it (RFC 1034 §3.6.2).

## 5. The agent credential

### 5.1 Format

A credential is a JWS in compact serialization (RFC 7515), with an Ed25519 signature (`EdDSA`, RFC 8037) by a domain key.

**Protected header**

| Member | Value |
| --- | --- |
| `alg` | `EdDSA` |
| `typ` | `crest-cred+jwt` |
| `kid` | the selector of the domain key |

A verifier MUST reject a protected header that contains `crit`. It ignores any other member.

**Claims (payload)**

| Claim | Required | Value |
| --- | --- | --- |
| `iss` | yes | The issuer host. It MUST equal the host of `from`, lowercase, as A-labels. |
| `sub` | yes | The agent ID, unique within the issuer. Grammar: `^[A-Za-z0-9._-]{1,64}$`. |
| `from` | yes | The one address the agent sends from, in canonical form (§6.4). |
| `cnf` | yes | `{"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "<base64url public key>"}}`. This is the agent key, as a proof-of-possession key (RFC 7800). |
| `principal` | yes | The disclosure (§5.3). |
| `scope` | no | A statement of the agent's authority, in plain words (§5.4). |
| `iat` | yes | The time the credential was issued. |
| `exp` | yes | The time it expires. `exp - iat` MUST be more than 0 and at most 86,400 (24 hours). |

The payload MUST be I-JSON (RFC 7493). A verifier MUST reject duplicate member names. `iat` and `exp` MUST be integers.

The payload SHOULD be serialized with JCS. A verifier does not depend on this: it checks the signature over the bytes as sent.

The whole credential in compact form MUST be at most 1,536 octets.

A verifier MUST ignore claims it does not know. Claim names without a colon (`:`) are reserved for this specification. An extension claim name MUST contain a colon, for example `example.com:tier` (§11).

### 5.2 One credential per address

A credential names exactly one address. Each address has its own credential, agent ID and agent key, in every disclosure mode. To a receiver, an agent is an address.

The issuer:
- MUST NOT give two addresses the same `sub` or the same agent key;
- SHOULD keep an address's `sub` and agent key stable across reissues, so a counterparty sees the same agent each time;
- MAY change the agent key when it must, for example after a compromise;
- decides how it groups addresses that belong to one agent. That grouping is outside the protocol.

### 5.3 Principal disclosure

`principal` is one of three objects. No other members are allowed in them.

| Mode | Object | What the receiver learns |
| --- | --- | --- |
| withheld | `{"mode": "withheld"}` | The issuer says it knows the principal. Nothing more. **This is the default.** |
| pseudonymous | `{"mode": "pseudonymous", "id": "<id>"}` | A pseudonym for the principal that only this counterparty sees. Grammar: `^[A-Za-z0-9._-]{1,64}$`. |
| named | `{"mode": "named", "name": "<name>"}` | The principal's name or address, as the issuer attests it. At most 128 UTF-8 octets, with no control characters. |

Rules for issuers:
- **No credential without a principal.** An issuer MUST NOT issue a credential it cannot trace to the principal whose authority it carries. Withheld mode hides that link from the receiver. The link must still exist.
- **The principal chooses.** Anything above withheld is the principal's choice.
- **Pseudonyms are pairwise.** In pseudonymous mode, the agent writes to each counterparty from its own address, so it has its own credential, agent ID, agent key and `id` for each (§5.2). The issuer MUST NOT reuse an `id` across counterparties. What counts as one counterparty is the issuer's choice.
- **Only the issuer raises disclosure.** Disclosure is set by the credential. A sender cannot raise it per message.

Email's own headers limit what a mode can hide. A `From` address that names the principal names them whatever the credential says. Anonymity needs an alias address.

A disclosed principal is only as reliable as the issuer that attests it.

### 5.4 Scope

`scope` is an optional statement, in plain words, of what the agent may do. For example: "Books restaurant tables for one person, up to $500 per booking."

- At most 280 UTF-8 octets.
- No control characters: U+0000 to U+001F and U+007F to U+009F.
- It is part of the credential, so the domain signs it and the agent cannot change it per message.

CREST never decides whether a message fits its scope. A receiver shows the scope and applies its own policy.

### 5.5 Issuing

- An issuer SHOULD issue credentials that last about 24 hours, and reissue them before they expire.
- An issuer MUST certify only an agent key it has proof of possession for, or one it holds itself.
- Before revealing a withheld principal, to whom and when, an issuer follows law and its own terms. That is outside the protocol.

## 6. The signed message

### 6.1 Message layout

A signed message MUST have one of two layouts.

1. The whole message is one `text/plain` part.
2. The top level is `multipart/mixed`, and:
   - its first child is `text/plain` and is not marked `Content-Disposition: attachment`. This is the body.
   - every other child is a single part (not `multipart/*`) with `Content-Disposition: attachment`. These are the attachments.

Nothing else is allowed. In particular, a signed message has no `text/html` alternative and no nested multiparts. HTML is what a person would see in place of the signed text, and it is what gateways rewrite most.

The body part:
- MUST use charset `utf-8` or `us-ascii`. A missing charset means `us-ascii`.
- MAY use any content transfer encoding. `quoted-printable` or `base64` is RECOMMENDED, because they survive relays that rewrap long lines.
- MUST NOT use `format=flowed`. Verifiers do not undo it.

An attachment with a `message/*` type (a forwarded email) is allowed. It is covered by the digest of its body bytes as they appear in the message.

### 6.2 The `Crest-Signature` header

A signed message carries exactly one `Crest-Signature` header field. It is a tag list:

```
Crest-Signature: v=0; c=<credential>; b=<agent signature>
```

| Tag | Value |
| --- | --- |
| `v` | `0` |
| `c` | the credential, compact JWS (§5) |
| `b` | the agent signature, detached compact JWS (§6.5) |

- The signer MAY fold the header anywhere, including inside values (RFC 5322 §2.2.3).
- Before parsing, a verifier removes all whitespace: SP, HTAB, CR and LF.
- Tags are separated by `;` and written `name=value`. A duplicate tag makes the header malformed. Unknown tags are ignored.
- With whitespace removed, the value MUST be at most 2,048 octets. In practice it is about 800.
- The issuer's DKIM signature SHOULD cover `Crest-Signature`.

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
| `attachments` | an array with one entry per attachment, in MIME order: `{"type": ..., "name": ..., "sha256": ...}` |
| `credential` | base64url of SHA-256 over the `c` tag value, the credential in compact form as ASCII |

An attachment entry is:
- `type`: the media type and subtype, lowercase, without parameters. A missing `Content-Type` means `text/plain`.
- `name`: the `filename` parameter of `Content-Disposition`, or failing that the `name` parameter of `Content-Type`, decoded per RFC 2231. If neither is present, `""`.
- `sha256`: base64url of SHA-256 over the part's body after its transfer encoding is decoded.

Not covered:
- `Message-ID` and `Date`, which some providers replace on sending;
- display names, which servers re-encode;
- `In-Reply-To` and `References`, which servers rewrite, and which nothing in v0 depends on;
- all other headers.

DKIM still covers whatever the issuer's DKIM signature lists.

### 6.4 Canonical forms

**Addresses.** For `From`, `To`, `Cc` and `Reply-To`:
1. Parse the header as an RFC 5322 address list. Take the addr-spec of every mailbox, including the members of groups. Drop display names, comments and routes.
2. Convert the domain to A-labels (IDNA2008, RFC 5891), then lowercase it, and remove a trailing dot. A domain that cannot be converted makes the message malformed.
3. Lowercase the ASCII letters A to Z in the local part. Leave all other characters as they are. Apply no Unicode normalization.
4. Keep header order. Drop later duplicates.
5. If the header is absent, the list is `[]`. If the header appears more than once, the message is malformed.

A signed message MUST NOT use a quoted-string local part (for example `"john doe"@example.com`) in these four headers. A verifier treats one as malformed.

**Subject.**
1. Unfold: remove each CRLF that is followed by whitespace.
2. Decode RFC 2047 encoded words. Whitespace between two adjacent encoded words is dropped, as RFC 2047 §6.2 says.
3. Replace each run of SP and HTAB with one SP.
4. Trim SP at both ends.

An absent `Subject` is `""`. More than one `Subject` makes the message malformed. An encoded word in an unknown charset makes the message malformed.

**Text.**
1. Decode the body part's transfer encoding.
2. Decode the charset to Unicode. Bytes that are invalid in the charset make the message malformed.
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
| `typ` | `crest-sig` |
| `iat` | when the signer signed, an integer |
| `nonce` | a random value, at least 96 bits, in base64url. Grammar: `^[A-Za-z0-9_-]{16,64}$`. |

A verifier MUST reject `crit`, and ignores other members.

The signature is computed as in RFC 7515: Ed25519 over `ASCII(BASE64URL(header) || "." || BASE64URL(JCS(signing input)))`.

### 6.6 Signing

The signer:
1. builds the message in its final form, as it will leave the issuer's mail system. Footers, banners and subject tags are added first.
2. picks the credential for the `From` address. It MUST NOT sign with a credential that has less than 6 hours left before `exp`.
3. builds the signing input from those bytes, signs it, and adds `Crest-Signature`.
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
4. **The mailbox.** This is the envelope recipient (RCPT TO) this copy was delivered for, and the addresses that mailbox receives at.

A verifier SHOULD verify soon after arrival. The domain key in DNS may change later.

### 7.2 Steps

A verifier runs these steps in order. The first step that fails gives the verdict **not verified**, with the reason shown.

| # | Check | Reason if it fails |
| --- | --- | --- |
| 1 | The message has a `Crest-Signature` header. | `no_signature` |
| 2 | It has exactly one. | `multiple_signatures` |
| 3 | `From` has exactly one address. Let H be its host. | `malformed` |
| 4 | At least one DKIM signature passed with `d=` equal to H (compared case-insensitively). If none did, stop here, before any DNS lookup. | `dkim_unaligned` |
| 5 | The header parses (§6.2), and is within its size limit. | `malformed` |
| 6 | `v` is `0`. | `unsupported_version` |
| 7 | `c` and `b` parse as compact JWS, `b` with an empty payload, and their JSON is I-JSON. | `malformed` |
| 8 | The credential header has `alg` `EdDSA`, `typ` `crest-cred+jwt`, a valid selector in `kid`, and no `crit`. `iss` equals H. | `credential_invalid` |
| 9 | Look up TXT at `<kid>._crest.H` (§7.4). | `dns_error`, `dns_limited` |
| 10 | Exactly one record with `v=CREST0` and `k=ed25519` exists. | `key_not_found` |
| 11 | Its `p` is not empty. | `key_revoked` |
| 12 | The credential's signature verifies with that key. | `credential_invalid` |
| 13 | The claims are well-formed: `sub`, `principal`, `scope`, `cnf` and lifetime, per §5. | `credential_invalid` |
| 14 | `iat - 300 <= arrival <= exp + 7200`. | `credential_expired` |
| 15 | `from` equals the canonical `From` address. | `from_mismatch` |
| 16 | The layout is valid (§6.1). | `layout` |
| 17 | The signing input can be built (§6.3, §6.4). | `malformed` |
| 18 | The signature header has `alg` `EdDSA`, `typ` `crest-sig`, a valid `nonce`, and no `crit`. Its `iat` satisfies `credential iat - 300 <= iat <= min(exp, arrival + 300)`. | `signature_invalid` |
| 19 | The agent signature verifies with the key in `cnf`, over the rebuilt signing input. | `signature_invalid` |
| 20 | `To` or `Cc` lists an address of the mailbox (§7.5). | `not_addressed` |
| 21 | The tuple (envelope recipient, `iss`, `sub`, `nonce`) has not been seen (§7.6). | `replay` |

If every step passes, the verdict is **verified**.

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
- **Not verified**, with one reason from §7.2. A message that is not verified is plain email: the receiver handles it as it would without CREST.

The reason is for diagnosis. A receiver SHOULD NOT tell the user a different story for each reason. A changed text and a forgery both fail as `signature_invalid`.

A verdict never blocks delivery by itself. Receivers may still apply their own policies.

### 7.4 DNS lookups

- A verifier MUST look up a key only for the domain that passed aligned DKIM (step 4). This keeps unauthenticated mail from making the verifier query any domain it names.
- A verifier MUST NOT make the lookup while the SMTP session is open.
- The lookup timeout is 2 seconds. A timeout or a server failure is `dns_error`.
- Answers are cached for their TTL. A missing record is cached for at least 5 minutes.
- A verifier MUST limit lookups of distinct uncached selectors per domain. A limit of 4 per domain per hour is RECOMMENDED. A lookup refused by the limit is `dns_limited`.
- Like DKIM, a lookup tells the sender's DNS operator that a message arrived. See §10.

### 7.5 Addressed to this mailbox

A captured message passes DKIM again if it is resent unchanged to someone else. Step 20 stops that. A message verifies only for a mailbox it was addressed to in `To` or `Cc`.

- The mailbox's addresses are its own addresses and aliases.
- A receiver MAY also count addresses it knows forward to the mailbox, for example an old address the user set up to forward.
- A recipient that was only on the envelope, such as a `Bcc` recipient or an unknown forward, gets **not verified** (`not_addressed`). A sender that wants a recipient to verify lists them in `To` or `Cc`.

This rule is open for review (§15, issue 1).

### 7.6 Replays

The verifier remembers each (envelope recipient, `iss`, `sub`, `nonce`) of a message it verified. It keeps the tuple until the credential's `exp` plus the 2-hour grace. After that, step 14 rejects the message anyway.

- The tuple includes the envelope recipient, so one message delivered to two mailboxes at the same receiver verifies for each.
- The check comes after the signatures, so a forged message cannot fill the store.
- A receiver MAY remove duplicate deliveries, such as SMTP retries, by `Message-ID` before verifying. A second copy that reaches the verifier is not verified (`replay`).

### 7.7 Limits

| Item | Limit |
| --- | --- |
| `Crest-Signature` value, whitespace removed | 2,048 octets |
| Credential, compact | 1,536 octets |
| Credential lifetime (`exp - iat`) | at most 24 hours |
| Credential life left when signing | at least 6 hours |
| Arrival grace after `exp` | 2 hours |
| Clock skew | 5 minutes |
| `scope` | 280 UTF-8 octets |
| Named principal | 128 UTF-8 octets |
| `sub`, pseudonym `id` | 1 to 64 characters, `[A-Za-z0-9._-]` |
| `nonce` | 16 to 64 base64url characters, at least 96 random bits |
| DNS lookup timeout | 2 seconds |
| Negative cache | at least 5 minutes |
| Uncached selectors per domain | 4 per hour (RECOMMENDED) |
| Domain key TTL | at most 1 hour (SHOULD) |
| Retired selector kept | at least 7 days after last use (SHOULD) |

## 8. First contact and receiver control

v0 has no special message for an introduction. A stranger agent's first message is a signed message like any other.

- **The receiver decides who gets in.** Holding, admitting, asking a person, and blocking are the receiver's policy. CREST supplies the evidence, never the admission rule.
- **The evidence.** It is the verdict and, when verified, the agent's domain, address, agent ID, principal as far as disclosed, and scope.
- **Anything offered in support is content.** For example: "Bob at partner.example suggested I write", a forwarded message, or a code the receiver gave out. The receiver, or its agent, judges it like any text.
- **A forwarded CREST message cannot be verified** by the receiver in v0. The receiver may look up keys only for the domain that passed DKIM on the outer message (§7.4). An introducer who wants to be verified writes to the receiver directly, or copies the stranger in.
- **No automatic replies to agents.** A receiver SHOULD NOT tell a sending agent that its message was held. Silence tells address scrapers nothing, and it avoids backscatter.
- **Agent addresses are worth protecting.** An issuer SHOULD keep agent addresses from becoming widely known, for example with an alias per counterparty, and replace an address that is abused. A counterparty knows the agent by its address, so a replacement starts a new pairing.

## 9. Security considerations

**What "verified" means.** The `From` host's mail system sent the message, and the agent key that domain certified for that address signed its addresses, subject, text and attachments. The credential was valid on arrival, and this mailbox was meant to receive it.

It does not mean:
- that the agent is honest or competent;
- that the request fits its scope;
- that the principal exists outside the issuer's word.

**Sender text is untrusted.** `scope`, a named principal, `sub`, the subject and the text are all written by the sender's side. A receiver MUST show them as the sender's claims. When it passes them to a language model, it MUST mark them as data, never as instructions.

**Display names are not signed.** `From: "Your Bank" <maple-tiger-27@acme.example>` verifies. Receivers SHOULD show the address and the issuing domain, not the display name, next to a verified verdict.

**Lookalike domains.** CREST proves which domain spoke, not that it is the domain the user expects. A receiver SHOULD make internationalized and lookalike domains visible, for example by showing A-labels or by flagging confusable characters.

**A stolen agent key** can sign only for its one address. It lasts until the credential lapses: at most 24 hours plus the 2-hour grace. It still needs the domain's mail system to pass DKIM. Protecting keys is the issuer's job.

**A leaked domain key** lets the attacker mint credentials for any address on the host. To pass step 4, the attacker also needs to send through the domain's DKIM-signing mail system. Removing the key reaches verifiers within the record's TTL.

**A compromised mail system and domain key** together let an attacker send as any agent of that domain. That is the issuer's full compromise. CREST cannot do better than the issuer it trusts.

**Addresses that differ only in case.** Verifiers lowercase ASCII in local parts. An issuer MUST NOT issue credentials for two addresses that are equal after that lowercasing.

**Resending a captured message.** DKIM passes again on an unchanged resend. The addressing check (§7.5) and the replay store (§7.6) stop it from verifying anywhere it was not sent.

**Relays that change messages.** Mailing lists and gateways that change a covered part or break DKIM make a message not verified. This is deliberate: a verdict that could be true for some receivers and false for others would make implementations disagree. ARC (RFC 8617) is not used in v0.

**Strict alignment.** The DKIM domain must equal the `From` host. Relaxed alignment would need the Public Suffix List, and its versions differ between implementations. A provider that signs subdomain mail with the parent domain must sign CREST mail with the exact host.

**Denial of service.**
- Key lookups happen only after aligned DKIM passes, have timeouts, and are rate-limited.
- Size limits (§7.7) bound parsing.
- JSON must be I-JSON, which rejects duplicate keys, a common source of parser disagreement.

**Time.** Verification uses arrival time, so a signer cannot backdate. The signature's `iat` is checked only for sanity.

**Long-term proof is out of scope.** CREST verifies a message when it arrives. Proving years later what was said is a records question between one party, its archive, and perhaps a court. An extension may add timestamps or key transparency. A receiver that needs proof later SHOULD keep the DNS record it verified against, next to the message.

## 10. Privacy considerations

**Being an agent is always disclosed.** A signed message says an agent wrote it. Who it acts for is disclosed only as far as the principal chooses (§5.3).

**Unlinkability depends on addresses.** A credential names one address, its own agent ID and its own key (§5.2), so nothing in it links two of an agent's addresses. Whether counterparties can link an agent depends on whether its issuer gives each counterparty its own address.

**The domain links.** Every message shows its domain, as DKIM already does. Unlinkability across counterparties holds only when many principals share the domain. On a domain with one owner, the domain names the owner.

**Other things link.** Writing style, timing, scope wording, other headers such as `Received` and `Message-ID` formats, and the content itself. CREST does not hide them.

**Withheld is not anonymous to the issuer.** The issuer knows the principal (§5.3). When it reveals a withheld principal is a matter of law and its terms.

**No directory.** Nothing in CREST lists a domain's agents or addresses. Selectors name domain keys, not agents.

**DNS lookups.** The sender's DNS operator can see that a receiver looked up a key, as with DKIM. Caching limits what it learns.

**Other agent headers.** A sender MAY also add the `Agent-of` header (draft-chuang-agent-attribution-header-fields), but only in named mode. In the other modes it would reveal the principal.

## 11. Versioning and extensions

- **Version.** The header's `v=0`, the record's `v=CREST0`, and the signing input's `"v": 0` mark this version. A verifier that does not support a message's version returns `unsupported_version`. A later version may add members to the signing input, which is why the signing input carries `v`.
- **Credential claims.** Extensions add claims whose names contain a colon. The domain signs them. Verifiers ignore claims they do not know.
- **Header tags.** Unknown tags are ignored. A tag is not signed, so it MUST NOT carry anything a receiver relies on.
- **JWS header members.** Unknown members are ignored. `crit` is rejected in v0.
- **Possible extensions**, none defined here:
  - a structured scope vocabulary;
  - a published agent card (A2A);
  - DNS records per agent;
  - ARC for trusted forwarders;
  - a structured `note` part for machine-readable data;
  - timestamps for long-term proof.

## 12. Conformance

There are three roles.

| Role | Must |
| --- | --- |
| Issuer | Publish domain keys (§4), and issue credentials that follow §5, including the issuer rules in §5.2, §5.3 and §5.5. |
| Signer | Sign messages that follow §6, with the 6-hour rule (§6.6). |
| Verifier | Follow §7 exactly, and reach the expected verdict on every published test vector. |

Two verifiers given the same four inputs (§7.1) MUST reach the same verdict and the same reason. That is the test of this specification. Where it fails, the specification is wrong and should be fixed.

## 13. Registrations

None has been requested yet. If CREST goes ahead, it would ask for:

- **Header field:** `Crest-Signature`, in the Permanent Message Header Field Names registry (RFC 3864), provisional at first.
- **Underscored DNS name:** `_crest`, for TXT, in the Underscored and Globally Scoped DNS Node Names registry (RFC 8552).
- **Media types** for the JWS `typ` values: `application/crest-cred+jwt` and `application/crest-sig`.
- **JWT claims:** `from`, `principal` and `scope`, in the JSON Web Token Claims registry, or renamed to collision-resistant names if the registry's experts prefer.

## 14. Relation to A2A and CREST Tasks

**A2A.** CREST is independent of A2A (the Agent2Agent protocol), with a defined bridge planned.
- An agent that also speaks A2A may publish an Agent Card. A later extension will say how a card names its CREST addresses, and how a credential points to a card.
- Both use JOSE, so keys and signatures move between them without conversion.
- Mapping A2A task states onto email belongs to CREST Tasks.

**CREST Tasks.** A later document adds tasks on top of v0:
- a signed, machine-readable task part;
- requests, offers, acceptance and confirmation;
- the rules that decide when an agreement exists over slow, lossy email.

It reuses v0's credential and signature unchanged, and adds the task part to the signing input under a new version.

## 15. Open issues

These are open for review. Each needs a decision before v0 is final.

1. **The addressing check and forwarded mail.** §7.5 lets a message verify only for a mailbox listed in `To` or `Cc`. That stops a captured message from being resent to someone else. But a plain forward, for example from an old address the receiver does not know about, then shows as not verified, although it keeps DKIM. So do `Bcc` recipients. The alternative, no addressing check, lets anyone who receives a signed message resend it, verified, to anyone. Is the trade right?
2. **The numbers.** The values in §7.7 are first proposals: in particular the 2-hour grace, the 6-hour minimum, the 280-octet scope, the 2,048-octet header and the selector rate limit. Real traffic should set them.
3. **Will the header survive?** It is untested whether a folded header of about 800 octets survives Microsoft 365, Gmail, Amazon SES and common gateways unchanged, or within what limits. If it does not, the fallback is to carry the credential and signature in a MIME part.
4. **Attachment names.** Libraries differ in how they decode filenames, for example RFC 2047 encoded words where RFC 2231 is expected. Should `name` stay in the signing input, with exact rules, or be dropped?
5. **Local parts.** Lowercasing ASCII in local parts matches how almost all mail systems behave, but RFC 5321 says local parts are case-sensitive. Is lowercasing right, and how should non-ASCII local parts (SMTPUTF8) be compared?
6. **Editor's choices on the wire.** None of these is settled. Each is open to change while v0 is a draft.
   - Tag letters `c` and `b`.
   - base64url in DNS, where DKIM uses base64.
   - A standard detached JWS rather than RFC 7797 unencoded payloads.
   - A message-level `exp` was dropped: the credential's `exp` and arrival time bound a message already.
7. **Test vectors.** Appendix B lists the first set. Still missing:
   - non-ASCII subjects in several encodings;
   - internationalized domains and SMTPUTF8 addresses;
   - multiple DKIM signatures;
   - `message/rfc822` attachments;
   - published machine-readable files.
8. **The formal model** (Appendix C) is not built yet.
9. **Name.** "CREST" and the header name are provisional until a trademark check is done.

## Appendix A. Worked example

The reference sketch in `reference/crest_v0.py` produces this example. Run `uv run --with cryptography python reference/crest_v0.py --example` to reproduce it byte for byte. The keys are test keys derived from fixed strings. Never use them for anything else.

**DNS**

```
s1._crest.acme.example. TXT "v=CREST0; k=ed25519; p=8HdNlpm5db4VyCRM73vUIBPbBLaQ0eHR6IdgouZsfwk"
```

**Credential: protected header and claims**

```json
{"alg":"EdDSA","kid":"s1","typ":"crest-cred+jwt"}
```

```json
{
  "cnf": {"jwk": {"crv": "Ed25519", "kty": "OKP", "x": "56n6gHHV7WyyHMgucGUeyc41a95mH8M5Sodd8EcTfUM"}},
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
{"attachments":[{"name":"booking.csv","sha256":"toHbGVby3dGckYAJkxBXPj9DGUnSCDiuIVwGV4oFR7w",
"type":"text/csv"}],"cc":[],"credential":"VJTvpJO2BHDbAMRd9wVXolaQc60ix5iczhAaXo_YB48",
"from":"maple-tiger-27@acme.example","reply_to":[],"subject":"Table for 2, Friday 7 November, 19:30",
"text":"JO-XRoNsBAPLwS_XAckdl7Jmo2DmjMagPnYpKzTgLkA","to":["reservations@bistro.example"],"v":0}
```

Note that `From` is written `Maple-Tiger-27@acme.example` in the message and canonicalized to lowercase.

**Message as sent, before the issuer's DKIM signature.** Line endings are CRLF on the wire.

```
Crest-Signature: v=0;
 c=eyJhbGciOiJFZERTQSIsImtpZCI6InMxIiwidHlwIjoiY3Jlc3QtY3JlZCtqd3QifQ.eyJjbmYi
 OnsiandrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiNTZuNmdISFY3V3l5SE1nd
 WNHVWV5YzQxYTk1bUg4TTVTb2RkOEVjVGZVTSJ9fSwiZXhwIjoxNzkzOTUyMDAwLCJmcm9tIjoibW
 FwbGUtdGlnZXItMjdAYWNtZS5leGFtcGxlIiwiaWF0IjoxNzkzODY1NjAwLCJpc3MiOiJhY21lLmV
 4YW1wbGUiLCJwcmluY2lwYWwiOnsiaWQiOiJwX1hrMjkiLCJtb2RlIjoicHNldWRvbnltb3VzIn0s
 InNjb3BlIjoiQm9va3MgcmVzdGF1cmFudCB0YWJsZXMgZm9yIG9uZSBwZXJzb24sIHVwIHRvICQ1M
 DAgcGVyIGJvb2tpbmcuIiwic3ViIjoiYWdfN0hxMiJ9.47Kwts6Ukd235LbLIfYTwTC0fAEILEXmM
 APaAEiUBc-8Sm0jAdNQgNNnY7FwbZKBG6Ga8uphSPZ10_Y9mcKLCQ;
 b=eyJhbGciOiJFZERTQSIsImlhdCI6MTc5Mzg3MDEwMCwibm9uY2UiOiJabTl5TFdWNFlXMXdiR1V
 0YjI1c2VRIiwidHlwIjoiY3Jlc3Qtc2lnIn0..J76daT-bD8KuBLZgWPBWssuqkKubtkrR559rTX9
 mTyUj6M1MiRbNUimv0vzWBrIRfpk6eK_rz-YROYXCAgvJBA
From: Booking agent <Maple-Tiger-27@acme.example>
To: Reservations <reservations@bistro.example>
Subject: Table for 2, Friday 7 November, 19:30
Message-ID: <example-1@acme.example>
Date: Thu, 05 Nov 2026 09:15:00 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="=_crest_example_1"

--=_crest_example_1
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

Hello,

Could you hold a table for 2 this Friday, 7 November, at 19:30?
One guest is vegetarian.

Thank you

--=_crest_example_1
Content-Type: text/csv
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="booking.csv"
MIME-Version: 1.0

ZGF0ZSx0aW1lLHBhcnR5CjIwMjYtMTEtMDcsMTk6MzAsMgo=

--=_crest_example_1--
```

**Verifier inputs**

| Input | Value |
| --- | --- |
| Arrival time | 1793870110 (2026-11-05T09:15:10Z) |
| DKIM | pass, `d=acme.example` |
| Envelope recipient | `reservations@bistro.example` |

**Verdict:** verified. The agent:
- `iss`: `acme.example`
- `from`: `maple-tiger-27@acme.example`
- `sub`: `ag_7Hq2`
- `principal`: pseudonymous, `p_Xk29`
- the scope above.

## Appendix B. Test vectors

`reference/crest_v0.py` runs each vector against the example in Appendix A. Run it without arguments: it prints one line per vector and exits non-zero if any fails.

| Change to the message or inputs | Expected |
| --- | --- |
| None | verified |
| The same message again, same mailbox | `replay` |
| The same message, a second mailbox at the same receiver | verified |
| `Crest-Signature` folded differently | verified |
| Display name changed | verified (CREST does not cover it; DKIM may) |
| Trailing spaces added to a body line | verified |
| Subject changed | `signature_invalid` |
| Text changed | `signature_invalid` |
| `Reply-To` added | `signature_invalid` |
| `Cc` added | `signature_invalid` |
| Attachment changed | `signature_invalid` |
| An HTML part added | `layout` |
| Body charset ISO-8859-1 | `layout` |
| A second `To` header | `malformed` |
| A second `Crest-Signature` | `multiple_signatures` |
| No `Crest-Signature` | `no_signature` |
| DKIM passes only for `mail.acme.example` | `dkim_unaligned` |
| `v=1` | `unsupported_version` |
| DNS lookup fails | `dns_error` |
| No record at the selector | `key_not_found` |
| Record with empty `p=` | `key_revoked` |
| Record holds a different key | `credential_invalid` |
| Arrival 1 second after `exp` plus grace | `credential_expired` |
| Arrival exactly at `exp` plus grace | verified |
| `From` changed to another address on the same host | `from_mismatch` |
| Delivered to a mailbox not in `To` or `Cc` | `not_addressed` |

Some of these changes would also break DKIM in real mail. The vectors test the CREST checks alone, with the DKIM result given as an input.

The sketch handles ASCII domains and dot-atom local parts only, and does not handle `message/*` attachments. Machine-readable vectors, and vectors for what the sketch does not handle, are open (§15, issue 7).

## Appendix C. Formal model

A formal model of v0 (Tamarin or ProVerif) is planned, to be built alongside this draft and run on every change. It assumes perfect cryptography and an attacker who controls the network or plays one side.

It is to prove:
1. a verified message traces to a credential the domain issued for a delegating principal;
2. a captured message cannot verify for a mailbox it was not addressed to, or verify twice for the same one.

It does not exist yet.

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
| v0 is the identity layer | Tasks and agreements move to CREST Tasks. |
| Scope | A plain-words statement, signed by the domain. Software never enforces it. |
| Both proofs required | Aligned DKIM, checked by the receiver's own mail system, plus the agent signature. Without DKIM, no key lookup. |
| A credential belongs to a mailbox | The credential names its address. DKIM alignment is strict. |
| Where the signature travels | A header, with a size cap. Bare addresses are signed, not raw headers. |
| Pseudonymous mode | A pairwise address, credential, agent ID and key per counterparty. |
| First contact | No introduction act. A first contact is a signed message, and support for it is content. |
| Verdicts | Two: verified, or not verified with a reason. The message is checked as the receiver accepted it, and the payload is rebuilt, not sent. |
| One credential per address | A single `from` address with its own agent ID and key, in every mode. |
| Subject and Reply-To | Both signed. |
| Licence | Apache 2.0 for spec and code. The founder is editor until a second independent implementation exists. Changes go through public review. |
| Relation to A2A | Independent, with a defined bridge. |
