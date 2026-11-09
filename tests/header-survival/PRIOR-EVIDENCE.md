# Prior evidence: what mail systems do to a long, folded, unknown header

This is what public sources say, collected on 2026-11-08 before any message of the
header-survival test was sent. It is kept apart from the test's own results, which live under
`results/`. Each item is labelled **DOCUMENTED** (official documentation or an RFC),
**REPORTED** (a credible third-party account) or **UNKNOWN** (no source found).

One reading note. Colophon removes all whitespace from the header value before parsing
(specification section 6.2), so refolding on its own cannot break a signature. Only a
receiver that cuts, drops, duplicates or rewrites the value does.


## Baseline

- **DOCUMENTED.** RFC 5322 §2.2.3 lets any receiver unfold and refold header bodies; a value of 800–2,560 octets folded under 78 chars is ordinary. RFC 6376 §3.4 says "Some mail systems modify email in transit, potentially invalidating a signature"; `relaxed` header canonicalization unfolds continuation lines and collapses whitespace, `simple` "does not change header fields in any way". https://www.rfc-editor.org/rfc/rfc6376.html
- **DOCUMENTED.** Microsoft's own DKIM cmdlet text: relaxed tolerates "Header field line rewrapping"; simple tolerates "No changes". https://learn.microsoft.com/powershell/module/exchange/New-DkimSigningConfig
- **DOCUMENTED.** Postfix `header_size_limit` default 102400; longer multi-line headers are truncated, not rejected. https://www.postfix.org/postconf.5.html (mirror: https://manpages.debian.org/jessie/postfix/postconf.5)
- **REPORTED.** Sendmail `MaxHeadersLength=32768` rejects ("Headers too large"); Office 365 and Cisco IronPort were named as senders that emit headers that large (Sympa list, 2022-10/2024-10). https://lists.sympa.community/arc/en/2024-10/msg00005.html
- **REPORTED.** A receiver that re-serialises messages refolded long headers so `c=simple` failed and `c=relaxed` passed (dkimpy). https://github.com/smswithoutborders/RelaySMS-Publisher/issues/212

Conclusion for the baseline: a 2.5 KB header is far below every documented limit. The live risk is whitespace/fold changes, which only matter if the Colophon verifier canonicalises like `simple`.

## Gmail (consumer and Workspace)

- **DOCUMENTED limits.** 32 KB per header value, 1 KB per header name, 500 KB (512,000 bytes) total, 5,000 fields; rejection `552-5.3.4`; "These limits also apply to incoming messages." Unknown headers are accepted; nothing says they are stripped or rewritten. https://knowledge.workspace.google.com/admin/gmail/gmail-message-header-limits
- **DOCUMENTED retrieval.** Gmail API `format=raw` returns "The entire email message in an RFC 2822 formatted and base64url encoded string." https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages
- **UNKNOWN.** Whether raw/IMAP `BODY[]` output is byte-identical to the SMTP DATA (folding preserved). No Google statement found.

## Microsoft 365 / Exchange Online and Outlook.com

- **DOCUMENTED limits.** "The current limit is 256 KB. Individual headers are limited to 32KB each"; excess rejected `552 5.3.4`. https://learn.microsoft.com/en-us/office365/servicedescriptions/exchange-online-service-description/exchange-online-limits
- **DOCUMENTED storage.** "Outlook does not save messages in MIME format"; `$value` MIME is generated on request. https://learn.microsoft.com/en-us/graph/outlook-get-mime-message. Per MS-OXCMAIL §2.4, a fixed set of headers maps to MAPI properties; "The rest are saved in their raw, unconverted format to facilitate round-tripping" in `PidTagMimeSkeleton` (not in Exchange 2007; present since 2010). https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmail/b9673f1d-0847-4fea-a297-f4ad9ef8d7ba and https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmail/9617e6c1-9267-41f6-98c9-3276d0e547cd
- **DOCUMENTED (Exchange 2010 article).** The MIME writer merges the skeleton with MAPI-derived content "As long as nothing modifies the item by using a remote operation"; never when a TNEF body part exists; "MIME RFCs do not mandate that headers be maintained after a message has been stored." https://learn.microsoft.com/en-us/previous-versions/office/developer/exchange-server-2010/hh545614(v=exchg.140)
- **DOCUMENTED evidence of re-serialisation.** Microsoft's own `$value` samples show Exchange-style folding (`Message-ID:` folded onto a 16-space-indented line; unfolded `x-microsoft-antispam` lines well over 78 chars). The unknown header's content survives; its whitespace is Exchange's, not the sender's. https://learn.microsoft.com/en-us/graph/outlook-get-mime-message
- **DOCUMENTED.** `internetMessageHeaders` is a parsed name/value array (folding not representable). https://learn.microsoft.com/en-us/graph/api/resources/internetmessageheader?view=graph-rest-1.0
- **DOCUMENTED stripping scope.** Header firewall removes only `X-MS-Exchange-Organization-*`, `X-MS-Exchange-Forest-*`, `Received:` and `Resent-*:`; ordinary custom headers are out of scope. https://learn.microsoft.com/en-us/exchange/header-firewall-exchange-2013-help
- **REPORTED.** Since ~2026-07, `X-MS-Exchange-Transport-CrossTenantHeadersStripped` marks removal of some metadata when a message crosses tenants; which headers is undocumented. https://learn.microsoft.com/en-us/answers/questions/5965967/exchange-online-automatic-forwarding-no-longer-pre
- **REPORTED.** Outlook.com runs on the same Office 365 infrastructure as Exchange Online. https://petri.com/outlook-com-exchange-online
- **UNKNOWN.** Whether the skeleton path preserves original fold positions of unknown headers on IMAP/`$value`.

## iCloud Mail

- **DOCUMENTED.** 20 MB message limit; no header limits published. https://support.apple.com/102198
- **REPORTED.** Messages with a `Message-ID` local part over 39 chars were accepted and silently not delivered. https://medium.com/follow-up-boss-dev/when-icloud-emails-go-into-a-black-hole-76991abd87a8. An IMAP "Parse Error" with custom headers was reported in Thunderbird. https://bugzilla.mozilla.org/show_bug.cgi?id=1846109
- **UNKNOWN.** Refolding, stripping, raw fidelity.

## Fastmail

- **DOCUMENTED.** Fastmail adds `X-Spam-*`, `X-ME-*`, `Authentication-Results` and ARC headers on inbound; no statement on size limits or altering existing headers. https://fastmail.help/hc/en-us/articles/1500000278262
- **DOCUMENTED (protocol).** JMAP `blobId` is "the raw octets of the message"; Raw header form is "The raw octets of the header field value". https://www.rfc-editor.org/rfc/rfc8621.html
- **REPORTED.** Cyrus `maxheaderlines_skip` default 1000 affects caching, not storage (2009 patch). https://lists.andrew.cmu.edu/pipermail/cyrus-devel/2009-February/001126.html
- **UNKNOWN.** Any header-size cutoff.

## Yahoo Mail

- **DOCUMENTED.** Error list includes "Header too big (e.g. From, Subject, To)" and RFC-compliance failures ("Duplicate headers", "Incorrectly formatted headers"); no numeric limits. https://senders.yahooinc.com/smtp-error-codes/
- **UNKNOWN.** Storage and IMAP fidelity for unknown headers.

## Proton Mail

- **DOCUMENTED.** External mail is "stored on our servers with zero-access encryption"; body and attachments encrypted; the subject "is part of the header packet, which is not end-to-end encrypted". https://proton.me/support/proton-mail-encryption-explained. Headers are viewable and downloadable as `.txt`. https://proton.me/support/check-email-headers
- **UNKNOWN.** Whether the stored header packet is the byte-exact original (folding) or a parsed/re-emitted form.

## Zoho Mail

- **DOCUMENTED.** 40 MB incoming, 500 attachments; no header limits documented. https://www.zoho.com/mail/help/adminconsole/rates-and-limits.html
- **REPORTED.** Zoho adds `X-ZohoMail*` headers. https://help.zoho.com/portal/en/community/topic/zoho-spam-email-headers-x-zohomail-etc?page=1
- **UNKNOWN.** Everything else.

## Amazon SES inbound (S3 action)

- **DOCUMENTED.** "Amazon SES delivers you the raw, unmodified email in Multipurpose Internet Mail Extensions (MIME) format"; 40 MB including headers (S3), 150 KB (SNS). SES prepends `Authentication-Results`, `X-SES-Spam-Verdict`, `X-SES-Virus-Verdict`. https://docs.aws.amazon.com/ses/latest/dg/receiving-email-concepts.html and https://docs.aws.amazon.com/ses/latest/dg/receiving-email-action-s3.html
- This is the strongest documented "keep as-is" guarantee among the providers surveyed.

## Forwarder: Gmail automatic forwarding

- **DOCUMENTED.** Google tells forwarders to add `X-Forwarded-For:`/`X-Forwarded-To:` and to "Avoid changing the body and message headers protected by DKIM"; "Gmail does its own authentication check on forwarded messages." https://support.google.com/a/answer/175365
- **REPORTED.** Gmail-forwarded mail carries `X-Forwarded-To`, `X-Forwarded-For`, extra `Received` and per-hop DKIM/ARC/Authentication-Results. https://lists.exim.org/lurker/message/20240514.082555.10b0e6aa.en.html
- **UNKNOWN.** Whether unknown headers are refolded in the forwarded copy.

## Forwarder: Cloudflare Email Routing

- **DOCUMENTED.** "The `From:` header of the message is not modified"; envelope sender rewritten; two DKIM signatures added; ARC supported; mail must pass SPF or DKIM or is rejected. https://developers.cloudflare.com/email-routing/postmaster/. ARC: "we take a snapshot of all the headers and the body of the original message" then add `Arc-Authentication-Results`, `Arc-Message-Signature`, `Arc-Seal` (2023-10-26). https://blog.cloudflare.com/email-routing-subdomains/. 25 MiB message limit. https://developers.cloudflare.com/email-routing/limits/. Workers `forward()` may add only `X-` headers. https://developers.cloudflare.com/email-routing/email-workers/runtime-api/
- **UNKNOWN.** Whether the forwarded bytes are otherwise untouched.

## Summary

| Provider | Keeps unknown headers? | Refolds? | Known limits | Source quality |
|---|---|---|---|---|
| Gmail / Workspace | Yes (DOCUMENTED, limits page) | UNKNOWN | 32 KB/value, 1 KB/name, 500 KB total, 5,000 fields | Official |
| Microsoft 365 / Outlook.com | Yes, via MIME skeleton (DOCUMENTED, spec); content kept, bytes regenerated | Likely yes: MIME is rebuilt on request; own samples show Exchange folding (DOCUMENTED) | 32 KB/header, 256 KB total | Official + spec |
| iCloud | UNKNOWN | UNKNOWN | 20 MB message only | Anecdotal |
| Fastmail | Presumed yes (JMAP raw blob, protocol-level) | UNKNOWN | None published | Official (partial) |
| Yahoo | UNKNOWN | UNKNOWN | "Header too big", no numbers | Official (vague) |
| Proton | Headers viewable (DOCUMENTED); fidelity UNKNOWN | UNKNOWN | None published | Official (partial) |
| Zoho | UNKNOWN | UNKNOWN | 40 MB message | Official (silent on headers) |
| SES to S3 | Yes, "raw, unmodified" (DOCUMENTED) | No (DOCUMENTED) | 40 MB incl. headers | Official |
| Gmail forwarding | Yes (REPORTED); adds X-Forwarded-*, ARC | UNKNOWN | Gmail limits apply | Official guidance + list post |
| Cloudflare Email Routing | Yes (DOCUMENTED From unchanged; ARC over all headers) | UNKNOWN | 25 MiB | Official |

**Practical reading for the header-survival test:** no surveyed provider documents stripping or truncating an unknown 2.5 KB header. The one documented transformation is Exchange's MIME regeneration, so a verifier that is byte-exact over folding (DKIM `simple` analogue) will be fragile at Microsoft; a `relaxed`-style canonicalisation covers every documented behaviour found.