# Header survival results: run 20261109T154845Z-0490

Sent 2026-11-09 15:48 UTC from `test@colophon-protocol.org` through Amazon SES. Messages: `minimal` (one short header),
`cap` (the header at exactly 2,560 octets with a 2,048-octet credential), `attachments`
(a CSV and a PDF attached). Each cell: what the receiver did to the header, then the
reference verifier's verdict on the stored message with the receiver's own inputs.

`intact` means the whitespace-removed value is what was sent; `refolded` means the same
value on different line breaks, which the spec allows (section 6.2).

### Direct deliveries

| Receiver | Provider | Account | Capture | minimal | cap | attachments |
|---|---|---|---|---|---|---|
| ses-inbound | Amazon SES inbound (S3) | - | s3 | intact; verified | intact; verified | intact; verified |
| gmail-workspace | Gmail (Google Workspace) | business | file | intact; verified | intact; verified | intact; verified |

### Recorded forwards (behaviour of the whole path, not one provider)

| Receiver | Provider | Account | Capture | Via | minimal | cap | attachments |
|---|---|---|---|---|---|---|---|
| cloudflare-to-gmail | Gmail (Google Workspace) | business | file | Cloudflare Email Routing | intact; verified | intact; verified | intact; verified |

### Inputs used

- ses-inbound / minimal: DKIM pass for amazonses.com, colophon-protocol.org; arrival from topmost Received; DNS live lookup
- ses-inbound / cap: DKIM pass for amazonses.com, colophon-protocol.org; arrival from topmost Received; DNS live lookup
- ses-inbound / attachments: DKIM pass for amazonses.com, colophon-protocol.org; arrival from topmost Received; DNS live lookup
- gmail-workspace / minimal: DKIM pass for amazonses.com, colophon-protocol.org; arrival from topmost Received; DNS live lookup
- gmail-workspace / cap: DKIM pass for amazonses.com, colophon-protocol.org; arrival from topmost Received; DNS live lookup
- gmail-workspace / attachments: DKIM pass for amazonses.com, colophon-protocol.org; arrival from topmost Received; DNS live lookup
- cloudflare-to-gmail / minimal: DKIM pass for amazonses.com, cloudflare-email.net, colophon-protocol.org, <forwarding domain>; arrival from topmost Received; DNS live lookup
- cloudflare-to-gmail / cap: DKIM pass for amazonses.com, cloudflare-email.net, colophon-protocol.org, <forwarding domain>; arrival from topmost Received; DNS live lookup
- cloudflare-to-gmail / attachments: DKIM pass for amazonses.com, cloudflare-email.net, colophon-protocol.org, <forwarding domain>; arrival from topmost Received; DNS live lookup
