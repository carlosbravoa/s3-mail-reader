# S3 Mail Reader

A local web reader for mail that Amazon SES delivers as raw RFC-822 objects into
an S3 bucket. Binds to `127.0.0.1` only. The sole write it performs is deleting a
message you explicitly ask it to delete.

Needs `s3:ListBucket`, `s3:GetObject` and — for the delete button —
`s3:DeleteObject` on the target buckets.

Don't have the SES side set up yet? **[SES-SETUP.md](SES-SETUP.md)** is a runbook
for pointing a domain's mail at an S3 bucket from scratch.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp mailboxes.example.json mailboxes.json   # then edit for your buckets
```

`mailboxes.json` is gitignored, since it names your real buckets. Starting without
it is the one hard failure: the reader has nothing to read, so it says what to copy
and exits rather than starting up broken.

## Run

```bash
./run.sh              # serves every mailbox in mailboxes.json
./restart.sh 5000     # same, restarting any instance already on that port
```

Then open <http://127.0.0.1:5000>.

`restart.sh` finds the running instance by listening port, not by command-line
pattern — `pkill -f app.py` matches the invoking shell too and kills it.

## Mailboxes

One instance serves them all; pick one from the dropdown. `mailboxes.json`:

```json
[
  { "id": "live",    "label": "example.com (live)",    "bucket": "example-mail",         "prefix": "inbox/" },
  { "id": "sent",    "label": "example.com (sent)",    "bucket": "example-mail",         "prefix": "sent/"  },
  { "id": "archive", "label": "old-domain (archive)",  "bucket": "old-domain-mail",      "prefix": ""       }
]
```

Add a bucket by adding an entry. Each mailbox keeps its own index cache, and the
first entry is the default view.

Setting `MAIL_BUCKET` overrides the file entirely with a single ad-hoc mailbox,
which is useful for pointing the reader at something one-off:

```bash
MAIL_BUCKET=some-bucket MAIL_PREFIX=inbox/ ./run.sh
```

## Per-address inboxes

The second dropdown filters by the address the message was actually delivered to,
so `you@example.com` and `contact@example.com` are separate inboxes in one bucket.

The address comes from the `Received:` header SES stamps on arrival, which ends
with `for <recipient>;`. That is the **envelope** recipient — the address SMTP
actually delivered to. `To:` is the wrong field: it misses BCCs, aliases, and list
mail, and it is trivially forged. Extraction resolves on 100/100 messages in the
archive it was built against, which turned out to hold ten distinct addresses.

Nothing configures this. The dropdown is built from whatever addresses appear in
the mailbox, so a new address shows up the first time it receives mail — no SES
rule change, and it works retroactively on mail already in the bucket.

The alternative was one SES receipt rule per address, each writing to its own S3
prefix. That gives hard separation but needs an infra change per address, writes a
copy per matching rule for multi-recipient mail, and cannot classify existing mail.

Uses whatever credentials your AWS CLI already has.

| Env var | Default | Meaning |
| --- | --- | --- |
| `MAIL_BUCKET` | *(unset)* | Single ad-hoc bucket, overriding `mailboxes.json` |
| `MAIL_PREFIX` | *(empty)* | Key prefix, e.g. `inbox/` |
| `MAIL_REGION` | `us-east-1` | Bucket region |
| `MAIL_PORT` | `5000` | Local port |
| `MAIL_HOST` | `127.0.0.1` | Bind address. Anything else publishes your mail — see below |

## How it works

Listing every message without downloading it is the whole trick. `ListObjectsV2`
returns key, size and `LastModified`; a ranged `GET` of the first 64 KB of each
object is enough to parse the header block. Those rows are cached in
`.index-<bucket>.json`, so only the first run pays for the fetch. Full bodies are
downloaded lazily when you open a message, with the last 32 kept in memory.

SES writes a large `X-SES-RECEIPT` header, which is why the header window is 64 KB
rather than the few KB you would otherwise need.

Message routes use Flask's `<path:key>` converter, not `<key>`. When `MAIL_PREFIX`
is set the object keys contain a slash, and the default string converter refuses
to match across path segments — every message would 404.

Dates come from the message's `Date:` header, falling back to the S3 object
timestamp when that header is missing or malformed — 91 of the 100 messages in the
archive have a usable one. Fallback dates are tagged in the UI.

## Views

- **Inbox** — two-pane list and reader. Filters compose: mailbox, then recipient
  address, then a sender/subject search.
- **Inventory** — senders grouped by domain, honouring the same filters. Written
  for account auditing: each domain is a service that may still have the address
  on file.
**New message** and **Refresh** sit in the list header, next to the mail they act
on, rather than in the top bar. They are hidden while selecting messages, since
the only thing to do in that mode is finish or cancel it.

- **New message** — compose from scratch rather than replying to something. See
  [Sending](#sending).
- **Refresh** — picks up new deliveries and returns you to the view you were in,
  filters intact. It re-lists the bucket but reuses cached header rows, so it
  costs one `ListObjectsV2` plus a fetch per genuinely new message.

`/api/mailboxes` returns every mailbox with its message count and address
breakdown, which is the quickest way to see what is where. `/api/refresh` is the
JSON equivalent of the Refresh button, for scripting.

A full re-read of every header (`get_index(force=True)`) is only for when the
parsing code itself changes; deleting the `.index-*.json` files achieves the same.

## Deleting

Two ways: the Delete button on an open message, or multi-select in the list.

Checkboxes are hidden until you press **Select** in the list header — the default
list stays clean. In selection mode a header checkbox takes the whole current view
(which respects the active filters, so "all mail to `sales@`" is one click), and
clicking a row picks it instead of opening it. **Cancel** leaves the mode and
clears the selection. The mode is remembered in `sessionStorage`, so it survives
the redirect after a delete and you can keep going.

The Delete button shows the live count and confirms before sending.

Bulk deletes go through `delete_objects`, so N messages cost one S3 call rather
than N, chunked at the API's 1000-key limit. Submitted keys are intersected with
the mailbox's own index first, so a key belonging to another mailbox is ignored
rather than deleted.

Deleting issues a plain `DeleteObject`. **Enable versioning on your buckets** and
that writes a delete marker instead of destroying anything: the message disappears
from `ListObjectsV2` and therefore from the reader, but the bytes remain. Pair it
with a lifecycle rule so the trash empties itself:

```bash
aws s3api put-bucket-versioning --bucket example-mail \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-lifecycle-configuration --bucket example-mail \
  --lifecycle-configuration '{"Rules":[{"ID":"purge-deleted-after-30d","Status":"Enabled",
    "Filter":{"Prefix":""},"NoncurrentVersionExpiration":{"NoncurrentDays":30},
    "Expiration":{"ExpiredObjectDeleteMarker":true}}]}'
```

Without versioning, the delete button destroys mail permanently. Set it up first.

Restoring means removing the delete marker. `restore.sh` does it:

```bash
./restore.sh example-mail                 # list what is deleted, with subjects
./restore.sh example-mail <key>           # restore one
./restore.sh example-mail --all           # restore everything deleted
```

Then hit Refresh. Verified working end to end.

### Why the endpoint is defended

The app has no authentication, so **any page open in your browser could POST to
`127.0.0.1:5000`** and delete your mail. That is ordinary CSRF, and localhost is
not exempt from it. Three layers:

- **POST only.** A GET that deletes is reachable by link prefetch, an `<img>` tag,
  or an iframe. `GET /delete` returns 405.
- **Per-process CSRF token**, rendered into the form and compared with
  `secrets.compare_digest`. A cross-origin page cannot read the token, because the
  same-origin policy blocks it from reading the page that contains it.
- **Origin check.** A cross-origin form POST carries an `Origin` header; anything
  that is not this app is rejected. A *missing* `Origin` is allowed through,
  because same-origin GETs and some legitimate clients omit it — the token, which
  a cross-origin page cannot read, is what actually holds the line. The Origin
  check is the second lock, not the first.

Tested: no token → 403, wrong token → 403, valid token with a foreign `Origin` →
403, `GET` → 405, genuine submission → 302.

## Sending

Two entry points, one form, one endpoint:

- **Reply**, on an open message, prefills everything from the message being answered.
- **New message**, in the header nav, starts from nothing.

Both send through SES (`SendRawEmail`) and file a copy under the `sent/` prefix —
which is just another mailbox in `mailboxes.json`, so sent mail is readable like
anything else.

A new message has no original to take a From address from, so it is suggested
from the recipient addresses seen across the inbound mailboxes. It defaults to
whichever address is selected in the dropdown, then to the last one that was
selected, then to the busiest address of the current mailbox — so composing while
viewing `sales@` sends as `sales@`, and clearing the filter afterwards still
sends as `sales@` rather than reverting to something unrelated. The memory is
per-process and resets when the reader restarts. The field stays free text, so
any address at a verified domain works.

Mailboxes with the `sent/` prefix are left out of the suggestions entirely: mail
we sent never travelled through SES inbound, so its "recipient" is the person we
wrote to rather than one of our own addresses, and those must never end up in From.

Three details of replying that are easy to get wrong and are handled:

- **Threading.** `In-Reply-To` and `References` are carried over from the
  original's `Message-ID`. Without them the recipient's client starts a new
  thread instead of continuing the conversation. Note these headers are *folded*
  onto continuation lines in the sent message — that is valid RFC 5322, not a bug.
- **From address.** The reply goes out as the address the original was delivered
  to, so mail to `sales@example.com` is answered by `sales@example.com` rather than
  hardcoded identity.
- **Reply target.** The original's `Reply-To` wins when present, `From` otherwise.

`Message-ID` and `Date` are set explicitly — `EmailMessage` generates neither, and
SES will not add a usable `Message-ID` of your own domain either.

The `/send` endpoint carries the same POST-only, CSRF-token and Origin checks as
`/delete`, for replies and new messages alike. Tested: no token → 403, foreign
`Origin` → 403.

### The sandbox

While the account lacks SES production access, mail can only go to **verified
identities** — in practice, addresses at your own verified domain. The form shows a
warning when this applies, and a rejection surfaces SES's own message:

```
Email address is not verified. The following identities failed the check
in region US-EAST-1: someone@gmail.com
```

Request production access from the SES console (Account dashboard → Request
production access) to send to anyone.

## Handling untrusted HTML

Mail bodies are hostile input, so they get four independent layers:

1. **Remote content is defused before sanitizing** — `img src` is rewritten to
   `data-blocked-src`, `background=` attributes are dropped, and `url(` in CSS is
   broken. Nothing phones home until you click "Load remote images".
2. **`bleach` allowlist** — a fixed tag/attribute set, with `CSSSanitizer` for
   inline styles. Scripts, iframes, objects, forms and event handlers are stripped.
3. **Sandboxed iframe** — the body renders in an iframe with only
   `allow-popups allow-popups-to-escape-sandbox`. No `allow-scripts`, no
   `allow-same-origin`, so the body cannot run code or reach the parent page.
4. **CSP** — the body response carries
   `default-src 'none'; img-src data:; style-src 'unsafe-inline'; form-action 'none'`.
   With images enabled, `img-src` widens to `https: http:` and nothing else.

Links are rewritten to `target="_blank" rel="noopener noreferrer"`.

Attachments are never rendered inline — they download with a sanitized filename
and `Content-Disposition: attachment`.

## When AWS is not set up

Credentials are the usual reason the reader cannot talk to S3, and they fail in
ordinary ways: none configured yet, an SSO session that lapsed overnight, a role
without access to the bucket. None of those are helped by a stack trace, so every
boto failure that reaches a route renders as a page naming the problem and the
command that fixes it — no credentials, expired credentials, denied access, wrong
region, missing bucket, unknown profile, or AWS simply unreachable. The status is
`503`, and `/api/*` returns the same explanation as JSON.

Nothing is cached from a failure, so fixing the credentials and hitting retry
works without restarting. Startup is the same: if the initial index fails the app
prints the explanation and serves anyway, so the browser can tell you what is
wrong. `restart.sh` will then report a failed start — that is the health check
doing its job; the reason is in `reader-<port>.log`.

## Light and dark

The button at the right of the header cycles **Auto → Light → Dark**. Auto follows
your system setting, and stays reachable so pinning a theme is not a one-way door.
The choice lives in `localStorage` and is applied from a script in `<head>`, before
the first paint — set it after paint and every page load flashes the other theme.

Message bodies stay on a white background in all three. Mail is authored assuming
one, and inverting it turns hand-written colours in the HTML unreadable. The
body is a sandboxed iframe with its own document, so it is themed separately by
`templates/body.html` regardless.

## Running it on another machine

[`deploy/`](deploy/) has a systemd unit and a walkthrough: a dedicated IAM user
scoped to the mail buckets and `SendRawEmail`, credentials outside the checkout,
and a service that survives reboots.

## Notes

- Bind address defaults to `127.0.0.1`. There is no authentication, so do not
  expose this port. Putting it on the internet means publishing your mail, and
  putting it on a shared LAN means publishing it to everyone on that LAN.
  `MAIL_HOST` exists for people who have read that sentence and decided anyway;
  an SSH tunnel gets you remote access without it.
- `.index-*.json` holds senders and subjects in cleartext. It is gitignored.
- Attachments and raw source are served with `X-Content-Type-Options: nosniff`.
  The content type comes from the message, so it is the sender's to choose.

## License

MIT — see [LICENSE](LICENSE).
