# Receiving mail for a domain into S3 with Amazon SES

A runbook for pointing a domain's mail at an S3 bucket, where this reader can see
it. Written from a real setup; every command here was actually run.

Work through it in order — each phase ends with a check, and a later phase failing
is almost always an earlier check that was skipped.

## Before you start

- **You must control the domain's DNS.** Not just the registration — you need to
  add MX and TXT records. This runbook assumes Route 53; any DNS host works, you
  just add the records by hand.
- **Pick your region first and never change it.** SES identities, receipt rules
  and production access are all *per-region*, and mail receiving is only offered
  in a subset of regions (`us-east-1`, `us-west-2` and `eu-west-1` have supported
  it longest — check current AWS docs before choosing something else). Everything
  below assumes one region throughout.
- **Receiving does not require production access.** The SES sandbox restricts
  *sending* only. You can receive mail on day one.

Set these once and paste the blocks as-is:

```bash
DOMAIN=example.com
BUCKET=example-mail
REGION=us-east-1
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
ZONE=$(aws route53 list-hosted-zones-by-name --dns-name "$DOMAIN" \
        --query "HostedZones[?Name=='${DOMAIN}.'].Id" --output text | cut -d/ -f3)
echo "account=$ACCOUNT zone=$ZONE"
```

## 1. Create the bucket

Mail is personal data. This bucket must never be public, and must not be the
bucket serving your website.

```bash
aws s3api create-bucket --bucket "$BUCKET" --region "$REGION"

aws s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=false,RestrictPublicBuckets=true

aws s3api put-bucket-encryption --bucket "$BUCKET" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
```

`BlockPublicPolicy=false` is deliberate — the next step attaches a policy granting
a service principal write access, and blocking public *policies* would reject it.
`RestrictPublicBuckets=true` still keeps the bucket itself private.

> If the region is not `us-east-1`, `create-bucket` also needs
> `--create-bucket-configuration LocationConstraint=$REGION`.

**Check:** `aws s3api get-bucket-policy-status --bucket "$BUCKET"` → `IsPublic: false`.

## 2. Let SES write to it

```bash
cat > /tmp/ses-bucket-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowSESInboundPuts",
    "Effect": "Allow",
    "Principal": { "Service": "ses.amazonaws.com" },
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::${BUCKET}/*",
    "Condition": {
      "StringEquals": { "AWS:SourceAccount": "${ACCOUNT}" },
      "StringLike": { "AWS:SourceArn": "arn:aws:ses:${REGION}:${ACCOUNT}:receipt-rule-set/*" }
    }
  }]
}
EOF
aws s3api put-bucket-policy --bucket "$BUCKET" --policy file:///tmp/ses-bucket-policy.json
```

The two conditions matter: without them any AWS account's SES could write into
your bucket. They scope it to your account's rule sets.

## 3. Verify the domain in SES

```bash
aws ses verify-domain-identity --domain "$DOMAIN" --region "$REGION"
aws ses verify-domain-dkim     --domain "$DOMAIN" --region "$REGION"
```

Keep both outputs. The first returns one verification token, the second three DKIM
tokens. DKIM is only needed for *sending*, but set it up now — it costs nothing and
you will want it later.

## 4. DNS

Four record types. Substitute the tokens from step 3.

```bash
cat > /tmp/dns.json <<EOF
{
  "Comment": "SES inbound mail for ${DOMAIN}",
  "Changes": [
    { "Action": "UPSERT", "ResourceRecordSet": {
        "Name": "${DOMAIN}.", "Type": "MX", "TTL": 300,
        "ResourceRecords": [{ "Value": "10 inbound-smtp.${REGION}.amazonaws.com" }] } },
    { "Action": "UPSERT", "ResourceRecordSet": {
        "Name": "_amazonses.${DOMAIN}.", "Type": "TXT", "TTL": 300,
        "ResourceRecords": [{ "Value": "\"VERIFICATION_TOKEN\"" }] } },
    { "Action": "UPSERT", "ResourceRecordSet": {
        "Name": "DKIM1._domainkey.${DOMAIN}.", "Type": "CNAME", "TTL": 300,
        "ResourceRecords": [{ "Value": "DKIM1.dkim.amazonses.com" }] } },
    { "Action": "UPSERT", "ResourceRecordSet": {
        "Name": "DKIM2._domainkey.${DOMAIN}.", "Type": "CNAME", "TTL": 300,
        "ResourceRecords": [{ "Value": "DKIM2.dkim.amazonses.com" }] } },
    { "Action": "UPSERT", "ResourceRecordSet": {
        "Name": "DKIM3._domainkey.${DOMAIN}.", "Type": "CNAME", "TTL": 300,
        "ResourceRecords": [{ "Value": "DKIM3.dkim.amazonses.com" }] } }
  ]
}
EOF
aws route53 change-resource-record-sets --hosted-zone-id "$ZONE" --change-batch file:///tmp/dns.json
```

The TXT value keeps its embedded quotes — Route 53 wants `"\"token\""`.

**Check** — records resolve within a minute or two, well before Route 53 stops
reporting `PENDING`:

```bash
dig +short MX  "$DOMAIN"
dig +short TXT "_amazonses.$DOMAIN"
```

**Check** — SES verification usually flips 2–3 minutes after the records resolve:

```bash
aws ses get-identity-verification-attributes --identities "$DOMAIN" --region "$REGION"
```

Wait for `"VerificationStatus": "Success"`. **Mail sent to an unverified domain is
rejected**, so do not test before this passes.

## 5. Receipt rule

Rules live in a *rule set*, and only one rule set is active at a time. Look before
you write — an existing rule may already match your domain:

```bash
aws ses describe-active-receipt-rule-set --region "$REGION"
```

If nothing is active yet:

```bash
aws ses create-receipt-rule-set --rule-set-name default-rule-set --region "$REGION"
aws ses set-active-receipt-rule-set --rule-set-name default-rule-set --region "$REGION"
```

Then add the rule:

```bash
cat > /tmp/rule.json <<EOF
{
  "Name": "${DOMAIN}-to-s3",
  "Enabled": true,
  "TlsPolicy": "Optional",
  "ScanEnabled": true,
  "Recipients": ["${DOMAIN}"],
  "Actions": [
    { "S3Action": { "BucketName": "${BUCKET}", "ObjectKeyPrefix": "inbox/" } },
    { "StopAction": { "Scope": "RuleSet" } }
  ]
}
EOF
aws ses create-receipt-rule --rule-set-name default-rule-set \
  --rule file:///tmp/rule.json --region "$REGION"
```

Three things worth understanding here:

**`Recipients: ["example.com"]` is a domain match, so it accepts every address at
the domain.** You never define individual addresses — `you@`, `sales@`, anything
you invent works immediately. Entries may also be a full address or a subdomain;
an *empty* `Recipients` is a catch-all across every verified domain.

**The `StopAction` is not optional if any other rule exists.** SES runs *all*
matching rules, not just the first. A pre-existing catch-all rule will also match
your domain and write a second copy into whatever bucket it targets. `StopAction`
ends evaluation after yours. Rules run in creation order; check the order in
`describe-active-receipt-rule-set` if in doubt.

**`ObjectKeyPrefix` is worth setting** even with one domain per bucket. It leaves
room for a `sent/` prefix alongside, which is how this reader stores replies.

## 6. Test it

```bash
aws s3 ls "s3://$BUCKET/inbox/"
```

Send a message from an external account — Gmail is ideal, since it exercises real
SPF/DKIM/DMARC rather than an AWS-internal path. It should land within seconds.

Confirm the message was authenticated on arrival:

```bash
aws s3 cp "s3://$BUCKET/inbox/<key>" - | grep -iA4 '^Authentication-Results:'
```

You want `spf=pass`, `dkim=pass`, `dmarc=pass`, plus SES's own
`X-SES-Spam-Verdict: PASS` and `X-SES-Virus-Verdict: PASS`.

You will also find an `AMAZON_SES_SETUP_NOTIFICATION` object. SES writes it once
when a receipt rule is created, to prove it can write to the bucket. It is not
mail; delete it whenever.

## 7. Versioning, before you delete anything

Do this **before** using the reader's delete button. Without versioning, deleting
is permanent.

```bash
aws s3api put-bucket-versioning --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled

aws s3api put-bucket-lifecycle-configuration --bucket "$BUCKET" \
  --lifecycle-configuration '{"Rules":[{"ID":"purge-deleted-after-30d","Status":"Enabled",
    "Filter":{"Prefix":""},"NoncurrentVersionExpiration":{"NoncurrentDays":30},
    "Expiration":{"ExpiredObjectDeleteMarker":true},
    "AbortIncompleteMultipartUpload":{"DaysAfterInitiation":7}}]}'
```

Deleting now writes a delete marker instead of destroying the object, and the
lifecycle rule empties the trash after 30 days. `restore.sh` undoes deletions
within that window.

Note this rule expires *noncurrent* versions only — it is the trash-emptier, not a
cap on live mail. With a catch-all accepting spam, consider a separate
`Expiration.Days` rule for current objects too.

## 8. Point the reader at it

```json
[
  { "id": "live", "label": "example.com", "bucket": "example-mail", "prefix": "inbox/" }
]
```

Receiving is done. Everything below is only needed if you also want to *send*.

---

# Sending

## 9. SPF, DMARC and a custom MAIL FROM

DKIM (step 3) already gives you an aligned signature. These improve deliverability
further.

```bash
aws ses set-identity-mail-from-domain --identity "$DOMAIN" \
  --mail-from-domain "mail.${DOMAIN}" \
  --behavior-on-mx-failure UseDefaultValue --region "$REGION"
```

Then publish:

```
TXT   example.com.          "v=spf1 include:amazonses.com ~all"
TXT   _dmarc.example.com.   "v=DMARC1; p=none; rua=mailto:dmarc@example.com; fo=1"
MX    mail.example.com.     10 feedback-smtp.us-east-1.amazonses.com
TXT   mail.example.com.     "v=spf1 include:amazonses.com ~all"
```

**Why the MAIL FROM subdomain.** By default SES uses `amazonses.com` as the
envelope sender. SPF then *passes* but does not *align* with your From domain, so
DMARC has to lean entirely on DKIM. Pointing MAIL FROM at a subdomain of your own
domain gives you SPF alignment as well.

**The `mail.` MX does not disturb your inbound MX.** They are different names.
Inbound mail keeps flowing to S3.

`UseDefaultValue` means that if those records ever vanish, SES falls back to its
own domain and mail still goes out — it degrades rather than failing closed.

**Check:**

```bash
aws ses get-identity-mail-from-domain-attributes --identities "$DOMAIN" --region "$REGION"
```

Wait for `Success`, then send one message and confirm in the received copy that
`Return-Path` now reads `@mail.example.com` and `Authentication-Results` shows
`spf=pass` with an aligned `envelope-from`.

Start DMARC at `p=none` (monitor only). Tighten to `quarantine`, then `reject`,
once the `rua` reports show only your own mail passing. Pointing `rua` at an
address on the same domain means the reports arrive in your own bucket.

## 10. Bounces and complaints

Set this up *before* requesting production access — the reviewer asks about it.

```bash
ARN=$(aws sns create-topic --name ses-notifications --region "$REGION" \
        --query TopicArn --output text)

for T in Bounce Complaint Delivery; do
  aws ses set-identity-notification-topic --identity "$DOMAIN" \
    --notification-type $T --sns-topic "$ARN" --region "$REGION"
done

aws sns subscribe --topic-arn "$ARN" --protocol email \
  --notification-endpoint you@somewhere-else.com --region "$REGION"
```

Confirm the subscription from the email SNS sends, or it silently expires after
three days.

Leave SES email feedback forwarding **enabled** as well. A bounce then arrives
twice: as JSON on SNS, and as an ordinary message to your `From` address — which
lands in your bucket and is readable in the reader with no extra tooling.

## 11. Production access

Until granted, sending only reaches **verified identities** — in practice,
addresses at your own domain. Receiving is unaffected.

Request it in the SES console → **Account dashboard** → *Request production
access*. **Confirm the console's region selector matches your region first**;
access is granted per-region and requesting it in the wrong one leaves your real
setup sandboxed.

Answer the bounce/complaint question with what you built in step 10, and mention
that DKIM and a custom MAIL FROM are configured so SPF and DKIM both align.

---

# Troubleshooting

**"No identities found" in the console.** Wrong region. Identities are per-region;
check the selector. `aws sesv2 list-email-identities --region <r>` across a few
regions will show you where things actually live.

**Console offers to "verify an email address".** You do not need one. A *domain*
identity already covers every address at it. Address verification also emails you
a confirmation link, which is awkward when mail lands in S3 rather than a mailbox.

**Mail is rejected / bounces.** Domain verification is not `Success`, or the MX
record is missing or points at the wrong region's endpoint.

**Messages written twice.** Two receipt rules match. Add a `StopAction` to yours,
or scope the other rule's `Recipients`.

**Nothing arrives and DNS looks right.** Confirm the *registrar's* nameservers
point at the hosted zone you edited — `dig +short NS example.com` versus the
zone's own NS record. Editing a zone the registry does not delegate to is silent
and total.

**`X-SES-RECEIPT` looks like it holds the recipient.** It is encrypted and
useless. The envelope recipient is in the `Received:` header SES stamps, which
ends `for <address>;`. That is what this reader parses to split per-address
inboxes.

**Sending fails with "Email address is not verified".** The SES sending sandbox.
Either the recipient is not a verified identity, or you need production access.
