# Running the reader as a service

For a machine that should keep serving the reader across reboots. Written for
systemd; adapt paths as needed.

## 1. An IAM user for just this

Do not deploy your own credentials. The reader needs read/write on the mail
buckets and `SendRawEmail` as your verified domains — nothing else. Substitute
your buckets, account id and region:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "ListTheMailBuckets", "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketLocation"],
      "Resource": ["arn:aws:s3:::example-mail", "arn:aws:s3:::old-domain-mail"] },
    { "Sid": "ReadFileAndDeleteMail", "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject",
                 "s3:DeleteObject", "s3:DeleteObjectVersion"],
      "Resource": ["arn:aws:s3:::example-mail/*", "arn:aws:s3:::old-domain-mail/*"] },
    { "Sid": "SendOnlyAsOwnVerifiedDomains", "Effect": "Allow",
      "Action": "ses:SendRawEmail",
      "Resource": ["arn:aws:ses:us-east-1:ACCOUNT:identity/example.com"] },
    { "Sid": "ReadSandboxStatusForTheComposeWarning", "Effect": "Allow",
      "Action": "ses:GetAccount", "Resource": "*" }
  ]
}
```

```bash
aws iam create-policy --policy-name mailreader-service \
  --policy-document file://policy.json
aws iam create-user --user-name mailreader-service
aws iam attach-user-policy --user-name mailreader-service \
  --policy-arn arn:aws:iam::ACCOUNT:policy/mailreader-service
aws iam create-access-key --user-name mailreader-service
```

Two of those permissions deserve a second look before you grant them:

- **`s3:DeleteObjectVersion`** is what `restore.sh` needs to remove a delete
  marker. It is also what permanently destroys an old version, so it undoes the
  safety net versioning gives you. Drop it if the deployed machine does not need
  to restore, and run restores from a trusted machine instead.
- **`ses:SendRawEmail`** lets that machine send mail as your domain. Drop it for
  a read-only viewer; Reply and New message then fail, and nothing else does.

## 2. Install

```bash
sudo useradd --system --home /opt/mailreader --shell /usr/sbin/nologin mailreader
sudo git clone https://github.com/carlosbravoa/s3-mail-reader /opt/mailreader
cd /opt/mailreader
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt
sudo cp mailboxes.example.json mailboxes.json   # then edit for your buckets

sudo install -d -m 700 -o mailreader -g mailreader /etc/mailreader
sudo install -m 600 -o mailreader -g mailreader credentials /etc/mailreader/credentials
sudo chown -R mailreader:mailreader /opt/mailreader
```

`/etc/mailreader/credentials` is an ordinary AWS credentials file:

```ini
[default]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
region = us-east-1
```

## 3. Start it

```bash
sudo cp deploy/mailreader.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mailreader
systemctl status mailreader
journalctl -u mailreader -f
```

The first start indexes every bucket, so give it a moment before the page loads.

## 4. Reaching it

The unit ships with `MAIL_HOST=127.0.0.1`, so the reader is reachable only from
that machine. From your laptop:

```bash
ssh -L 5000:127.0.0.1:5000 thatmachine
```

then open <http://127.0.0.1:5000>. Nothing is exposed to the network.

### Exposing it on the LAN instead

Setting `MAIL_HOST=0.0.0.0` in the unit makes it reachable from every device on
your network. **The app has no authentication.** Anyone who reaches the port —
a guest phone, a compromised smart TV, anyone who joins the wifi — can read every
message, delete mail, and send as your domain. There is no login to stop them.

If you accept that, at least bind to the LAN interface rather than everything,
and firewall the port to your own subnet:

```ini
Environment=MAIL_HOST=192.168.1.50
```

```bash
sudo ufw allow from 192.168.1.0/24 to any port 5000 proto tcp
```

The CSRF Origin check follows whatever address the request arrived on, so this
needs no other change.

## Notes

- **One process only.** The index cache, the CSRF token and the remembered From
  address all live in process memory. Behind gunicorn or similar, use a single
  worker (`-w 1`) or logins will fail unpredictably as requests land on different
  workers.
- This runs Flask's development server. That is fine for one person on a trusted
  network and is what the unit does; it is not a hardened public web server, and
  the reader should not be one.
- `ProtectSystem=strict` makes the whole filesystem read-only except
  `ReadWritePaths=/opt/mailreader`, which the index cache needs. Move the checkout
  and you must move that line too.
