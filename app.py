#!/usr/bin/env python3
"""Local web reader for SES-delivered mail archived in S3.

Serves any number of mailboxes (bucket + prefix pairs) defined in
mailboxes.json, and splits each one by recipient address. Read-only: it never
writes to S3 and binds to 127.0.0.1 only.
"""

import email
import email.parser
import email.policy
import json
import mimetypes
import os
import re
import secrets
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parsedate_to_datetime
from functools import lru_cache
from pathlib import Path

import bleach
import boto3
from bleach.css_sanitizer import CSSSanitizer
from botocore.exceptions import BotoCoreError, ClientError
from flask import (Flask, Response, abort, jsonify, redirect, render_template,
                   request, url_for)

HERE = Path(__file__).parent
REGION = os.environ.get("MAIL_REGION", "us-east-1")
PORT = int(os.environ.get("MAIL_PORT", "5000"))

# SES prepends a large X-SES-RECEIPT blob, so give the header block room.
HEADER_BYTES = 65536

# The app has no authentication, so any page open in the browser could POST to
# 127.0.0.1 and delete mail. A per-process token the attacker cannot read
# (same-origin policy blocks it) plus an Origin check closes that off.
CSRF_TOKEN = secrets.token_urlsafe(32)

app = Flask(__name__)


@app.context_processor
def inject_csrf():
    return {"csrf_token": CSRF_TOKEN}


def check_csrf():
    if not secrets.compare_digest(request.form.get("csrf", ""), CSRF_TOKEN):
        abort(403)
    origin = request.headers.get("Origin")
    if origin and origin not in (f"http://127.0.0.1:{PORT}",
                                 f"http://localhost:{PORT}"):
        abort(403)

# --------------------------------------------------------------------------
# AWS failures
# --------------------------------------------------------------------------

# Credentials are the usual reason this app cannot talk to S3: none configured,
# an SSO session that lapsed overnight, or a role without access to the bucket.
# A stack trace helps with none of those, so every boto failure is translated
# into a page that names the problem and the command that fixes it.

# Matched on class name rather than by import: which of these botocore defines
# varies by version, and an ImportError at startup would defeat the purpose.
_NO_CREDENTIALS = {"NoCredentialsError", "PartialCredentialsError",
                   "CredentialRetrievalError", "InvalidConfigError"}
_STALE_SSO = {"SSOError", "SSOTokenLoadError", "TokenRetrievalError",
              "UnauthorizedSSOTokenError"}
_UNREACHABLE = {"EndpointConnectionError", "ConnectTimeoutError",
                "ReadTimeoutError", "ConnectionError"}

_LOGIN = "aws configure          # or, for SSO: aws sso login"

# S3 error codes that mean "the credentials themselves are the problem".
_BAD_CREDS = {"ExpiredToken", "ExpiredTokenException", "RequestExpired",
              "InvalidAccessKeyId", "InvalidClientTokenId", "AuthFailure",
              "SignatureDoesNotMatch", "UnrecognizedClientException",
              "InvalidToken", "TokenRefreshRequired"}
_FORBIDDEN = {"AccessDenied", "AccessDeniedException", "AllAccessDisabled",
              "InvalidAccessKeyId.NotFound", "Forbidden"}
_WRONG_REGION = {"PermanentRedirect", "AuthorizationHeaderMalformed",
                 "IllegalLocationConstraintException"}


def explain_aws(exc):
    """Turn a boto failure into a title, an explanation and a fix."""
    name = type(exc).__name__

    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        code = err.get("Code", "") or ""
        message = err.get("Message", "") or str(exc)
        if code in _BAD_CREDS:
            return {"title": "AWS credentials rejected",
                    "detail": f"AWS refused the request ({code}). The credentials "
                              "are configured but expired or wrong.",
                    "command": _LOGIN}
        if code in _FORBIDDEN:
            return {"title": "Access denied",
                    "detail": f"The credentials work, but are not allowed to do "
                              f"this: {message}",
                    "command": "The reader needs s3:ListBucket and s3:GetObject on "
                               "the bucket, s3:DeleteObject to delete, and "
                               "ses:SendRawEmail to send."}
        if code in _WRONG_REGION:
            return {"title": "Wrong region",
                    "detail": f"The bucket does not live in {REGION}: {message}",
                    "command": "MAIL_REGION=<bucket-region> ./run.sh"}
        if code in ("NoSuchBucket", "404"):
            return {"title": "Bucket not found",
                    "detail": f"No such bucket in {REGION}. Check the names in "
                              "mailboxes.json.",
                    "command": "aws s3 ls"}
        return {"title": "AWS request failed",
                "detail": f"{code}: {message}" if code else message,
                "command": ""}

    if name in _NO_CREDENTIALS:
        return {"title": "No AWS credentials",
                "detail": "The reader uses whatever credentials your AWS CLI has, "
                          f"and found none it could use ({exc}).",
                "command": _LOGIN}
    if name in _STALE_SSO:
        return {"title": "SSO session expired",
                "detail": f"The cached SSO token is no longer valid ({exc}).",
                "command": "aws sso login"}
    if name == "ProfileNotFound":
        return {"title": "AWS profile not found",
                "detail": f"{exc}. AWS_PROFILE names a profile that is not in "
                          "your AWS config.",
                "command": "aws configure list-profiles"}
    if name == "NoRegionError":
        return {"title": "No AWS region",
                "detail": "No region is configured and none was passed.",
                "command": "MAIL_REGION=us-east-1 ./run.sh"}
    if name in _UNREACHABLE:
        return {"title": "Cannot reach AWS",
                "detail": f"The request never got there ({exc}). This one is "
                          "usually the network, not you.",
                "command": ""}

    return {"title": "AWS request failed", "detail": str(exc), "command": ""}


@app.errorhandler(BotoCoreError)
@app.errorhandler(ClientError)
def aws_error(exc):
    """Any boto failure that reaches a route renders as an explanation.

    Deliberately not a base.html page: the header builds its dropdowns from the
    index, so rendering it here would hit S3 again and fail a second time.
    """
    problem = explain_aws(exc)
    if request.path.startswith("/api/"):
        return jsonify(error=problem["title"], detail=problem["detail"],
                       fix=problem["command"]), 503
    return render_template("aws_error.html", **problem), 503


# --------------------------------------------------------------------------
# S3 access
# --------------------------------------------------------------------------

_local = threading.local()


def s3():
    """One boto3 client per thread; clients aren't meant to be shared."""
    if not hasattr(_local, "client"):
        _local.client = boto3.client("s3", region_name=REGION)
    return _local.client


def fetch_head(bucket, key):
    """First HEADER_BYTES of an object — enough to parse the header block."""
    resp = s3().get_object(Bucket=bucket, Key=key,
                           Range=f"bytes=0-{HEADER_BYTES - 1}")
    return resp["Body"].read()


@lru_cache(maxsize=32)
def fetch_raw(bucket, key):
    return s3().get_object(Bucket=bucket, Key=key)["Body"].read()


# --------------------------------------------------------------------------
# Header parsing
# --------------------------------------------------------------------------

_header_parser = email.parser.BytesParser(policy=email.policy.default)

# SES stamps its own Received: header with the envelope recipient. That is the
# address the message was actually delivered to — To: misses BCCs, aliases and
# list mail. Verified to resolve on every message of a real 100-message archive.
_RECEIVED_FOR = re.compile(r"\bfor\s+<?([^\s<>;]+@[^\s<>;]+)>?\s*;", re.I)


def hdr(msg, name, default=""):
    """Header access that survives malformed mail."""
    try:
        value = msg[name]
        return str(value).strip() if value is not None else default
    except Exception:
        try:
            raw = msg.get_all(name, [])
            return str(raw[0]).strip() if raw else default
        except Exception:
            return default


def split_addr(value):
    """Return (display name, address) without choking on junk."""
    if not value:
        return "", ""
    try:
        from email.utils import parseaddr
        name, addr = parseaddr(value)
        return name.strip(), addr.strip().lower()
    except Exception:
        return "", value.strip().lower()


def envelope_recipient(msg):
    """The address SES delivered to, from its own Received: header."""
    try:
        received = msg.get_all("Received", [])
    except Exception:
        received = []
    # SES's hop is the one mentioning amazonaws.com; prefer it, but fall back to
    # any hop with a usable "for" clause.
    fallback = ""
    for hop in received:
        text = str(hop)
        hit = _RECEIVED_FOR.search(text)
        if not hit:
            continue
        addr = hit.group(1).lower()
        if "amazonaws.com" in text:
            return addr
        fallback = fallback or addr
    if fallback:
        return fallback
    # Messages we sent ourselves never travelled through SES inbound, so they
    # have no Received: hop. Group those by who they went to.
    return split_addr(hdr(msg, "To"))[1]


# --------------------------------------------------------------------------
# Mailboxes
# --------------------------------------------------------------------------

class Mailbox:
    def __init__(self, spec):
        self.id = spec["id"]
        self.label = spec.get("label", spec["id"])
        self.bucket = spec["bucket"]
        self.prefix = spec.get("prefix", "")
        slug = re.sub(r"[^\w.\-]", "_", f"{self.bucket}-{self.prefix}".strip("-"))
        self.index_path = HERE / f".index-{slug}.json"
        self._index = None
        self._lock = threading.Lock()

    # -- indexing ----------------------------------------------------------

    def list_objects(self):
        out = []
        paginator = s3().get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
            for obj in page.get("Contents", []):
                if obj["Key"].endswith("/"):
                    continue
                out.append({
                    "key": obj["Key"],
                    "size": obj["Size"],
                    "last_modified": obj["LastModified"].isoformat(),
                })
        return out

    def index_entry(self, obj):
        key = obj["key"]
        entry = {
            "key": key,
            "size": obj["size"],
            "date": obj["last_modified"],
            "date_from_header": False,
            "from_name": "",
            "from_addr": "",
            "to": "",
            "recipient": "",
            "subject": "(no subject)",
            "multipart": False,
            "spam": "",
            "virus": "",
        }
        try:
            msg = _header_parser.parsebytes(fetch_head(self.bucket, key),
                                            headersonly=True)
        except Exception as exc:
            entry["subject"] = f"(unparseable headers: {exc})"
            return entry

        name, addr = split_addr(hdr(msg, "From"))
        entry["from_name"] = name
        entry["from_addr"] = addr
        entry["to"] = hdr(msg, "To")
        entry["recipient"] = envelope_recipient(msg)
        entry["subject"] = hdr(msg, "Subject") or "(no subject)"
        entry["multipart"] = "multipart/mixed" in hdr(msg, "Content-Type").lower()
        entry["spam"] = hdr(msg, "X-SES-Spam-Verdict")
        entry["virus"] = hdr(msg, "X-SES-Virus-Verdict")

        raw_date = hdr(msg, "Date")
        if raw_date:
            try:
                entry["date"] = parsedate_to_datetime(raw_date).isoformat()
                entry["date_from_header"] = True
            except Exception:
                pass  # keep the S3 LastModified fallback
        return entry

    def load_cache(self):
        if not self.index_path.exists():
            return {}
        try:
            rows = json.loads(self.index_path.read_text())
            # Drop rows from before recipient extraction existed.
            return {r["key"]: r for r in rows if "recipient" in r}
        except Exception:
            return {}

    def build_index(self, force=False):
        cache = {} if force else self.load_cache()
        objects = self.list_objects()
        missing = [o for o in objects if o["key"] not in cache]

        if missing:
            with ThreadPoolExecutor(max_workers=16) as pool:
                for entry in pool.map(self.index_entry, missing):
                    cache[entry["key"]] = entry

        live = {o["key"] for o in objects}
        entries = [e for k, e in cache.items() if k in live]
        entries.sort(key=lambda e: e["date"], reverse=True)
        self.index_path.write_text(json.dumps(entries, indent=1))
        return entries

    def get_index(self, force=False, rescan=False):
        """rescan re-lists the bucket but keeps cached header rows, so picking up
        new mail costs one ListObjectsV2 plus a fetch per genuinely new key.
        force additionally discards the cache and re-reads every header."""
        with self._lock:
            if self._index is None or force or rescan:
                self._index = self.build_index(force=force)
            return self._index

    def get_entry(self, key):
        for entry in self.get_index():
            if entry["key"] == key:
                return entry
        return None

    def forget(self, key):
        """Drop one entry from the index after its object has been deleted."""
        with self._lock:
            if self._index is not None:
                self._index = [e for e in self._index if e["key"] != key]
                self.index_path.write_text(json.dumps(self._index, indent=1))

    def addresses(self):
        """Recipient addresses present in this mailbox, most mail first."""
        counts = {}
        for entry in self.get_index():
            addr = entry["recipient"] or "(unknown)"
            counts[addr] = counts.get(addr, 0) + 1
        return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


class ConfigError(Exception):
    """mailboxes.json is missing or unusable. Nothing works without it."""


def load_mailboxes():
    env_bucket = os.environ.get("MAIL_BUCKET")
    if env_bucket:
        # Ad-hoc single mailbox, for pointing the reader somewhere one-off.
        return [Mailbox({"id": "env", "label": env_bucket,
                         "bucket": env_bucket,
                         "prefix": os.environ.get("MAIL_PREFIX", "")})]

    path = HERE / "mailboxes.json"
    if not path.exists():
        # The first thing a fresh clone hits, so say what to do about it.
        raise ConfigError(
            "mailboxes.json is missing. Copy the example and edit it for your "
            "buckets:\n"
            "    cp mailboxes.example.json mailboxes.json\n"
            "  Or skip the file and point the reader at one bucket:\n"
            "    MAIL_BUCKET=your-bucket MAIL_PREFIX=inbox/ ./run.sh")
    try:
        specs = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ConfigError(f"mailboxes.json is not valid JSON: {exc}")

    if not isinstance(specs, list) or not specs:
        raise ConfigError("mailboxes.json must be a non-empty list of mailboxes. "
                          "See mailboxes.example.json.")
    for i, spec in enumerate(specs, 1):
        if not isinstance(spec, dict):
            raise ConfigError(f"mailbox {i} in mailboxes.json is not an object.")
        absent = [k for k in ("id", "bucket") if not spec.get(k)]
        if absent:
            raise ConfigError(f"mailbox {i} in mailboxes.json is missing "
                              f"{' and '.join(absent)}.")
    return [Mailbox(s) for s in specs]


try:
    MAILBOXES = load_mailboxes()
except ConfigError as exc:
    # A traceback here helps nobody: the fix is always editing a config file.
    print(f"Cannot start: {exc}", file=sys.stderr)
    raise SystemExit(1)

BY_ID = {m.id: m for m in MAILBOXES}


def current_mailbox():
    return BY_ID.get(request.args.get("mb", ""), MAILBOXES[0])


# --------------------------------------------------------------------------
# Body rendering
# --------------------------------------------------------------------------

ALLOWED_TAGS = [
    "a", "abbr", "b", "blockquote", "br", "caption", "center", "code", "col",
    "colgroup", "dd", "div", "dl", "dt", "em", "font", "h1", "h2", "h3", "h4",
    "h5", "h6", "hr", "i", "img", "li", "ol", "p", "pre", "small", "span",
    "strong", "sub", "sup", "table", "tbody", "td", "tfoot", "th", "thead",
    "tr", "u", "ul",
]

ALLOWED_ATTRS = {
    "*": ["align", "bgcolor", "class", "colspan", "dir", "height", "rowspan",
          "style", "title", "valign", "width"],
    "a": ["href", "name", "rel", "target", "title"],
    "img": ["alt", "data-blocked-src", "height", "src", "width"],
    "font": ["color", "face", "size"],
}

_css_sanitizer = CSSSanitizer()

_IMG_SRC = re.compile(r"(<img\b[^>]*?)\bsrc\s*=", re.I)
_BACKGROUND_ATTR = re.compile(r"\sbackground\s*=\s*(\"[^\"]*\"|'[^']*'|\S+)", re.I)
_CSS_URL = re.compile(r"url\s*\(", re.I)


def block_remote(html):
    """Defuse anything that would phone home when the body renders."""
    html = _IMG_SRC.sub(r"\1data-blocked-src=", html)
    html = _BACKGROUND_ATTR.sub(" ", html)
    html = _CSS_URL.sub("none-(", html)
    return html


def sanitize(html, allow_images):
    if not allow_images:
        html = block_remote(html)
    clean = bleach.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRS,
        css_sanitizer=_css_sanitizer,
        strip=True,
    )
    # Every surviving link opens in a new tab, severed from this page.
    return clean.replace("<a ", '<a target="_blank" rel="noopener noreferrer" ')


def parse_full(bucket, key):
    try:
        return email.message_from_bytes(fetch_raw(bucket, key),
                                        policy=email.policy.default)
    except ClientError as exc:
        # Only a genuinely absent object is a 404. Anything else — expired
        # credentials, a denied role — must reach the handler that explains it,
        # or a credentials problem masquerades as missing mail.
        if exc.response.get("Error", {}).get("Code") in ("NoSuchKey", "NoSuchVersion", "404"):
            abort(404)
        raise


def extract_bodies(msg):
    html = text = None
    for pref, slot in (("html", "html"), ("plain", "text")):
        try:
            part = msg.get_body(preferencelist=(pref,))
            if part is not None:
                content = part.get_content()
                if slot == "html":
                    html = content
                else:
                    text = content
        except Exception:
            pass
    return html, text


def walk_attachments(msg):
    """(walk index, filename, content type, size) for each attached part."""
    out = []
    for i, part in enumerate(msg.walk()):
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if disposition != "attachment" and not filename:
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        out.append({
            "idx": i,
            "filename": filename or f"part-{i}",
            "content_type": part.get_content_type(),
            "size": len(payload),
        })
    return out


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

def _nav(mb, **extra):
    """Query args that must survive every link."""
    args = {"mb": mb.id}
    args.update({k: v for k, v in extra.items() if v})
    return args


@app.route("/")
def inbox():
    mb = current_mailbox()
    query = request.args.get("q", "").strip()
    address = request.args.get("to", "").strip()
    selected_key = request.args.get("sel", "")
    remember_address(address)

    entries = mb.get_index()
    total = len(entries)

    if address:
        entries = [e for e in entries if (e["recipient"] or "(unknown)") == address]
    if query:
        needle = query.lower()
        entries = [e for e in entries
                   if needle in e["subject"].lower()
                   or needle in e["from_addr"].lower()
                   or needle in e["from_name"].lower()]

    message = None
    if selected_key:
        entry = mb.get_entry(selected_key)
        if entry is None:
            abort(404)
        msg = parse_full(mb.bucket, selected_key)
        html, _text = extract_bodies(msg)
        message = {
            "entry": entry,
            "has_html": html is not None,
            "attachments": walk_attachments(msg),
            "cc": hdr(msg, "Cc"),
            "reply_to": hdr(msg, "Reply-To"),
            "allow_images": request.args.get("images") == "1",
        }

    return render_template(
        "inbox.html", entries=entries, query=query, address=address,
        selected_key=selected_key, message=message, total=total,
        mailboxes=MAILBOXES, mb=mb, addresses=mb.addresses(), nav=_nav,
    )


@app.route("/m/<path:key>/body")
def message_body(key):
    """Sanitized body, served standalone so it can live in a locked-down iframe."""
    mb = current_mailbox()
    if mb.get_entry(key) is None:
        abort(404)
    allow_images = request.args.get("images") == "1"
    msg = parse_full(mb.bucket, key)
    html, text = extract_bodies(msg)

    if html is not None:
        body = sanitize(html, allow_images)
    elif text is not None:
        body = f"<pre>{bleach.clean(text)}</pre>"
    else:
        body = "<p><em>This message has no readable text or HTML body.</em></p>"

    page = render_template("body.html", body=body)
    img_src = "img-src data: https: http:;" if allow_images else "img-src data:;"
    resp = Response(page, mimetype="text/html")
    resp.headers["Content-Security-Policy"] = (
        f"default-src 'none'; {img_src} style-src 'unsafe-inline'; "
        "font-src data:; form-action 'none'; base-uri 'none'"
    )
    return resp


@app.route("/m/<path:key>/attachment/<int:idx>")
def attachment(key, idx):
    mb = current_mailbox()
    if mb.get_entry(key) is None:
        abort(404)
    msg = parse_full(mb.bucket, key)
    for i, part in enumerate(msg.walk()):
        if i != idx:
            continue
        payload = part.get_payload(decode=True) or b""
        filename = part.get_filename() or f"part-{idx}"
        filename = re.sub(r"[^\w.\-]", "_", filename)
        guessed = part.get_content_type() or mimetypes.guess_type(filename)[0]
        return Response(
            payload,
            mimetype=guessed or "application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"',
                     # The type comes from the message, so it is attacker-chosen.
                     # Disposition already forces a download; this stops a browser
                     # second-guessing the type and rendering it anyway.
                     "X-Content-Type-Options": "nosniff"},
        )
    abort(404)


@app.route("/m/<path:key>/raw")
def raw_source(key):
    mb = current_mailbox()
    if mb.get_entry(key) is None:
        abort(404)
    # content_type, not mimetype: mimetype appends its own charset, and passing a
    # parameterised value there yields "charset=utf-8; charset=utf-8".
    return Response(fetch_raw(mb.bucket, key),
                    content_type="text/plain; charset=utf-8",
                    headers={"X-Content-Type-Options": "nosniff"})


@app.route("/inventory")
def inventory():
    """Senders grouped by domain — the account-audit view."""
    mb = current_mailbox()
    address = request.args.get("to", "").strip()
    remember_address(address)

    entries = mb.get_index()
    if address:
        entries = [e for e in entries if (e["recipient"] or "(unknown)") == address]

    domains = {}
    for entry in entries:
        addr = entry["from_addr"]
        domain = addr.rsplit("@", 1)[-1] if "@" in addr else "(unknown)"
        bucket = domains.setdefault(domain, {
            "domain": domain, "count": 0, "latest": "", "senders": set(),
            "subjects": [],
        })
        bucket["count"] += 1
        bucket["senders"].add(addr)
        bucket["latest"] = max(bucket["latest"], entry["date"])
        if len(bucket["subjects"]) < 5:
            bucket["subjects"].append(entry["subject"])

    rows = sorted(domains.values(), key=lambda d: (-d["count"], d["domain"]))
    for row in rows:
        row["senders"] = sorted(row["senders"])
    return render_template("inventory.html", rows=rows, total=len(entries),
                           mailboxes=MAILBOXES, mb=mb, address=address,
                           addresses=mb.addresses(), nav=_nav, query="")


# The address dropdown is nominally a filter, but picking one also says which of
# our addresses we are working as. Remembering the last one makes it the default
# From for a message composed later, once the filter has been cleared.
_last_address = None


def remember_address(address):
    global _last_address
    if address:
        _last_address = address


def own_addresses():
    """Addresses of ours that could plausibly send, most mail first.

    Only inbound mailboxes count: in a sent/ mailbox there is no SES Received:
    hop, so the recipient falls back to To: — the people we wrote to, not us.
    """
    counts = {}
    for box in MAILBOXES:
        if box.prefix == "sent/":
            continue
        for addr, count in box.addresses():
            if "@" in addr:
                counts[addr] = counts.get(addr, 0) + count
    return sorted(counts, key=lambda a: (-counts[a], a))


@app.route("/compose")
def compose_form():
    """A new message, not tied to anything in the archive."""
    mb = current_mailbox()
    options = own_addresses()

    # Send as whichever address we are looking at: the one filtered on now, else
    # the last one filtered on, else the busiest address of this mailbox — never
    # an address belonging to some other mailbox while a plausible one exists.
    address = request.args.get("to", "").strip()
    local = [a for a, _ in mb.addresses() if a in options]
    from_addr = next((a for a in (address, _last_address) if a and a in options),
                     (local or options or [""])[0])

    return render_template(
        "compose.html", mb=mb, mailboxes=MAILBOXES, addresses=mb.addresses(),
        address=address, query="", nav=_nav, entry=None,
        reply_to="", from_addr=from_addr, from_options=options,
        subject="", quoted="", message_id="", references="",
        sandbox=not production_access(),
    )


@app.route("/reply/<path:key>")
def reply_form(key):
    """Compose a reply, prefilled from the message being answered."""
    mb = current_mailbox()
    entry = mb.get_entry(key)
    if entry is None:
        abort(404)
    msg = parse_full(mb.bucket, key)

    # Answer Reply-To when the sender asked for it, otherwise From.
    target = split_addr(hdr(msg, "Reply-To"))[1] or entry["from_addr"]

    subject = entry["subject"]
    if not subject.lower().startswith("re:"):
        subject = f"Re: {subject}"

    _html, text = extract_bodies(msg)
    quoted = ""
    if text:
        who = entry["from_name"] or entry["from_addr"]
        body = "\n".join(f"> {line}" for line in text.strip().splitlines())
        quoted = f"\n\nOn {shortdate(entry['date'])}, {who} wrote:\n{body}\n"

    return render_template(
        "compose.html", mb=mb, mailboxes=MAILBOXES, addresses=mb.addresses(),
        address="", query="", nav=_nav, entry=entry,
        reply_to=target,
        # Reply as the address it was sent to, not a hardcoded one.
        from_addr=entry["recipient"] or "",
        from_options=own_addresses(),
        subject=subject, quoted=quoted,
        message_id=hdr(msg, "Message-ID"),
        references=" ".join(x for x in (hdr(msg, "References"),
                                        hdr(msg, "Message-ID")) if x).strip(),
        sandbox=not production_access(),
    )


@lru_cache(maxsize=1)
def production_access():
    """False while the account is in the SES sending sandbox."""
    try:
        client = boto3.client("sesv2", region_name=REGION)
        return bool(client.get_account().get("ProductionAccessEnabled"))
    except Exception:
        return False


@app.route("/send", methods=["POST"])
def send_reply():
    check_csrf()
    mb = BY_ID.get(request.form.get("mb", ""))
    if mb is None:
        abort(404)

    from_addr = request.form.get("from", "").strip()
    to_addr = request.form.get("to", "").strip()
    subject = request.form.get("subject", "").strip()
    body = request.form.get("body", "")

    if not (from_addr and to_addr):
        return render_template("sent.html", mb=mb, mailboxes=MAILBOXES,
                               addresses=mb.addresses(), address="", query="",
                               nav=_nav, ok=False,
                               error="From and To are both required."), 400

    reply = EmailMessage()
    reply["From"] = from_addr
    reply["To"] = to_addr
    reply["Subject"] = subject
    # EmailMessage does not generate one, and SES will not add it either.
    reply["Message-ID"] = make_msgid(domain=from_addr.rsplit("@", 1)[-1])
    reply["Date"] = formatdate(localtime=True)
    # Without these two the recipient's client starts a new thread.
    if request.form.get("message_id"):
        reply["In-Reply-To"] = request.form["message_id"]
    if request.form.get("references"):
        reply["References"] = request.form["references"]
    reply.set_content(body)

    try:
        raw = reply.as_bytes()
        boto3.client("ses", region_name=REGION).send_raw_email(
            Source=from_addr,
            Destinations=[to_addr],
            RawMessage={"Data": raw},
        )
    except ClientError as exc:
        return render_template("sent.html", mb=mb, mailboxes=MAILBOXES,
                               addresses=mb.addresses(), address="", query="",
                               nav=_nav, ok=False,
                               error=exc.response["Error"]["Message"]), 502

    # SES keeps no copy, so file one ourselves under the sent/ prefix.
    stamp = re.sub(r"[^\w]", "", reply["Message-ID"] or "")[:40] or "reply"
    try:
        s3().put_object(Bucket=mb.bucket, Key=f"sent/{stamp}", Body=raw)
        for box in MAILBOXES:
            if box.bucket == mb.bucket and box.prefix == "sent/":
                box.get_index(force=True)
    except ClientError:
        pass  # the reply went out; failing to archive it is not fatal

    return render_template("sent.html", mb=mb, mailboxes=MAILBOXES,
                           addresses=mb.addresses(), address="", query="",
                           nav=_nav, ok=True, to_addr=to_addr, error=None)


@app.route("/delete", methods=["POST"])
def delete_message():
    """Delete one message. The buckets are versioned, so this writes a delete
    marker and the object stays recoverable until the lifecycle rule purges it."""
    check_csrf()
    mb = BY_ID.get(request.form.get("mb", ""))
    key = request.form.get("key", "")
    if mb is None or mb.get_entry(key) is None:
        abort(404)

    s3().delete_object(Bucket=mb.bucket, Key=key)
    mb.forget(key)

    return redirect(url_for("inbox", **_nav(
        mb, q=request.form.get("q", ""), to=request.form.get("to", ""),
        deleted="1")))


@app.route("/delete-bulk", methods=["POST"])
def delete_bulk():
    """Delete every checked message in one S3 call."""
    check_csrf()
    mb = BY_ID.get(request.form.get("mb", ""))
    if mb is None:
        abort(404)

    # Only delete keys that are actually in this mailbox's index.
    known = {e["key"] for e in mb.get_index()}
    keys = [k for k in request.form.getlist("keys") if k in known]
    if not keys:
        return redirect(url_for("inbox", **_nav(
            mb, q=request.form.get("q", ""), to=request.form.get("to", ""))))

    # delete_objects takes 1000 keys per call; chunk so large selections work.
    deleted = 0
    for i in range(0, len(keys), 1000):
        chunk = keys[i:i + 1000]
        resp = s3().delete_objects(
            Bucket=mb.bucket,
            Delete={"Objects": [{"Key": k} for k in chunk], "Quiet": True},
        )
        failed = {e["Key"] for e in resp.get("Errors", [])}
        for key in chunk:
            if key not in failed:
                mb.forget(key)
                deleted += 1

    return redirect(url_for("inbox", **_nav(
        mb, q=request.form.get("q", ""), to=request.form.get("to", ""),
        deleted=deleted)))


@app.route("/refresh")
def refresh():
    """Pick up new deliveries, then go back to where the user was."""
    mb = current_mailbox()
    before = len(mb.get_index())
    after = len(mb.get_index(rescan=True))
    return redirect(url_for("inbox", **_nav(
        mb, q=request.args.get("q", ""), to=request.args.get("to", ""),
        new=(after - before) if after > before else None)))


@app.route("/api/refresh")
def api_refresh():
    mb = current_mailbox()
    return jsonify({"mailbox": mb.id, "indexed": len(mb.get_index(rescan=True))})


@app.route("/api/messages")
def api_messages():
    return jsonify(current_mailbox().get_index())


@app.route("/api/mailboxes")
def api_mailboxes():
    return jsonify([
        {"id": m.id, "label": m.label, "bucket": m.bucket, "prefix": m.prefix,
         "messages": len(m.get_index()),
         "addresses": [{"address": a, "count": n} for a, n in m.addresses()]}
        for m in MAILBOXES
    ])


@app.template_filter("shortdate")
def shortdate(iso):
    return iso.replace("T", " ")[:16] if iso else ""


@app.template_filter("humansize")
def humansize(num):
    for unit in ("B", "KB", "MB"):
        if num < 1024 or unit == "MB":
            return f"{num:.0f} {unit}" if unit == "B" else f"{num:.1f} {unit}"
        num /= 1024


if __name__ == "__main__":
    for box in MAILBOXES:
        print(f"Indexing s3://{box.bucket}/{box.prefix} ...", flush=True)
        try:
            print(f"  {len(box.get_index())} messages, "
                  f"{len(box.addresses())} addresses")
        except (BotoCoreError, ClientError) as exc:
            # Serve anyway: the browser then explains the problem, and a Refresh
            # after fixing the credentials indexes without a restart.
            problem = explain_aws(exc)
            print(f"  {problem['title']}: {problem['detail']}")
            if problem["command"]:
                print(f"  {problem['command']}")
    print(f"http://127.0.0.1:{PORT}")
    app.run(host="127.0.0.1", port=PORT, debug=False)
