"""STEP 1 - Parse a raw .eml file into structured fields.

An .eml file is just text: headers (From, Received, ...) then the body.
Python's built-in `email` library does the hard work of decoding it.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import quopri
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr

# Internal address ranges. An IP inside these is not the attacker's real IP.
PRIVATE_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
    )
]

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
# Matches "spf=pass", "dkim=fail", "dmarc=none" inside Authentication-Results.
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
FROM_HOST_RE = re.compile(r"\bfrom\s+(\S+)", re.I)
MAX_INSPECT_BYTES = 8 * 1024 * 1024
BY_HOST_RE = re.compile(r"\bby\s+(\S+)", re.I)
# Names of your own mail gateways, e.g. "mx.corp.example". Optional.
TRUSTED_AUTHSERV_IDS = {
    s.strip().lower()
    for s in os.getenv("TRIAGE_AUTHSERV_IDS", "").split(",")
    if s.strip()
}


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    md5: str
    sha256: str


@dataclass
class Hop:
    """One mail server the message passed through (one Received header)."""

    index: int
    from_host: str
    by_host: str
    ips: list[str]
    raw: str


@dataclass
class ParsedEmail:
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: list[str] = field(default_factory=list)
    date: str = ""
    message_id: str = ""
    auth: dict[str, str] = field(default_factory=dict)
    hops: list[Hop] = field(default_factory=list)
    origin_ip: str = ""
    body_text: str = ""
    body_html: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    # Kept so attachments.py can look inside them (as text / pixels, never run):
    html_attachments: list[tuple[str, str]] = field(default_factory=list)  # (name, html)
    images: list[tuple[str, bytes]] = field(default_factory=list)          # (name, bytes)
    calendars: list[tuple[str, str]] = field(default_factory=list)         # (name, .ics text)
    nested: list[tuple[str, "ParsedEmail"]] = field(default_factory=list)  # attached emails
    list_id: str = ""                 # set by mailing lists
    # Mechanisms where a LOWER (untrusted) Authentication-Results header claims
    # "pass" but our own gateway's header does not: someone planted a fake.
    auth_conflicts: list[str] = field(default_factory=list)

    @property
    def from_domain(self) -> str:
        return domain_of(self.from_addr)


def domain_of(address: str) -> str:
    """'alice@Example.com' -> 'example.com'."""
    return address.rsplit("@", 1)[-1].lower().strip() if "@" in address else ""


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr in net for net in PRIVATE_NETS)


def _trusted_auth_header(headers: list) -> str:
    """Pick the one Authentication-Results header we can trust.

    Every header starts with the name of the server that wrote it (the
    "authserv-id"), e.g. "mx.corp.example; spf=pass ...". If you set
    TRIAGE_AUTHSERV_IDS (comma-separated names of YOUR gateways), we use the
    first header written by one of them. Otherwise we fall back to the
    topmost header, which in a normal mail flow is your own gateway's.
    """
    if not headers:
        return ""
    if TRUSTED_AUTHSERV_IDS:
        for header in headers:
            server = str(header).split(";", 1)[0].strip().lower()
            if server in TRUSTED_AUTHSERV_IDS:
                return str(header)
        return ""  # none written by our gateway -> trust nothing
    return str(headers[0])


def _body(msg, kind: str) -> str:
    part = msg.get_body(preferencelist=(kind,))
    if part is None:
        return ""
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", "replace")


def rfc822_bytes(part) -> bytes | None:
    """The raw bytes of an email attached to an email, or None if it is not one."""
    name = (part.get_filename() or "").lower()
    if part.get_content_type() == "message/rfc822":
        inner = part.get_payload()
        inner = inner[0] if isinstance(inner, list) else inner
        cte = str(part.get("Content-Transfer-Encoding", "")).strip().lower()
        if cte in ("base64", "quoted-printable"):
            text = inner.get_payload()
            if isinstance(text, str):
                data = text.encode("ascii", "replace")
                return base64.b64decode(data) if cte == "base64" else quopri.decodestring(data)
        return inner.as_bytes(policy=policy.default)
    if name.endswith(".eml"):
        return part.get_payload(decode=True) or None
    return None


def parse_eml(raw: bytes, _depth: int = 0) -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    p = ParsedEmail()

    p.subject = str(msg.get("Subject", ""))
    p.from_name, p.from_addr = parseaddr(str(msg.get("From", "")))
    p.reply_to = parseaddr(str(msg.get("Reply-To", "")))[1]
    p.return_path = parseaddr(str(msg.get("Return-Path", "")))[1]
    p.to = [a for _, a in getaddresses([str(v) for v in msg.get_all("To", [])])]
    p.date = str(msg.get("Date", ""))
    p.message_id = str(msg.get("Message-ID", ""))

    # --- Authentication results -------------------------------------------
    # The receiving mail server writes its SPF/DKIM/DMARC verdict into the
    # Authentication-Results header. Headers are stacked newest-first, so the
    # FIRST one is the one added by our own gateway - the only one we trust.
    # We read ONLY that header. An attacker can forge any header lower down,
    # so we must never "fill in the gaps" (e.g. a missing dkim result) from
    # a lower header - that would let them inject dkim=pass / dmarc=pass.
    p.auth = {"spf": "none", "dkim": "none", "dmarc": "none"}
    all_auth = [str(h) for h in msg.get_all("Authentication-Results", [])]
    trusted = _trusted_auth_header(all_auth)
    p.list_id = str(msg.get("List-Id", ""))
    if trusted:
        for mech, result in AUTH_RE.findall(trusted):
            mech = mech.lower()
            if p.auth[mech] == "none":
                p.auth[mech] = result.lower()
    for other in all_auth:
        if other == trusted:
            continue
        for mech, result in AUTH_RE.findall(other):
            mech = mech.lower()
            if result.lower() == "pass" and p.auth[mech] != "pass" and mech not in p.auth_conflicts:
                p.auth_conflicts.append(mech)
    received_spf = msg.get_all("Received-SPF", [])
    if p.auth["spf"] == "none" and received_spf:
        # Same rule: only the topmost Received-SPF was written by our server.
        p.auth["spf"] = str(received_spf[0]).split()[0].lower()

    # --- Received hops ------------------------------------------------------
    # Each server adds a Received header on top, so reversing the list gives
    # the journey in time order: hop 1 is closest to the sender.
    received = [" ".join(str(h).split()) for h in msg.get_all("Received", [])]
    for i, raw_hop in enumerate(reversed(received), start=1):
        from_m = FROM_HOST_RE.search(raw_hop)
        by_m = BY_HOST_RE.search(raw_hop)
        p.hops.append(
            Hop(
                index=i,
                from_host=from_m.group(1) if from_m else "",
                by_host=by_m.group(1).rstrip(";") if by_m else "",
                ips=IPV4_RE.findall(raw_hop),
                raw=raw_hop,
            )
        )
    for hop in p.hops:
        public = [ip for ip in hop.ips if is_public_ip(ip)]
        if public:
            p.origin_ip = public[0]
            break

    # --- Body and attachments ----------------------------------------------
    p.body_text = _body(msg, "plain")
    p.body_html = _body(msg, "html")

    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        # We NEVER open or run attachments. We only fingerprint (hash) them.
        p.attachments.append(
            Attachment(
                filename=part.get_filename() or "(no name)",
                content_type=part.get_content_type(),
                size=len(payload),
                md5=hashlib.md5(payload).hexdigest(),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
        name = part.get_filename() or "(no name)"
        inner = rfc822_bytes(part)
        if inner and _depth < 2 and len(p.nested) < 5:
            # Parsed so we can read the links INSIDE it (never to trust its headers).
            p.nested.append((name, parse_eml(inner, _depth + 1)))
        if part.get_content_type() == "text/calendar" or name.lower().endswith((".ics", ".vcs")):
            if len(payload) <= MAX_INSPECT_BYTES:
                p.calendars.append((name, payload.decode("utf-8", "replace")))
        if (part.get_content_type() == "text/html"
                or name.lower().endswith((".html", ".htm", ".shtml", ".xhtml", ".svg"))):
            if len(payload) <= MAX_INSPECT_BYTES and len(p.html_attachments) < 10:
                p.html_attachments.append((name, payload.decode("utf-8", "replace")))

    # Images anywhere in the message, including ones shown inline in the body
    # (which are not "attachments"): a QR code is usually an inline picture.
    for part in msg.walk():
        if part.get_content_maintype() == "image" and len(p.images) < 20:
            data = part.get_payload(decode=True) or b""
            if 0 < len(data) <= MAX_INSPECT_BYTES:
                p.images.append((part.get_filename() or "inline image", data))
    return p
