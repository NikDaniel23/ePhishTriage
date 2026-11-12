"""STEP 0 - Find the email that was actually reported.

Reports rarely arrive as the original email. They arrive as:

  1. a FORWARD AS ATTACHMENT: the employee's email to the SOC, with the
     phish attached (message/rfc822, a .eml file or an Outlook .msg file).
     This is what the Outlook "Report" button and most phishing mailboxes
     produce. The original headers survive -> we unwrap and analyse those.

  2. an INLINE FORWARD: the employee pressed plain "Forward". The phish is
     pasted as quoted text and its real headers are GONE: From becomes your
     colleague, SPF/DKIM become your own server's. We cannot rebuild them,
     so we warn the analyst and lower confidence instead of pretending.

  3. a direct upload of the original .eml / .msg -> nothing to do.

We also read what the reporter wrote, because "I clicked it" turns a
phishing ticket into an incident.
"""
from __future__ import annotations

import base64
import quopri
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr

from .iocs import registered_domain
from .parser import domain_of

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # first bytes of every .msg file
MAX_DEPTH = 3  # a forward of a forward of a forward is plenty

# Lines that email clients put above an inline-forwarded message.
INLINE_MARKERS = re.compile(
    r"^-{2,}\s*Forwarded message\s*-{2,}"      # Gmail
    r"|^-{2,}\s*Original Message\s*-{2,}"      # Outlook (older)
    r"|^Begin forwarded message:"              # Apple Mail
    r"|^-{2,}\s*Mesej (?:Asal|dimajukan)\s*-{2,}"  # Malay clients
    r"|^From:.*\n(?:Sent|Date|Dihantar|Tarikh):", # Outlook (newer): From/Sent block
    re.I | re.M,
)
# Things a reporter writes when they already interacted with the phish.
INTERACTED = [
    "i clicked", "clicked the link", "clicked on the link", "opened the link",
    "opened the attachment", "entered my password", "typed my password",
    "entered my details", "logged in", "i signed in", "gave my password",
    # Bahasa Melayu
    "saya klik", "dah klik", "sudah klik", "terklik", "buka lampiran",
    "masukkan kata laluan", "dah log masuk", "sudah log masuk", "beri kata laluan",
]


class UnsupportedFormat(Exception):
    """The file cannot be read (e.g. .msg without the extract-msg library)."""


@dataclass
class ReportInfo:
    kind: str = "direct"           # "direct" | "attached" | "inline"
    reporter: str = ""             # who sent the report
    reported_at: str = ""
    note: str = ""                 # what the reporter wrote to the SOC
    interacted: list[str] = field(default_factory=list)  # "i clicked", ...
    warnings: list[str] = field(default_factory=list)


# ------------------------------------------------------------------ .msg
def is_msg(raw: bytes) -> bool:
    return raw[:8] == OLE_MAGIC


def msg_to_eml(raw: bytes) -> bytes:
    """Convert an Outlook .msg file into .eml bytes the rest of the tool reads."""
    try:
        import extract_msg
    except ImportError as exc:
        raise UnsupportedFormat(
            "Reading Outlook .msg files needs the extract-msg library: "
            "pip install extract-msg"
        ) from exc

    msg = extract_msg.openMsg(raw)
    try:
        out = EmailMessage()
        # Outlook keeps the original internet headers (Received,
        # Authentication-Results...) when the mail came from outside. Copy
        # them, except the ones describing the old MIME layout.
        headers = msg.header
        skip = {"content-type", "content-transfer-encoding", "mime-version"}
        if headers is not None and len(headers.keys()):
            for name, value in headers.items():
                if name.lower() not in skip:
                    out[name] = str(value).replace("\r", " ").replace("\n", " ")
        else:
            # Drafts / internal mail: no transport headers, build the basics.
            out["From"] = msg.sender or ""
            out["To"] = msg.to or ""
            out["Subject"] = msg.subject or ""
            if msg.date:
                out["Date"] = str(msg.date)

        out.set_content(msg.body or "")
        html = msg.htmlBody
        if html:
            if isinstance(html, bytes):
                html = html.decode("utf-8", "replace")
            out.add_alternative(html, subtype="html")

        for att in msg.attachments:
            data = getattr(att, "data", None)
            name = att.longFilename or att.shortFilename or "(no name)"
            if isinstance(data, bytes):
                out.add_attachment(data, maintype="application",
                                   subtype="octet-stream", filename=name)
            # Embedded .msg attachments are MSG objects, not bytes: convert
            # them too so a reported .msg inside a .msg still unwraps.
            elif data is not None and hasattr(data, "body"):
                inner = data.exportBytes() if hasattr(data, "exportBytes") else None
                if inner:
                    out.add_attachment(msg_to_eml(inner), maintype="message",
                                       subtype="rfc822", filename=name)
        return bytes(out)
    finally:
        msg.close()


def to_eml(raw: bytes) -> bytes:
    """Accept .eml or .msg bytes, always return .eml bytes."""
    return msg_to_eml(raw) if is_msg(raw) else raw


# ------------------------------------------------------------------ unwrap
def _attached_original(msg) -> bytes | None:
    """The first attached email inside msg, as .eml bytes, or None."""
    for part in msg.iter_attachments():
        ctype = part.get_content_type()
        name = (part.get_filename() or "").lower()
        if ctype == "message/rfc822":
            inner = part.get_payload()
            inner = inner[0] if isinstance(inner, list) else inner
            cte = str(part.get("Content-Transfer-Encoding", "")).strip().lower()
            if cte in ("base64", "quoted-printable"):
                # The standard says an attached email is never encoded, but
                # some clients (and Python itself) base64 it anyway. Python
                # then parses the base64 TEXT as an empty email, so decode
                # that text ourselves.
                text = inner.get_payload()
                if isinstance(text, str):
                    data = text.encode("ascii", "replace")
                    return (base64.b64decode(data) if cte == "base64"
                            else quopri.decodestring(data))
            return inner.as_bytes(policy=policy.default)
        if name.endswith(".eml"):
            return part.get_payload(decode=True) or None
        if name.endswith(".msg") or ctype == "application/vnd.ms-outlook":
            data = part.get_payload(decode=True) or b""
            return msg_to_eml(data) if is_msg(data) else None
    return None


def _plain_text(msg) -> str:
    part = msg.get_body(preferencelist=("plain",))
    if part is None:
        return ""
    try:
        return part.get_content()
    except Exception:
        return (part.get_payload(decode=True) or b"").decode("utf-8", "replace")


def _note(msg) -> str:
    text = _plain_text(msg)
    # Keep only what the reporter typed, not a quoted copy of the phish.
    cut = INLINE_MARKERS.search(text)
    return (text[: cut.start()] if cut else text).strip()[:1000]


def _interacted(note: str) -> list[str]:
    low = " ".join(note.lower().split())
    return [p for p in INTERACTED if p in low]


def unwrap(raw: bytes, org_domains: set[str] | None = None) -> tuple[bytes, ReportInfo]:
    """Return (the email to analyse, what we learned about the report).

    org_domains: your company's domains. When given, an outer email is only
    treated as a report if it comes from inside the company. This stops an
    attacker hiding a harmless-looking .eml inside their phish to get the
    outer email ignored.
    """
    info = ReportInfo()
    raw = to_eml(raw)

    for _ in range(MAX_DEPTH):
        outer = BytesParser(policy=policy.default).parsebytes(raw)
        sender = parseaddr(str(outer.get("From", "")))[1]
        # A REPORT is one colleague sending mail to another (or to the SOC
        # mailbox): sender and recipient share a domain, or the sender is in
        # our configured domains. Anything from OUTSIDE that carries an
        # attached email is not a report, it is the email to analyse.
        # Without this check an attacker hides the phish in an attached .eml
        # and the tool obligingly throws their outer email away.
        sender_reg = registered_domain(domain_of(sender))
        recipients = getaddresses(
            [str(v) for v in outer.get_all("To", []) + outer.get_all("Cc", [])])
        recipient_regs = {registered_domain(domain_of(addr)) for _, addr in recipients}
        internal = bool(sender_reg) and (
            sender_reg in (org_domains or ()) or sender_reg in recipient_regs)
        if not internal:
            break

        inner = _attached_original(outer)
        if inner is None:
            if info.kind == "direct" and INLINE_MARKERS.search(_plain_text(outer)):
                info.kind = "inline"
                info.reporter = sender
                info.reported_at = str(outer.get("Date", ""))
                info.note = _note(outer)
                info.warnings.append(
                    "Forwarded inline, not as an attachment: the original "
                    "sender, Received and SPF/DKIM/DMARC headers are lost. "
                    "Header findings below describe the forward, not the phish. "
                    "Ask the reporter to use the Report button or forward it "
                    "as an attachment."
                )
            break

        if info.kind == "direct":  # keep the FIRST (outermost) reporter
            info.kind = "attached"
            info.reporter = sender
            info.reported_at = str(outer.get("Date", ""))
            info.note = _note(outer)
        raw = inner

    info.interacted = _interacted(info.note)
    return raw, info
