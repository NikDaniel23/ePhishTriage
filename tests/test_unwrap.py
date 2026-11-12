"""Reports arrive wrapped: attached, inline-forwarded, or as Outlook .msg."""
import sys
import types
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

import pytest

from triage.enrich import Enricher
from triage.pipeline import analyse
from triage.unwrap import UnsupportedFormat, unwrap

ROOT = Path(__file__).parent.parent
SAMPLES = ROOT / "samples"
UPLOADS = ROOT / "test_uploads"
PHISH = (SAMPLES / "01_obvious_phish.eml").read_bytes()


def run(raw: bytes, **kw):
    return analyse(raw, Enricher(offline_file=SAMPLES / "mock_intel.json"), **kw)


def report_email(sender: str, note: str) -> EmailMessage:
    m = EmailMessage()
    m["From"] = sender
    m["To"] = "phishing-reports@corp.example"
    m["Subject"] = "FW: suspicious"
    m["Date"] = "Mon, 9 Nov 2026 09:31:40 +0800"
    m.set_content(note)
    return m


# ---- forwarded as an attachment ------------------------------------------
def test_attached_report_analyses_the_original():
    direct = run(PHISH)
    a = run((UPLOADS / "06_reported_as_attachment.eml").read_bytes())
    assert a.report.kind == "attached"
    assert a.report.reporter == "farid.hakim@corp.example"
    assert a.parsed.from_addr == "alert@secure-verify.top"   # the phish, not Farid
    assert a.result.verdict == direct.result.verdict == "MALICIOUS"
    assert a.result.score == direct.result.score


def test_reporter_click_escalates_the_action():
    a = run((UPLOADS / "06_reported_as_attachment.eml").read_bytes())
    assert "clicked the link" in a.report.interacted
    assert a.result.action.startswith("URGENT")
    assert "### Report" in a.ticket and "Reporter says they interacted" in a.ticket


def test_unencoded_rfc822_attachment():
    # How most mail clients write it: the email inline, no base64.
    m = report_email("ali@corp.example", "Please check.")
    m.add_attachment(BytesParser(policy=policy.default).parsebytes(PHISH))
    raw, info = unwrap(bytes(m))
    assert info.kind == "attached"
    assert b"secure-verify.top" in raw and b"ali@corp.example" not in raw


def test_eml_file_attachment():
    m = report_email("ali@corp.example", "See attached.")
    m.add_attachment(PHISH, maintype="application", subtype="octet-stream",
                     filename="phish.eml")
    assert unwrap(bytes(m))[1].kind == "attached"


def test_report_of_a_report_keeps_first_reporter():
    inner = report_email("ali@corp.example", "Got this.")
    inner.add_attachment(BytesParser(policy=policy.default).parsebytes(PHISH))
    outer = report_email("helpdesk@corp.example", "Passing on from Ali.")
    outer.add_attachment(inner)
    raw, info = unwrap(bytes(outer))
    assert info.reporter == "helpdesk@corp.example"
    assert BytesParser(policy=policy.default).parsebytes(raw)["From"].addresses[0] \
        .addr_spec == "alert@secure-verify.top"


def test_org_domains_stop_attacker_wrapping():
    # An EXTERNAL email carrying an .eml must be analysed itself, otherwise an
    # attacker could attach a harmless email to get theirs ignored.
    m = report_email("billing@evil.example", "Invoice attached.")
    m.add_attachment(PHISH, maintype="application", subtype="octet-stream",
                     filename="invoice.eml")
    assert unwrap(bytes(m), org_domains={"corp.example"})[1].kind == "direct"
    # Also with no configuration at all: the sender is not in the recipient's
    # organisation, so this is not a colleague's report.
    assert unwrap(bytes(m))[1].kind == "direct"


# ---- forwarded inline -----------------------------------------------------
def test_inline_forward_warns_and_lowers_confidence():
    a = run((UPLOADS / "07_reported_inline_forward.eml").read_bytes())
    assert a.report.kind == "inline"
    assert a.report.note == "Is this real? Looks dodgy to me."
    assert a.result.confidence == "Low"
    assert "original headers LOST" in a.ticket
    assert a.result.verdict == "MALICIOUS"  # body evidence still counts


# ---- direct uploads are untouched ----------------------------------------
@pytest.mark.parametrize("name", sorted(p.name for p in SAMPLES.glob("*.eml")))
def test_direct_samples_unchanged(name):
    a = run((SAMPLES / name).read_bytes())
    assert a.report.kind == "direct"
    assert "### Report" not in a.ticket


# ---- Outlook .msg ---------------------------------------------------------
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 64


def test_msg_without_library_gives_clear_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "extract_msg", None)  # import fails
    with pytest.raises(UnsupportedFormat, match="pip install extract-msg"):
        unwrap(OLE)


def test_msg_is_converted(monkeypatch):
    # A stand-in for extract_msg's Message object (no real .msg file needed).
    headers = BytesParser(policy=policy.default).parsebytes(PHISH)
    att = types.SimpleNamespace(data=b"<html></html>", longFilename="Statement.pdf.html",
                                shortFilename=None)
    fake = types.SimpleNamespace(
        header=headers, body="Verify your account immediately",
        htmlBody=b'<a href="http://nusabank-com-my.secure-verify.top/login">'
                 b"https://www.nusabank.com.my/login</a>",
        attachments=[att], close=lambda: None,
        sender=None, to=None, subject=None, date=None,
    )
    monkeypatch.setitem(sys.modules, "extract_msg",
                        types.SimpleNamespace(openMsg=lambda raw: fake))
    a = run(OLE)
    assert a.parsed.auth["dmarc"] == "fail"           # headers carried over
    assert a.parsed.attachments[0].filename == "Statement.pdf.html"
    assert any("anchor_mismatch" in u.flags for u in a.iocs.urls)
    assert a.result.verdict == "MALICIOUS"
