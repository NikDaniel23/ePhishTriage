"""QR codes, HTML attachments and supplier look-alikes: where links hide."""
from email.message import EmailMessage
from pathlib import Path

import pytest

from triage.attachments import inspect_html
from triage.enrich import Enricher
from triage.iocs import extract
from triage.org import Executive, Org, Supplier
from triage.parser import parse_eml
from triage.pipeline import analyse
from triage.scoring import score

SAMPLES = Path(__file__).parent.parent / "samples"
ORG = Org(frozenset({"corp.example"}), (),
          (Supplier("Example Supplies", ("example-supplies.example",)),))


def run(name: str):
    return analyse((SAMPLES / name).read_bytes(),
                   Enricher(offline_file=SAMPLES / "mock_intel.json"))


def titles(result) -> list[str]:
    return [f.title for f in result.findings]


# ---- QR codes -------------------------------------------------------------------
def test_link_hidden_in_a_qr_code_is_found():
    pytest.importorskip("cv2")
    a = run("08_quishing_qr_code.eml")
    assert "http" not in a.parsed.body_text          # no link anywhere in the text
    qr_urls = [u for u in a.iocs.urls if "qr_code" in u.flags]
    assert [u.url for u in qr_urls] == ["https://m365-reauth.example/mfa?u=staff"]
    assert qr_urls[0].source == "mfa-qr.png"
    assert "Link hidden in a QR code" in titles(a.result)
    assert a.result.verdict == "MALICIOUS"
    assert "m365-reauth.example" in a.iocs.domains   # so it can be hunted and blocked


def test_ordinary_image_is_not_a_qr_code():
    cv2 = pytest.importorskip("cv2")
    import numpy as np
    logo = cv2.imencode(".png", np.full((120, 240, 3), 200, np.uint8))[1].tobytes()
    m = EmailMessage()
    m["From"] = "news@kldesignmeetup.example"
    m["Subject"] = "Hello"
    m.set_content("Our new logo is attached.")
    m.add_attachment(logo, maintype="image", subtype="png", filename="logo.png")
    p = parse_eml(bytes(m))
    assert len(p.images) == 1 and extract(p).qr == []


# ---- HTML attachments -----------------------------------------------------------
def test_login_form_attachment_is_exposed():
    a = run("09_html_attachment_login.eml")
    rep = a.iocs.html_reports[0]
    assert rep.password_field and rep.obfuscation
    assert rep.form_actions == ["https://collect.voice-notify-login.example/save"]
    assert "Attachment is a login form that sends passwords outside" in titles(a.result)
    assert "Attachment hides its code" in titles(a.result)
    assert a.result.verdict == "MALICIOUS"
    hidden = [u for u in a.iocs.urls if "in_attachment" in u.flags]
    assert hidden and hidden[0].source == "Voicemail_0412.html"


def test_html_inspection_details():
    r = inspect_html("a.html", '<meta http-equiv="refresh" content="0; url=https://go.example/x">')
    assert r.redirects == ["https://go.example/x"] and not r.password_field
    r = inspect_html("b.html", "<script>window.location.href = 'https://jump.example/y';</script>")
    assert r.redirects == ["https://jump.example/y"]
    # password form whose target is only in script (fetch), not in <form action>
    r = inspect_html("c.html", '<input type="password"><script>fetch("https://x.example/c")</script>')
    assert r.password_field and r.form_actions == ["https://x.example/c"]
    # a harmless page raises nothing
    r = inspect_html("d.html", "<html><body><h1>Agenda</h1><p>See you Friday.</p></body></html>")
    assert not (r.password_field or r.redirects or r.obfuscation or r.urls)
    assert inspect_html("broken.html", "<<<form <input type=password").filename == "broken.html"


def test_harmless_html_attachment_scores_only_its_file_type():
    a = run("01_obvious_phish.eml")   # its .html attachment is an empty placeholder
    assert not any("password" in t.lower() for t in titles(a.result))


# ---- supplier look-alikes ----------------------------------------------------------
def supplier_email(sender: str, body: str) -> bytes:
    m = EmailMessage()
    m["Authentication-Results"] = "mx.corp.example; spf=pass; dkim=pass; dmarc=pass"
    m["From"] = sender
    m["To"] = "payables@corp.example"
    m["Subject"] = "Invoice"
    m.set_content(body)
    return bytes(m)


def test_fake_supplier_domain_is_flagged():
    p = parse_eml(supplier_email('"Example Supplies" <billing@examp1e-supplies.example>',
                                 "Our bank details have changed. Please use the new bank account."))
    r = score(p, extract(p), {}, ORG)
    assert "Sender domain imitates our supplier Example Supplies" in titles(r)
    assert r.verdict == "MALICIOUS"


def test_real_supplier_is_not_flagged():
    p = parse_eml(supplier_email('"Example Supplies" <billing@example-supplies.example>',
                                 "Please find the outstanding invoice for October."))
    r = score(p, extract(p), {}, ORG)
    assert not any("imitates" in t for t in titles(r))
    assert r.verdict == "LIKELY BENIGN"
