"""Five hard cases written to beat this tool (and four of them did).

Each one is a different lesson, kept here so it can never regress.
"""
from pathlib import Path

from triage.attachments import calendar_urls
from triage.enrich import Enricher
from triage.iocs import analyse_url
from triage.pipeline import analyse

ROOT = Path(__file__).parent
FIXTURES = ROOT / "fixtures"
INTEL = ROOT.parent / "samples" / "mock_intel.json"


def run(name: str):
    return analyse((FIXTURES / name).read_bytes(), Enricher(offline_file=INTEL))


def titles(a) -> list[str]:
    return [f.title for f in a.result.findings]


def test_case_01_internal_spoof_with_embedded_domain_link():
    a = run("case_01.eml")
    assert a.result.verdict == "MALICIOUS"
    # only the TOP Authentication-Results is trusted; the planted one is called out
    assert a.parsed.auth["dmarc"] == "fail" and a.parsed.auth_conflicts == ["dmarc"]
    assert "A planted header claims authentication passed" in titles(a)
    assert "Claims to be internal, but failed DMARC" in titles(a)
    link = a.iocs.urls[0]
    assert "embedded_domain" in link.flags
    assert link.registered_domain == "device-review.invalid"      # where it really goes
    assert link.imitates == "northline-studio.invalid"            # what it pretends to be


def test_case_02_mailing_list_forward_is_benign():
    a = run("case_02.eml")
    assert a.parsed.auth["dmarc"] == "fail"                       # and yet...
    assert a.result.verdict == "LIKELY BENIGN" and a.result.score == 0
    assert any("explained by a mailing list" in t for t in titles(a))


def test_list_id_alone_does_not_excuse_a_forgery():
    # Same email, but the link now leaves the sender's own site: no excuse.
    raw = (FIXTURES / "case_02.eml").read_bytes().replace(
        b"https://portal.buildform.invalid/", b"https://portal.buildform-login.invalid/")
    a = analyse(raw, Enricher(offline_file=INTEL))
    assert "DMARC failed" in titles(a)
    assert a.result.verdict != "LIKELY BENIGN"


def test_case_03_phish_hidden_in_an_attached_email():
    a = run("case_03.eml")
    assert a.report.kind == "direct"            # an outsider's email is NOT a user report
    assert a.parsed.from_addr == "plotdesk@lineprint.invalid"   # the outer email is analysed
    hidden = [u for u in a.iocs.urls if "in_attached_email" in u.flags]
    assert [u.registered_domain for u in hidden] == ["receipt-review.invalid"]
    assert "Link hidden inside an attached email" in titles(a)
    assert a.result.verdict == "MALICIOUS"


def test_case_04_payment_diversion():
    a = run("case_04.eml")
    assert set(a.parsed.auth.values()) == {"pass"}
    assert "Reply-To domain is a variation of the sender's" in titles(a)
    assert a.result.verdict in ("SUSPICIOUS", "MALICIOUS")
    assert a.result.action.startswith("Do not pay")


def test_case_05_link_inside_a_calendar_invite():
    a = run("case_05.eml")
    cal = [u for u in a.iocs.urls if "in_calendar" in u.flags]
    assert [u.registered_domain for u in cal] == ["lobby-check.invalid"]
    assert "Calendar invite links somewhere the email does not mention" in titles(a)
    assert a.result.verdict == "MALICIOUS"


def test_embedded_domain_rule_ignores_ordinary_subdomains():
    for url in ("https://portal.buildform.invalid/x", "https://www.maybank2u.com.my/login",
                "https://docs.mail.example.org/a", "https://a.b.c.cdn-host.net/x"):
        assert "embedded_domain" not in analyse_url(url).flags, url
    assert "embedded_domain" in analyse_url("https://login.maybank2u.com.my.evil.top/x").flags


def test_calendar_urls_survive_line_folding():
    ics = "BEGIN:VEVENT\r\nURL:https://meet.example.org/very/long/pa\r\n th/room-1\r\nEND:VEVENT\r\n"
    assert calendar_urls(ics) == ["https://meet.example.org/very/long/path/room-1"]


def test_honest_calendar_invite_is_quiet():
    # An invite whose link matches the email body raises nothing.
    from email.message import EmailMessage
    m = EmailMessage()
    m["Authentication-Results"] = "mx1.northline-studio.invalid; spf=pass; dkim=pass; dmarc=pass"
    m["From"] = "Room Booking <rooms@meetingdesk.invalid>"
    m["To"] = "operations@northline-studio.invalid"
    m["Subject"] = "Room reservation"
    m.set_content("Details: https://meet.meetingdesk.invalid/riverside-coordination")
    lines = ["BEGIN:VCALENDAR", "BEGIN:VEVENT", "SUMMARY:Riverside",
             "URL:https://meet.meetingdesk.invalid/riverside-coordination",
             "END:VEVENT", "END:VCALENDAR", ""]
    ics = (chr(13) + chr(10)).join(lines)
    m.add_attachment(ics.encode(), maintype="text", subtype="calendar", filename="invite.ics")
    a = analyse(bytes(m), Enricher(offline_file=INTEL))
    assert [u.flags for u in a.iocs.urls] == [["in_calendar"]]
    assert a.result.verdict == "LIKELY BENIGN" and a.result.score == 0
