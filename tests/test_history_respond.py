"""Case history (duplicates, campaigns, analyst decisions) and the response kit."""
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

import pytest

from triage.enrich import Enricher
from triage.history import History, anchors
from triage.iocs import extract
from triage.parser import parse_eml
from triage.pipeline import analyse
from triage.respond import actionable, blocklist_csv, hunt_queries, reporter_reply

ROOT = Path(__file__).parent.parent
SAMPLES = ROOT / "samples"
UPLOADS = ROOT / "test_uploads"


def run(path: Path):
    return analyse(path.read_bytes(), Enricher(offline_file=SAMPLES / "mock_intel.json"))


def save(h: History, a, **kw) -> int:
    return h.record(a.parsed, a.iocs, a.result, a.report, **kw)


@pytest.fixture
def history(tmp_path):
    return History(tmp_path / "cases.db")


# ---- duplicates and campaigns ------------------------------------------------
def test_reopening_the_same_file_is_one_case(history):
    a = run(SAMPLES / "01_obvious_phish.eml")
    assert save(history, a) == save(history, a)
    assert history.related(save(history, a)) == []


def test_same_email_from_another_reporter_is_linked(history):
    first = save(history, run(SAMPLES / "01_obvious_phish.eml"))
    second = save(history, run(UPLOADS / "06_reported_as_attachment.eml"))  # Farid reports it
    assert first != second
    rel = history.related(second)
    assert len(rel) == 1 and rel[0].same_email
    assert ("sender domain", "secure-verify.top") in rel[0].shared


def test_campaign_matched_on_infrastructure_not_subject(history):
    # A different email (new subject, new display name) reusing the same link domain.
    m = EmailMessage()
    m["From"] = '"Totally Different" <hello@other-sender.example>'
    m["Subject"] = "Your invoice"
    m["Message-ID"] = "<x@other-sender.example>"
    m.set_content("See http://nusabank-com-my.secure-verify.top/pay")
    p = parse_eml(bytes(m))
    first = save(history, run(SAMPLES / "01_obvious_phish.eml"))
    a = run(SAMPLES / "02_benign_newsletter.eml")
    new = history.record(p, extract(p), a.result)
    rel = history.related(new)
    assert [r.case_id for r in rel] == [first]
    assert not rel[0].same_email
    assert rel[0].shared == [("link domain", "secure-verify.top")]


def test_unrelated_emails_are_not_linked(history):
    save(history, run(SAMPLES / "01_obvious_phish.eml"))
    other = save(history, run(SAMPLES / "02_benign_newsletter.eml"))
    assert history.related(other) == []


def test_webmail_and_own_domains_are_never_anchors():
    a = run(SAMPLES / "05_bec_ceo_gift_cards.eml")
    found = anchors(a.parsed, a.iocs)
    assert ("sender address", "sample_dato_rahman_ceo@gmail.com") in found
    assert not any(v == "gmail.com" for _, v in found)   # would link every Gmail email
    reported = run(UPLOADS / "07_reported_inline_forward.eml")  # From: a colleague
    assert not any("corp.example" == v for _, v in anchors(reported.parsed, reported.iocs))


# ---- analyst decisions ---------------------------------------------------------
def test_analyst_decisions_give_an_agreement_rate(history):
    one = save(history, run(SAMPLES / "01_obvious_phish.eml"))
    two = save(history, run(SAMPLES / "03_tricky_shared_doc.eml"))
    assert history.accuracy() == (0, 0)
    history.decide(one, "MALICIOUS", "confirmed", now=datetime(2026, 11, 12, 9, 0))
    history.decide(two, "MALICIOUS", "tool said suspicious, it was a real phish")
    assert history.accuracy() == (1, 2)
    assert history.get(two)["analyst_note"].startswith("tool said")
    with pytest.raises(ValueError):
        history.decide(one, "PROBABLY FINE")


# ---- hunt queries -------------------------------------------------------------------
def test_hunt_queries_cover_received_clicked_and_ran():
    a = run(SAMPLES / "01_obvious_phish.eml")
    hunts = hunt_queries(a.parsed, a.iocs)
    text = "\n".join(h.query for h in hunts)
    assert "EmailEvents" in text and "UrlClickEvents" in text and "SHA256 in" in text
    assert '"secure-verify.top"' in text          # the real value, not defanged
    assert "gmail.com\"" not in text.replace("sample_nusabank_helpdesk@gmail.com\"", "")


def test_bec_with_no_links_still_gets_a_sender_hunt():
    a = run(SAMPLES / "05_bec_ceo_gift_cards.eml")
    hunts = hunt_queries(a.parsed, a.iocs)
    assert [h.title for h in hunts] == ["Who else received email from this sender?"]
    assert "SenderFromDomain" not in hunts[0].query  # never hunt on all of gmail.com


def test_attacker_text_cannot_inject_into_a_query():
    m = EmailMessage()
    m["From"] = '"x" <"a\\"| drop"@evil.example>'
    m["Reply-To"] = "ok@evil.example"
    m["Subject"] = 'hi" | union SecretTable //'
    m.set_content("hello")
    p = parse_eml(bytes(m))
    text = "\n".join(h.query for h in hunt_queries(p, extract(p)))
    assert "drop" not in text and "SecretTable" not in text   # bad address + subject dropped
    assert '"ok@evil.example"' in text


def test_benign_newsletter_has_nothing_of_ours_to_block():
    a = run(UPLOADS / "07_reported_inline_forward.eml")
    ind = actionable(a.parsed, a.iocs)
    assert not any("corp.example" in v for v in ind.sender_addresses + ind.sender_domains)


# ---- block list ---------------------------------------------------------------------
def test_blocklist_has_real_values_and_no_webmail_domain():
    a = run(SAMPLES / "01_obvious_phish.eml")
    csv = blocklist_csv(a.parsed, a.iocs)
    assert csv.splitlines()[0] == '"type","value","block_at"'
    assert '"sender_domain","secure-verify.top","mail gateway"' in csv
    assert '"sender_address","sample_nusabank_helpdesk@gmail.com"' in csv
    assert '"sender_domain","gmail.com"' not in csv
    assert a.parsed.attachments[0].sha256 in csv


def test_csv_cells_cannot_become_spreadsheet_formulas():
    from triage.respond import _csv_cell
    assert _csv_cell("=HYPERLINK(\"http://evil\")") == '"\'=HYPERLINK(""http://evil"")"'
    assert _csv_cell("normal.example") == '"normal.example"'


# ---- reply to the reporter ---------------------------------------------------------------
def test_reply_matches_verdict_and_handles_a_click():
    clicked = run(UPLOADS / "06_reported_as_attachment.eml")
    text = reporter_reply(clicked.result, clicked.report)
    assert text.startswith("Hi Farid,")
    assert "reset your password" in text and "You were right" in text
    benign = run(SAMPLES / "02_benign_newsletter.eml")
    assert "no signs of phishing" in reporter_reply(benign.result, benign.report)
    bec = run(SAMPLES / "05_bec_ceo_gift_cards.eml")
    assert "gift cards" in reporter_reply(bec.result, bec.report)


def test_recipients_own_domain_is_never_a_campaign_anchor():
    spoof = run(ROOT / "tests" / "fixtures" / "case_01.eml")   # forged "internal" sender
    found = anchors(spoof.parsed, spoof.iocs)
    assert not any(v == "northline-studio.invalid" for _, v in found)
    assert ("link domain", "device-review.invalid") in found   # the real infrastructure
