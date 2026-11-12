"""Run with:  pytest -q"""
from pathlib import Path

from triage.enrich import Enricher
from triage.iocs import brand_impersonation, defang, registered_domain
from triage.pipeline import analyse

ROOT = Path(__file__).parent.parent
SAMPLES = ROOT / "samples"


def run(name: str):
    enricher = Enricher(offline_file=SAMPLES / "mock_intel.json")
    return analyse((SAMPLES / name).read_bytes(), enricher)


def test_obvious_phish_is_malicious():
    a = run("01_obvious_phish.eml")
    assert a.result.verdict == "MALICIOUS"
    assert a.parsed.auth == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    assert a.parsed.origin_ip == "203.0.113.45"
    assert any("anchor_mismatch" in u.flags for u in a.iocs.urls)
    assert a.parsed.attachments[0].filename == "Statement.pdf.html"


def test_newsletter_is_benign():
    a = run("02_benign_newsletter.eml")
    assert a.result.verdict == "LIKELY BENIGN"
    assert a.result.score == 0


def test_tricky_email_is_suspicious_despite_passing_auth():
    a = run("03_tricky_shared_doc.eml")
    assert set(a.parsed.auth.values()) == {"pass"}
    assert a.result.verdict == "SUSPICIOUS"
    assert a.result.confidence == "Low"


def test_malay_tax_refund_is_malicious():
    a = run("04_malay_tax_refund.eml")
    assert a.result.verdict == "MALICIOUS"
    flags = {f for u in a.iocs.urls for f in u.flags}
    assert {"userinfo_trick", "ip_host", "anchor_mismatch", "brand_impersonation"} <= flags
    titles = [f.title for f in a.result.findings]
    assert "Display name claims to be 'lhdn'" in titles
    assert "Linked IP has abuse reports" in titles     # not the sender's IP
    assert "Sending IP has abuse reports" in titles    # 203.0.113.88
    content = " ".join(f.evidence for f in a.result.findings if f.category == "Content")
    assert "kata laluan" in content and "dalam masa 24 jam" in content


def test_helpers():
    assert registered_domain("www.maybank2u.com.my") == "maybank2u.com.my"
    assert registered_domain("a.b.evil.com") == "evil.com"
    assert defang("http://evil.com/a") == "hxxp://evil[.]com/a"
    assert brand_impersonation("www.maybank2u.com.my") is None
    assert brand_impersonation("maybank2u-login.xyz")[0] == "maybank"
    assert brand_impersonation("paypa1.com")[0] == "paypal"
    assert brand_impersonation("kldesignmeetup.example") is None


def test_one_letter_lookalike_link_in_a_clean_thread_reply():
    # The hard one: auth passes, it is a reply in a real thread, no urgency.
    # The only lie is one letter: the link shows stonebridge-files but goes
    # to stonebrLdge-files, and the plain-text part carries the genuine link.
    a = run("07_thread_reply_lookalike_link.eml")
    assert set(a.parsed.auth.values()) == {"pass"}
    assert a.result.verdict == "MALICIOUS"
    flags = {f for u in a.iocs.urls for f in u.flags}
    assert {"anchor_lookalike", "text_html_lookalike"} <= flags
    titles = [f.title for f in a.result.findings]
    assert "Link domain imitates the sender's own name" in titles


def test_lookalike_rules_do_not_fire_on_honest_links():
    from triage.iocs import analyse_url, is_lookalike
    # unrelated destination (a tracking link): ordinary mismatch, not a look-alike
    assert "anchor_lookalike" not in analyse_url(
        "https://click.mailer-service.example/t/abc", "https://shop.example-store.com").flags
    # same site, different page or subdomain: nothing at all
    assert analyse_url("https://docs.stonebridge-files.invalid/a",
                       "https://stonebridge-files.invalid/b").flags == []
    assert not is_lookalike("bit.ly", "bit.do")          # too short to judge
    assert is_lookalike("stonebridge-files.invalid", "stonebrldge-files.invalid")
