"""Business Email Compromise: catch the money request, not the innocent invoice."""
from email.message import EmailMessage
from pathlib import Path

from triage.bec import impersonated_executive, own_domain_lookalike
from triage.enrich import Enricher
from triage.iocs import extract
from triage.org import Executive, Org
from triage.parser import parse_eml
from triage.pipeline import analyse
from triage.scoring import score

SAMPLES = Path(__file__).parent.parent / "samples"
ORG = Org(frozenset({"corp.example"}),
          (Executive("Rahman Ismail", "Chief Executive Officer"),
           Executive("Tan Mei Ling", "Chief Financial Officer")))


def run(name: str):
    return analyse((SAMPLES / name).read_bytes(),
                   Enricher(offline_file=SAMPLES / "mock_intel.json"))


def email(sender: str, body: str, reply_to: str = "", subject: str = "Hello") -> bytes:
    m = EmailMessage()
    m["Authentication-Results"] = "mx.corp.example; spf=pass; dkim=pass; dmarc=pass"
    m["From"] = sender
    if reply_to:
        m["Reply-To"] = reply_to
    m["To"] = "finance@corp.example"
    m["Subject"] = subject
    m.set_content(body)
    return bytes(m)


def result(raw: bytes, org: Org = ORG):
    p = parse_eml(raw)
    return score(p, extract(p), {}, org)


def titles(r) -> list[str]:
    return [f.title for f in r.findings]


# ---- the two BEC samples --------------------------------------------------
def test_ceo_gift_card_fraud_is_caught():
    a = run("05_bec_ceo_gift_cards.eml")
    assert set(a.parsed.auth.values()) == {"pass"}        # Gmail passes everything
    assert not a.iocs.urls and not a.parsed.attachments  # nothing to scan
    assert a.result.verdict == "MALICIOUS"
    assert "Uses the name of our Chief Executive Officer" in titles(a.result)
    assert any(t.startswith("Classic BEC pattern") for t in titles(a.result))
    assert "T1657 Financial Theft" in a.result.mitre
    assert a.result.action.startswith("Do not pay")      # BEC playbook, not "block URLs"
    assert "clicked" not in a.result.action


def test_bank_change_from_lookalike_domain_is_caught():
    a = run("06_bec_bank_change_lookalike.eml")
    assert a.result.verdict == "MALICIOUS"
    assert "Sender domain imitates our own" in titles(a.result)


def test_without_bec_rules_the_ceo_fraud_would_be_missed():
    # Why this feature exists: with no knowledge of our org (no executives,
    # no domains) the same email scores far lower.
    raw = (SAMPLES / "05_bec_ceo_gift_cards.eml").read_bytes()
    assert result(raw, Org()).score < result(raw).score
    assert result(raw, Org()).verdict != "MALICIOUS"


def test_webmail_domain_is_not_an_indicator_to_block():
    a = run("05_bec_ceo_gift_cards.eml")
    assert "gmail.com" not in a.iocs.domains
    assert any("gmail.com" in e for e in a.iocs.emails)
    assert "Email address:" in a.ticket


# ---- false positives: normal business must stay quiet --------------------------
def test_real_internal_payment_email_stays_benign():
    raw = email('"Arjun Pillai" <arjun.pillai@corp.example>',
                "Hi team, please process the payment for the outstanding invoice "
                "from Example Supplies by Friday. Thanks.")
    r = result(raw)
    assert r.verdict == "LIKELY BENIGN"
    assert not any(t.startswith("Classic BEC") for t in titles(r))


def test_real_executive_from_our_domain_is_not_impersonation():
    raw = email('"Rahman Ismail" <rahman.ismail@corp.example>', "See you at the town hall.")
    assert not any(f.category == "BEC" for f in result(raw).findings)


def test_executive_name_with_outside_reply_to():
    raw = email('"Rahman Ismail" <rahman.ismail@corp.example>', "Call me.",
                reply_to="sample_rahman_private@gmail.com")
    assert "Executive's name, but replies go outside the company" in titles(result(raw))


def test_name_matching():
    assert impersonated_executive("Dato' Rahman Ismail (CEO)", ORG).name == "Rahman Ismail"
    assert impersonated_executive("Mei Ling Tan", ORG).name == "Tan Mei Ling"  # any order
    assert impersonated_executive("Rahman", ORG) is None                    # one word only
    assert impersonated_executive("Ismail Ahmad", ORG) is None              # different person


def test_lookalike_domains():
    assert own_domain_lookalike("c0rp.example", ORG)            # homoglyph
    assert own_domain_lookalike("corq.example", ORG)            # one letter off
    assert own_domain_lookalike("corp-payroll.example", ORG)    # our name inside
    assert own_domain_lookalike("corp.example.co", ORG)         # extra ending
    assert own_domain_lookalike("mail.corp.example", ORG) is None  # ours
    assert own_domain_lookalike("corporatetravel.example", ORG) is None
    assert own_domain_lookalike("example.com", ORG) is None


def test_phish_with_a_link_and_a_money_angle_keeps_the_link_playbook():
    raw = email('"Payroll" <payroll@secure-verify.top>',
                "Confirm your salary account at http://hr.secure-verify.top/confirm today.")
    r = result(raw)
    assert "Block the sender domain and URLs" in r.action or "Escalate" in r.action
    assert "do not pay or change any bank details" in r.action
