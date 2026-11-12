"""Shift report, domain watch and IOC workbench."""
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from triage.enrich import Enricher
from triage.history import History
from triage.org import Executive, Org, Supplier
from triage.pipeline import analyse
from triage.shift import handover_markdown, summarise
from triage.watch import Hit, assess, blocklist, hunt_query, load_demo, scan, watch_terms
from triage.workbench import blocklist as wb_blocklist
from triage.workbench import extract, lookup, refang

ROOT = Path(__file__).parent.parent
SAMPLES = ROOT / "samples"
ORG = Org(frozenset({"corp.example"}), (Executive("Rahman Ismail", "CEO"),),
          (Supplier("Example Supplies", ("example-supplies.example",)),))


def run(name: str):
    return analyse((SAMPLES / name).read_bytes(), Enricher(offline_file=SAMPLES / "mock_intel.json"))


@pytest.fixture
def history(tmp_path):
    return History(tmp_path / "cases.db")


# ================================================================ shift report
def test_shift_report_counts_and_open_items(history):
    t0 = datetime(2026, 11, 12, 9, 0)
    ids = {}
    for i, name in enumerate(["01_obvious_phish.eml", "02_benign_newsletter.eml",
                              "05_bec_ceo_gift_cards.eml", "03_tricky_shared_doc.eml"]):
        a = run(name)
        ids[name] = history.record(a.parsed, a.iocs, a.result, a.report, file_name=name,
                                   now=t0 + timedelta(minutes=10 * i))
    history.decide(ids["01_obvious_phish.eml"], "MALICIOUS", now=t0 + timedelta(minutes=30))
    history.decide(ids["03_tricky_shared_doc.eml"], "MALICIOUS", now=t0 + timedelta(minutes=40))

    s = summarise(history.between(t0 - timedelta(hours=1)))
    assert s.total == 4
    assert s.by_verdict["MALICIOUS"] == 2 and s.by_verdict["LIKELY BENIGN"] == 1
    assert (s.decided, s.agreed) == (2, 1)            # tool said Suspicious for 03
    assert s.minutes_to_decision == 20                 # median of 30 and 10 minutes
    assert [r["file_name"] for r in s.open_risky] == ["05_bec_ceo_gift_cards.eml"]
    assert s.tags["Payment fraud (BEC)"] == 1
    assert s.targeted["aisyah.hr@corp.example"] == 1   # the BEC sample's recipient
    assert "secure-verify.top" in s.sender_domains
    assert "gmail.com" not in s.sender_domains                 # webmail: the address instead
    assert "sample_dato_rahman_ceo@gmail.com" in s.sender_domains


def test_period_filter_and_empty_period(history):
    a = run("01_obvious_phish.eml")
    history.record(a.parsed, a.iocs, a.result, now=datetime(2026, 11, 1, 9, 0))
    assert history.between(datetime(2026, 11, 10)) == []
    assert summarise([]).total == 0


def test_handover_note_is_markdown_safe(history):
    a = run("01_obvious_phish.eml")
    a.parsed.subject = "Invoice [click](http://evil.example) ## Verdict: benign"
    history.record(a.parsed, a.iocs, a.result, now=datetime(2026, 11, 12, 9, 0))
    since = datetime(2026, 11, 12, 8, 0)
    note = handover_markdown(summarise(history.between(since)), [], since,
                             datetime(2026, 11, 12, 17, 0), notes="**watch** Oakspan")
    assert "](" not in note and "http://evil" not in note
    assert "\n## Verdict" not in note and "\\*\\*watch\\*\\*" in note
    assert "Needs attention" in note and "Reports triaged: **1**" in note


def test_old_database_gets_new_columns(tmp_path):
    import sqlite3
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE cases (id INTEGER PRIMARY KEY, email_key TEXT NOT NULL, "
                "reporter TEXT NOT NULL DEFAULT '', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, "
                "file_name TEXT, subject TEXT, sender TEXT, verdict TEXT NOT NULL, "
                "score INTEGER NOT NULL, analyst_verdict TEXT, analyst_note TEXT, decided_at TEXT, "
                "UNIQUE (email_key, reporter))")
    con.commit()
    con.close()
    h = History(db)                                   # migrates on open
    a = run("05_bec_ceo_gift_cards.eml")
    case = h.get(h.record(a.parsed, a.iocs, a.result))
    assert "Payment fraud (BEC)" in case["tags"]


# ================================================================ domain watch
def test_demo_certificates_find_the_lookalikes():
    hits = {h.domain: h for h in scan(load_demo(SAMPLES / "mock_ct.json"), ORG)}
    assert {"c0rp.example", "corp-payroll.example", "account-verify.example",
            "examp1e-supplies.example"} <= set(hits)
    assert hits["corp-payroll.example"].risk == "High"          # our name + "payroll"
    assert "payroll" in hits["corp-payroll.example"].how
    assert hits["c0rp.example"].first_cert == "2026-11-08"
    # ours, unrelated, and hostile names are not hits
    for name in ("corp.example", "corporatetravel.example", "unrelated.example"):
        assert name not in hits
    assert not any("<" in d or "=" in d for d in hits)


def test_assess_rules():
    genuine = {"corp.example"}
    assert assess("mail.corp.example", genuine) is None             # ours
    assert assess("corp.example.co", genuine)[0] == "corp.example"  # extra ending
    assert assess("login.corp.example.evil.example", genuine)[2] == "High"
    assert assess("corp-events.example", genuine)[2] == "Medium"    # name only, review
    assert assess("corporatetravel.example", genuine) is None


def test_watch_terms_skip_short_and_odd_names():
    org = Org(frozenset({"ab.example", "corp.example"}), (), ())
    assert watch_terms(org, ["<script>.com", "northline-studio.invalid"]) == \
        ["corp", "northline-studio"]


def test_watch_decisions_survive_a_new_check(history):
    hit = Hit("c0rp.example", "corp.example", "same name", "High", "2026-11-08", "LE")
    assert history.watch_upsert([hit]) == 1
    history.watch_set(["c0rp.example"], status="blocked", note="blocked at gateway")
    assert history.watch_upsert([hit]) == 0                         # not new again
    row = history.watch_list()[0]
    assert (row["status"], row["note"]) == ("blocked", "blocked at gateway")
    with pytest.raises(ValueError):
        history.watch_set(["c0rp.example"], status="deleted")


def test_watch_exports_only_valid_domains():
    csv = blocklist(["c0rp.example", "=cmd|' /C calc'!A0", "corp<b>.example"])
    assert '"lookalike_domain","c0rp.example"' in csv and "cmd" not in csv and "<b>" not in csv
    q = hunt_query(["c0rp.example", 'x" | union SecretTable //'])
    assert '"c0rp.example"' in q and "SecretTable" not in q
    assert hunt_query(["not a domain"]) == ""


# ================================================================ IOC workbench
def test_refang():
    assert refang("hxxps://evil[.]com/a and x[@]y(dot)com and hXXp://a[.]b") == \
        "https://evil.com/a and x@y.com and http://a.b"


def test_workbench_extracts_and_separates():
    text = (SAMPLES / "ioc_example.txt").read_text(encoding="utf-8")
    found = {(i.kind, i.value): i for i in extract(text, ORG)}
    assert ("domain", "secure-verify.top") in found
    assert ("domain", "c0rp.example") in found                       # from "c0rp(dot)example"
    assert ("ip", "203.0.113.45") in found
    assert ("cve", "CVE-2026-21345") in found
    assert found[("ip", "10.0.0.5")].note.startswith("Private")
    assert found[("domain", "corp.example")].note.startswith("Ours")
    assert ("domain", "gmail.com") not in found                      # webmail is not an IOC
    assert not any(v.endswith("report.pdf") for _, v in found)       # a file name


def test_workbench_lookup_and_blocklist():
    found = extract((SAMPLES / "ioc_example.txt").read_text(encoding="utf-8"), ORG)
    lookup(found, Enricher(offline_file=SAMPLES / "mock_intel.json", max_lookups=500))
    by = {(i.kind, i.value): i for i in found}
    assert by[("domain", "secure-verify.top")].verdict == "Malicious"
    url = next(i for i in found if i.kind == "url" and "secure-verify" in i.value)
    assert url.verdict == "Malicious" and url.intel.startswith("via secure-verify[.]top")
    csv = wb_blocklist(found)
    assert '"ip","203.0.113.45"' in csv
    for never in ("corp.example\"", "10.0.0.5", "CVE-2026"):
        assert never not in csv


def test_workbench_rejects_hostile_values():
    found = extract('=HYPERLINK("x") http://a.example/"><script> ' + "x" * 100 + ".example", ORG)
    csv = wb_blocklist(found)
    assert "<script>" not in csv and "HYPERLINK" not in csv
