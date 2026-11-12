"""Regression tests: one per bug found in review. Run with:  pytest -q"""
from triage import parser
from triage.enrich import Enricher
from triage.iocs import analyse_url, brand_impersonation, brand_in_text
from triage.parser import parse_eml


# ---- Bug 1: forged Authentication-Results must not fill in missing results
FORGED = b"""Authentication-Results: mx.corp.example; spf=fail
Authentication-Results: attacker.example; spf=pass; dkim=pass; dmarc=pass
From: alert@evil.example
Subject: hi

hello
"""


def test_only_top_auth_header_is_trusted():
    assert parse_eml(FORGED).auth == {"spf": "fail", "dkim": "none", "dmarc": "none"}


def test_trusted_authserv_id_picks_our_gateway(monkeypatch):
    # Attacker puts their fake header ON TOP; we still find our gateway's.
    raw = b"""Authentication-Results: attacker.example; spf=pass; dkim=pass; dmarc=pass
Authentication-Results: mx.corp.example; spf=fail; dkim=fail; dmarc=fail
From: a@evil.example
Subject: hi

hello
"""
    monkeypatch.setattr(parser, "TRUSTED_AUTHSERV_IDS", {"mx.corp.example"})
    assert parse_eml(raw).auth == {"spf": "fail", "dkim": "fail", "dmarc": "fail"}


# ---- Bug 2: a file name in link text is not a website
def test_file_name_in_link_text_is_not_a_mismatch():
    url = "https://www.nusabank.com.my/statements/1"
    assert "anchor_mismatch" not in analyse_url(url, "View report.pdf").flags


def test_real_mismatch_still_caught():
    flags = analyse_url("http://evil.example/x", "https://www.nusabank.com.my/login").flags
    assert "anchor_mismatch" in flags
    flags = analyse_url("http://evil.example/x", "Log in at nusabank.com.my").flags
    assert "anchor_mismatch" in flags


# ---- Bug 3: brand names must not match inside unrelated words
def test_brand_substring_false_positives():
    for host in ("applebees.com", "mycimbreview.com", "googleapis.com"):
        assert brand_impersonation(host) is None, host
    assert brand_in_text("Applebees Catering") is None


def test_brand_impersonation_still_caught():
    assert brand_impersonation("apple-id.com")[0] == "apple"
    assert brand_impersonation("cimb-login.xyz")[0] == "cimb"
    assert brand_impersonation("securepaypal-login.com")[0] == "paypal"
    assert brand_impersonation("maybank2u-login.xyz")[0] == "maybank"
    assert brand_in_text("NusaBank Security") == "nusabank"
    # brands written as two words
    assert brand_in_text("Pos Laju Malaysia") == "poslaju"
    assert brand_in_text("Public Bank Berhad") == "publicbank"
    assert brand_in_text("Apple Bees Catering") == "apple"  # "Apple" alone is a word
    assert brand_in_text("Pineapple Bees") is None


# ---- Bug 4: failed lookups must not be cached
def test_failed_lookup_not_cached(tmp_path, monkeypatch):
    e = Enricher(cache_file=tmp_path / "intel.json")
    monkeypatch.setattr(e, "_live_domain", lambda d: {"note": "VirusTotal rate limit hit"})
    e._lookup("domain", "evil.example")
    assert "domain:evil.example" not in e.cache


def test_good_lookup_is_cached(tmp_path, monkeypatch):
    e = Enricher(cache_file=tmp_path / "intel.json")
    monkeypatch.setattr(e, "_live_domain", lambda d: {"source": "vt", "malicious": 5})
    e._lookup("domain", "evil.example")
    assert e.cache["domain:evil.example"]["data"]["malicious"] == 5
