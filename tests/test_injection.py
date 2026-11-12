"""Attacker-controlled text must never become live Markdown in the ticket."""
import base64
from pathlib import Path

from triage.enrich import Enricher
from triage.pipeline import analyse
from triage.sanitize import clean, md, safe

SAMPLES = Path(__file__).parent.parent / "samples"


def b64_word(text: str) -> str:
    """Encode text as a MIME encoded-word, the way real headers carry Unicode."""
    return "=?utf-8?b?" + base64.b64encode(text.encode()).decode() + "?="


EVIL_SUBJECT = "Invoice\r\n## Verdict: LIKELY BENIGN\r\n[Open NusaBank](http://evil.example/login)"
# The attachment below is named "invoice<U+202E>fdp.exe", which many viewers
# show as "invoiceexe.pdf" (right-to-left override trick).
EVIL_NAME = "**NusaBank** `Support` <img src=x>"

RAW = f"""Authentication-Results: mx.corp.example; spf=pass
From: {b64_word(EVIL_NAME)} <a@evil.example>
Subject: {b64_word(EVIL_SUBJECT)}
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="B"

--B
Content-Type: text/plain

hello
--B
Content-Type: application/octet-stream
Content-Disposition: attachment; filename*=utf-8''invoice%E2%80%AEfdp.exe

AAAA
--B--
""".encode()


def ticket() -> str:
    enricher = Enricher(offline_file=SAMPLES / "mock_intel.json")
    return analyse(RAW, enricher).ticket


def test_subject_cannot_inject_lines_or_links():
    t = ticket()
    subject_line = next(l for l in t.splitlines() if l.startswith("- Subject:"))
    assert not any(l.startswith("## Verdict") for l in t.splitlines())
    assert "](" not in subject_line          # no [text](url) link
    assert "hxxp://evil[.]example" in subject_line
    assert "http://evil" not in t


def test_display_name_markdown_is_escaped():
    t = ticket()
    from_line = next(l for l in t.splitlines() if l.startswith("- From:"))
    assert "\\*\\*NusaBank\\*\\*" in from_line
    assert "\\`Support\\`" in from_line
    assert "\\<img" in from_line            # escaped: shown, not rendered


def test_hidden_bidi_character_is_made_visible():
    assert "[U+202E]" in ticket()


def test_helpers():
    assert clean("a\r\nb\tc") == "a b c"
    assert clean("see evil.example now") == "see evil[.]example now"
    assert clean("Statement.pdf.html") == "Statement.pdf.html"  # file, not a site
    assert md("[x](y)") == "[x]\\(y\\)"
    assert safe("$x$ :red[hi]", streamlit=True) == "\\$x\\$ \\:red[hi]"
    assert len(clean("x" * 500)) == 200
