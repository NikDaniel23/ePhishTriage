"""Make attacker-controlled text safe to DISPLAY.

Subject, display name, attachment file name, link text... the attacker wrote
all of these. If we paste them raw into Markdown (the ticket, the dashboard)
they can:

  - inject a clickable link:     Subject: [Open NusaBank](http://evil.example)
  - inject new lines / headings: Subject: hi\\n## Verdict: LIKELY BENIGN
  - hide characters:             invoice<U+202E>fdp.exe  shows as  invoiceexe.pdf

This is the same family of bug as XSS: untrusted data treated as markup.
The fix is the same too: neutralise it at the point of output.

Two steps, always in this order:
  clean(value)  -> one line, invisible chars made visible, URLs defanged
  md(value)     -> escape Markdown so the text renders literally
"""
from __future__ import annotations

import re

from .iocs import DOMAIN_RE, FILE_EXTS, URL_RE, defang

MAX_LEN = 200

EMAIL_RE = re.compile(r"[\w.+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,}", re.I)
# URL first so "http://a.com" is defanged as one piece, then emails, then
# bare domains (chat tools and ticket systems auto-link "evil.com").
LINKISH_RE = re.compile(
    f"{URL_RE.pattern}|{EMAIL_RE.pattern}|{DOMAIN_RE.pattern}", re.I
)
# Bidi overrides and zero-width characters: used to disguise file names and
# hide words. We show them as [U+202E] instead of deleting them, because
# their presence is itself evidence.
INVISIBLE_RE = re.compile("[​-‏‪-‮⁦-⁩﻿]")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")

# Characters that mean something in Markdown. "[" and "]" are left alone so
# defanged text like evil[.]com stays readable; escaping "(" and ")" is
# enough to stop [text](url) from becoming a link.
MD_SPECIAL = "\\`*_()<>|~!#"
# Extra syntax Streamlit adds on top of Markdown: $LaTeX$ and :red[colour].
STREAMLIT_SPECIAL = "$:"


def _defang_match(m: re.Match) -> str:
    text = m.group(0)
    # "Statement.pdf.html" looks like a domain but is a file name.
    if "://" not in text and "@" not in text:
        if text.rsplit(".", 1)[-1].lower() in FILE_EXTS:
            return text
    return defang(text)


def clean(value: str | None, max_len: int = MAX_LEN) -> str:
    """Attacker text -> single safe line (still needs md() for Markdown)."""
    text = str(value or "")
    text = INVISIBLE_RE.sub(lambda m: f"[U+{ord(m.group(0)):04X}]", text)
    text = CONTROL_RE.sub(" ", text)  # kills \r\n: no injected lines
    text = " ".join(text.split())
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return LINKISH_RE.sub(_defang_match, text)


def md(value: str | None, streamlit: bool = False) -> str:
    """Escape Markdown so the text is shown exactly as written."""
    special = MD_SPECIAL + (STREAMLIT_SPECIAL if streamlit else "")
    return "".join("\\" + ch if ch in special else ch for ch in str(value or ""))


def safe(value: str | None, streamlit: bool = False) -> str:
    """clean() then md(): use this for any attacker text going into Markdown."""
    return md(clean(value), streamlit=streamlit)
