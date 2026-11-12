"""Look INSIDE attachments and images, without ever opening or running them.

Two attacks hide here, where link scanners do not look:

  1. HTML ATTACHMENTS. The fake login page is not on a website (which could
     be blocked), it IS the attachment. The victim opens it locally, types a
     password, and the form posts it to the attacker. We read the HTML as
     text and report what it would do: password fields, where the form sends
     data, redirects, and code that hides itself.

  2. QR CODES ("quishing"). The link is drawn as a picture. There is no URL
     in the email for a scanner to check, and the victim opens it on a phone,
     outside the company's web protection. We decode the picture.

"Reading as text" is the safety line: nothing here renders HTML, runs
script or follows a link.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

MAX_IMAGE_BYTES = 8 * 1024 * 1024
URL_IN_TEXT = re.compile(r"""https?://[^\s<>"'\)\]\\]+""", re.I)
# Ways script hides what it does. Normal web pages use some of these; inside
# an EMAIL ATTACHMENT that also asks for a password they are a strong signal.
OBFUSCATION = {
    "atob(": "base64-decodes hidden content",
    "unescape(": "decodes hidden content",
    "fromcharcode": "builds text from character codes",
    "eval(": "runs text as code",
    "document.write(": "writes the page from script",
}
REDIRECT_JS = re.compile(
    r"""(?:window\.|document\.)?location(?:\.href)?\s*=\s*["'](https?://[^"']+)["']"""
    r"""|location\.(?:replace|assign)\(\s*["'](https?://[^"']+)["']""", re.I)
META_URL = re.compile(r"url\s*=\s*['\"]?(https?://[^'\"\s>]+)", re.I)


@dataclass
class HtmlReport:
    """What one HTML attachment would do if someone opened it."""
    filename: str
    password_field: bool = False
    form_actions: list[str] = field(default_factory=list)   # absolute URLs only
    redirects: list[str] = field(default_factory=list)
    obfuscation: list[str] = field(default_factory=list)    # human-readable reasons
    links: list[str] = field(default_factory=list)

    @property
    def urls(self) -> list[str]:
        return list(dict.fromkeys(self.form_actions + self.redirects + self.links))


class _Inspector(HTMLParser):
    def __init__(self, report: HtmlReport) -> None:
        super().__init__()
        self.r = report
        self._in_script = False
        self.script = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "input" and a.get("type", "").lower() == "password":
            self.r.password_field = True
        elif tag == "form":
            action = a.get("action", "").strip()
            if action.lower().startswith(("http://", "https://")):
                self.r.form_actions.append(action)
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = META_URL.search(a.get("content", ""))
            if m:
                self.r.redirects.append(m.group(1))
        elif tag == "a":
            href = a.get("href", "").strip()
            if href.lower().startswith(("http://", "https://")):
                self.r.links.append(href)
        elif tag == "script":
            self._in_script = True

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self.script.append(data)


def inspect_html(filename: str, text: str) -> HtmlReport:
    report = HtmlReport(filename)
    parser = _Inspector(report)
    try:
        parser.feed(text)
    except Exception:
        pass  # malformed HTML is normal in phishing kits: keep what we found
    script = "\n".join(parser.script)
    low = script.lower()
    report.obfuscation = [why for marker, why in OBFUSCATION.items() if marker in low]
    for m in REDIRECT_JS.finditer(script):
        report.redirects.append(m.group(1) or m.group(2))
    # Exfiltration URLs often sit in script (fetch / XMLHttpRequest), not in a form.
    if report.password_field and not report.form_actions:
        report.form_actions += [u.rstrip(".,;") for u in URL_IN_TEXT.findall(script)]
    for name in ("form_actions", "redirects", "links"):
        setattr(report, name, list(dict.fromkeys(getattr(report, name)))[:20])
    return report


def calendar_urls(text: str) -> list[str]:
    """Every URL in a calendar invite (.ics): URL, LOCATION, DESCRIPTION, ATTACH...

    Calendar files wrap long lines by starting the next line with a space,
    which would cut a URL in half, so lines are unfolded first.
    """
    unfolded = re.sub(r"\r?\n[ \t]", "", text)
    found = [u.rstrip(".,;") for u in URL_IN_TEXT.findall(unfolded.replace("\\n", " "))]
    return list(dict.fromkeys(found))[:20]


def qr_supported() -> bool:
    try:
        import cv2  # noqa: F401
        import numpy  # noqa: F401
        return True
    except ImportError:
        return False


def decode_qr(images: list[tuple[str, bytes]]) -> list[tuple[str, str]]:
    """(image name, decoded text) for every QR code found. Empty if none.

    Needs opencv-python-headless. Without it, returns nothing and the
    dashboard says images were not scanned (see qr_supported()).
    """
    try:
        import cv2
        import numpy as np
    except ImportError:
        return []
    found: list[tuple[str, str]] = []
    detector = cv2.QRCodeDetector()
    for name, data in images:
        if not data or len(data) > MAX_IMAGE_BYTES:
            continue
        try:
            img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
            if img is None:
                continue
            ok, texts, *_ = detector.detectAndDecodeMulti(img)
            if not ok:  # small or low-contrast codes: try again enlarged
                big = cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
                ok, texts, *_ = detector.detectAndDecodeMulti(big)
        except Exception:
            continue  # a broken image must never break triage
        for text in (texts or ()) if ok else ():
            if text:
                found.append((name, text.strip()))
    return list(dict.fromkeys(found))
