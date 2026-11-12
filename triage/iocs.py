"""STEP 2 - Extract Indicators of Compromise (IOCs) and inspect URLs.

IOC = a piece of evidence you can search for or block:
URLs, domains, IP addresses, file hashes, email addresses.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .attachments import HtmlReport, calendar_urls, decode_qr, inspect_html
from .parser import ParsedEmail, domain_of, is_public_ip

URL_RE = re.compile(r"""https?://[^\s<>"'\)\]]+""", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# Splits "maybank2u-login.xyz" or "NusaBank Security" into words.
TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9@$]+")
# File extensions that look like a domain in link text ("report.pdf").
# "zip" and "mov" are also real TLDs; we accept missing those to avoid
# flagging every "Download invoice.zip" link.
FILE_EXTS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "rtf",
    "htm", "html", "png", "jpg", "jpeg", "gif", "zip", "rar", "7z", "mov",
    "mp4", "exe", "eml", "msg", "ics",
}
# Brand names shorter than this ("cimb", "apple", "lhdn") must match a WHOLE
# word, otherwise "applebees.com" or "mycimbreview.com" would be flagged.
# Longer names ("paypal", "maybank") may appear inside a word, which catches
# "securepaypal-login.com".
SHORT_BRAND_LEN = 6
# Endings that make the FRONT of a host name look like a whole domain.
EMBED_TLDS = {"com", "net", "org", "gov", "edu", "my", "co", "io", "uk", "sg", "info", "biz",
              "invalid", "example", "test"}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "s.id",
}
# TLDs that are cheap/free and heavily abused. Not proof, just a weak signal.
SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "icu", "cyou", "cfd", "sbs", "tk", "ml", "ga",
    "cf", "gq", "zip", "mov", "live", "rest", "buzz", "shop",
}
# Country-style suffixes where the registered domain has three parts,
# e.g. maybank2u.com.my. Production code should use the `tldextract` library.
MULTI_SUFFIXES = {
    "com.my", "gov.my", "org.my", "edu.my", "net.my", "co.uk", "org.uk",
    "ac.uk", "gov.uk", "com.au", "com.sg", "co.id", "co.jp", "co.in",
    "com.br", "co.nz", "com.ph", "co.th",
}
# Brand keyword -> the domains that brand really owns. Edit for your SOC.
# "nusabank" is a FICTIONAL bank used by the sample emails.
BRANDS: dict[str, set[str]] = {
    "nusabank": {"nusabank.com.my"},
    "maybank": {"maybank2u.com.my", "maybank.com", "maybank.com.my"},
    "cimb": {"cimb.com", "cimbclicks.com.my", "cimb.com.my"},
    "publicbank": {"pbebank.com", "publicbank.com.my"},
    "lhdn": {"hasil.gov.my"},
    "poslaju": {"pos.com.my"},
    "microsoft": {
        "microsoft.com", "office.com", "live.com", "outlook.com",
        "microsoftonline.com", "sharepoint.com", "office365.com",
    },
    "paypal": {"paypal.com"},
    "google": {
        "google.com", "google.com.my", "gmail.com", "googleusercontent.com",
        "googleapis.com", "youtube.com",
    },
    "apple": {"apple.com", "icloud.com"},
    "netflix": {"netflix.com"},
}
ALL_LEGIT = set().union(*BRANDS.values())
# Free webmail providers. Their DOMAIN is never an indicator to block
# (blocking gmail.com cuts off half your customers); the sender ADDRESS is.
FREE_WEBMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com",
    "hotmail.com", "live.com", "msn.com", "icloud.com", "me.com", "aol.com",
    "proton.me", "protonmail.com", "gmx.com", "mail.com", "yandex.com", "zoho.com",
}

# Attackers swap letters for look-alike digits: paypa1, micr0soft.
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})


@dataclass
class UrlInfo:
    url: str
    host: str
    registered_domain: str
    flags: list[str] = field(default_factory=list)
    anchor_text: str = ""
    imitates: str = ""   # the genuine-looking domain this one is a near-copy of
    source: str = ""     # where it was hiding, if not in the body ("qr.png", "form.html")

    @property
    def defanged(self) -> str:
        return defang(self.url)


@dataclass
class IOCs:
    urls: list[UrlInfo] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    html_reports: list[HtmlReport] = field(default_factory=list)   # one per HTML attachment
    qr: list[tuple[str, str]] = field(default_factory=list)        # (image name, decoded text)


class _LinkParser(HTMLParser):
    """Collects (href, visible text) for every <a> tag in the HTML body."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def defang(value: str) -> str:
    """Make an indicator safe to paste: nobody can click it by accident."""
    return (
        value.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
        .replace("@", "[@]")
    )


def registered_domain(host: str) -> str:
    """'login.secure.evil.com' -> 'evil.com'; 'www.x.com.my' -> 'x.com.my'."""
    host = host.lower().strip(".")
    if not host or IP_HOST_RE.match(host):
        return host
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def levenshtein(a: str, b: str) -> int:
    """Edit distance: how many single-character edits turn a into b."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def normalise(text: str) -> str:
    return re.sub(r"[^a-z]", "", text.lower().translate(HOMOGLYPHS))


def is_legit_domain(reg_domain: str) -> bool:
    return reg_domain in ALL_LEGIT


def _brand_aliases() -> dict[str, set[str]]:
    """Each brand's name plus its own domain labels that contain the name.

    maybank -> {"maybank", "maybanku"}   ("maybanku" is maybank2u, normalised)
    """
    aliases = {}
    for brand, domains in BRANDS.items():
        labels = {brand} | {d.split(".")[0] for d in domains if brand in d}
        aliases[brand] = {normalise(label) for label in labels}
    return aliases


BRAND_ALIASES = _brand_aliases()


def brand_in_text(text: str) -> str | None:
    """Which brand (if any) a host name or display name mentions.

    Works word by word, so "applebees.com" is NOT apple, but
    "apple-id.com", "NusaBank Security" and "paypa1-secure.top" are caught.
    Pairs of neighbouring words are tried too, so brands written as two
    words ("Pos Laju", "Public Bank", "pos-laju.example") are caught.
    """
    words = [normalise(w) for w in TOKEN_SPLIT_RE.split(text.lower())]
    words = [w for w in words if w]
    pairs = [a + b for a, b in zip(words, words[1:])]
    for norm in words + pairs:
        for brand, aliases in BRAND_ALIASES.items():
            if norm in aliases:
                return brand
            if len(brand) >= SHORT_BRAND_LEN and brand in norm:
                return brand
    return None


def brand_impersonation(host: str) -> tuple[str, str] | None:
    """Return (brand, how) if a host pretends to be a brand it does not own."""
    reg = registered_domain(host)
    if is_legit_domain(reg):
        return None
    brand = brand_in_text(host)
    if brand:
        return brand, "brand name used inside a domain the brand does not own"
    label = normalise(reg.split(".")[0])
    for brand in BRANDS:
        limit = 2 if len(brand) >= 8 else 1
        if len(brand) >= 5 and 0 < levenshtein(label, brand) <= limit:
            return brand, "typosquat (one or two characters off the real name)"
    return None


def analyse_url(url: str, anchor_text: str = "") -> UrlInfo:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    reg = registered_domain(host)
    info = UrlInfo(url=url, host=host, registered_domain=reg, anchor_text=anchor_text)

    if IP_HOST_RE.match(host):
        info.flags.append("ip_host")
    if reg in SHORTENERS:
        info.flags.append("shortener")
    if "xn--" in host:
        info.flags.append("punycode")
    if reg.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        info.flags.append("suspicious_tld")
    # "northline-studio.invalid.device-review.invalid": a browser goes to the
    # END of the host name (device-review.invalid). Everything in front is
    # decoration the attacker chose, here a complete genuine-looking domain.
    front = host[: -len(reg) - 1].split(".") if reg and host.endswith("." + reg) else []
    if len(front) >= 2 and front[-1] in EMBED_TLDS and not IP_HOST_RE.match(host):
        info.flags.append("embedded_domain")
        info.imitates = registered_domain(".".join(front))
    if "@" in parts.netloc:
        info.flags.append("userinfo_trick")
    if brand_impersonation(host):
        info.flags.append("brand_impersonation")
    # The text shows one site but the link goes to another.
    shown = shown_domain(anchor_text or "")
    if shown and registered_domain(shown) != reg:
        shown_reg = registered_domain(shown)
        if is_lookalike(shown_reg, reg):
            # "stonebridge-files" shown, "stonebrldge-files" linked. A newsletter
            # may link somewhere unrelated; nobody links one letter away by accident.
            info.flags.append("anchor_lookalike")
            info.imitates = shown_reg
        else:
            info.flags.append("anchor_mismatch")
    return info


def is_lookalike(a: str, b: str) -> bool:
    """True if two different domains have near-identical NAMES.

    Compares the name before the first dot ("stonebridge-files"), which must
    be at least six characters: "bit.ly" and "bit.do" are too short to judge.
    Same name with a different ending (corp.example / corp.example.co) counts.
    """
    a, b = a.lower(), b.lower()
    if a == b:
        return False
    name_a, name_b = a.split(".")[0], b.split(".")[0]
    if min(len(name_a), len(name_b)) < 6:
        return False
    return levenshtein(name_a, name_b) <= 2


def shown_domain(text: str) -> str | None:
    """The website a link's visible text CLAIMS to go to, if it names one.

    "https://www.nusabank.com.my/login" -> "www.nusabank.com.my"
    "Visit nusabank.com.my"             -> "nusabank.com.my"
    "Open report.pdf"                   -> None  (a file name, not a site)
    """
    m = URL_RE.search(text)
    if m:
        return urlsplit(m.group(0)).hostname
    for candidate in DOMAIN_RE.findall(text):
        if candidate.rsplit(".", 1)[-1].lower() not in FILE_EXTS:
            return candidate
    return None


def extract(parsed: ParsedEmail) -> IOCs:
    iocs = IOCs()
    seen: dict[str, UrlInfo] = {}

    link_parser = _LinkParser()
    if parsed.body_html:
        link_parser.feed(parsed.body_html)
    html_urls: list[UrlInfo] = []
    for href, text in link_parser.links:
        if href.lower().startswith("http") and href not in seen:
            seen[href] = analyse_url(href, text)
            html_urls.append(seen[href])
    text_domains: set[str] = set()
    for url in URL_RE.findall(parsed.body_text):
        url = url.rstrip(".,;")
        text_domains.add(registered_domain(urlsplit(url).hostname or ""))
        if url not in seen:
            seen[url] = analyse_url(url)
    # An email has two versions of its body. People see the HTML one; many
    # scanners (and suspicious analysts) read the plain-text one. Putting the
    # genuine link in the text and a near-copy in the HTML hides the attack
    # from exactly the readers who would catch it.
    for info in html_urls:
        twin = next((d for d in text_domains if is_lookalike(d, info.registered_domain)), None)
        if twin and info.registered_domain not in text_domains:
            info.flags.append("text_html_lookalike")
            info.imitates = info.imitates or twin
    # URLs that are NOT in the body: inside HTML attachments and QR codes.
    iocs.html_reports = [inspect_html(n, t) for n, t in parsed.html_attachments]
    for report in iocs.html_reports:
        for url in report.urls:
            if url not in seen:
                seen[url] = analyse_url(url)
                seen[url].flags.append("in_attachment")
                seen[url].source = report.filename
    for cal_name, cal_text in parsed.calendars:
        for url in calendar_urls(cal_text):
            if url not in seen:
                seen[url] = analyse_url(url)
            seen[url].flags.append("in_calendar")
            seen[url].source = seen[url].source or cal_name
    # Emails attached to this email: their links are one level down, where
    # scanners that only read the outer message never look.
    for nested_name, inner in parsed.nested:
        for info in extract(inner).urls:
            if info.url not in seen:
                seen[info.url] = info
            seen[info.url].flags.append("in_attached_email")
            seen[info.url].source = seen[info.url].source or nested_name
    iocs.qr = decode_qr(parsed.images)
    for image_name, text in iocs.qr:
        if text.lower().startswith(("http://", "https://")):
            if text not in seen:
                seen[text] = analyse_url(text)
            seen[text].flags.append("qr_code")
            seen[text].source = image_name
    iocs.urls = list(seen.values())

    domains = {u.registered_domain for u in iocs.urls if not IP_HOST_RE.match(u.host)}
    for addr in (parsed.from_addr, parsed.reply_to, parsed.return_path):
        if addr:
            domains.add(registered_domain(domain_of(addr)))
    iocs.domains = sorted(d for d in domains if d and d not in FREE_WEBMAIL)

    ips = [parsed.origin_ip] if parsed.origin_ip else []
    ips += [u.host for u in iocs.urls if IP_HOST_RE.match(u.host)]
    iocs.ips = sorted({ip for ip in ips if is_public_ip(ip)})

    iocs.hashes = [a.sha256 for a in parsed.attachments]
    iocs.emails = sorted(
        {a for a in (parsed.from_addr, parsed.reply_to, parsed.return_path) if a}
    )
    return iocs
