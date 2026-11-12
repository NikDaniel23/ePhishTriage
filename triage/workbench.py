"""IOC workbench: paste any text, get every indicator out, looked up and ready to block.

Analysts constantly receive messy blobs of indicators: a threat report, a
vendor advisory, a chat message, a colleague's notes, often "defanged"
(hxxp://evil[.]com) so nobody clicks them. Today they copy each one into
five websites by hand.

Steps: refang -> extract -> separate what is safe to ignore -> look up ->
export (defanged for people, validated real values for tools).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .enrich import Enricher
from .iocs import (FILE_EXTS, FREE_WEBMAIL, IOCs, URL_RE, defang, is_legit_domain,
                   registered_domain)
from .org import Org
from .parser import IPV4_RE, is_public_ip
from .respond import DOMAIN_OK, EMAIL_OK, IP_OK, SHA_OK, _csv_cell
from .sanitize import EMAIL_RE
from urllib.parse import urlsplit

MAX_TEXT = 1_000_000
MAX_IOCS = 2000
REFANG = [
    (re.compile(r"\bhxxp(s?)", re.I), r"http\1"),
    (re.compile(r"\bfxp\b", re.I), "ftp"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[\s*@\s*\]|\(\s*@\s*\)|\[at\]|\(at\)", re.I), "@"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
]
HASHES = [("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
          ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
          ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b"))]
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
DOMAIN_IN_TEXT = re.compile(r"(?<![@\w.-])(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}\b", re.I)


@dataclass
class Indicator:
    kind: str           # url | domain | ip | email | sha256 | sha1 | md5 | cve
    value: str          # the real (refanged) value
    note: str = ""      # why it is safe to ignore, if it is
    intel: str = ""     # what the lookup said
    verdict: str = ""   # Malicious | Suspicious | No reports | Not looked up

    @property
    def actionable(self) -> bool:
        """Worth blocking or hunting: not ours, not a known-good site, not private."""
        return not self.note and self.kind != "cve"

    @property
    def defanged(self) -> str:
        return self.value if self.kind in ("sha256", "sha1", "md5", "cve") else defang(self.value)


def refang(text: str) -> str:
    for pattern, repl in REFANG:
        text = pattern.sub(repl, text)
    return text


def _domain_note(domain: str, org: Org) -> str:
    reg = registered_domain(domain)
    suppliers = {d for s in org.suppliers for d in s.domains}
    if reg in org.domains:
        return "Ours: never block"
    if reg in suppliers:
        return "Our supplier"
    if reg in FREE_WEBMAIL:
        return "Free webmail: block the address, not the domain"
    if is_legit_domain(reg):
        return "Known good site"
    return ""


def extract(text: str, org: Org) -> list[Indicator]:
    """Every indicator in `text`, deduplicated, in the order first seen."""
    text = refang(text[:MAX_TEXT])
    found: dict[tuple[str, str], Indicator] = {}

    def add(kind: str, value: str, note: str = "") -> None:
        key = (kind, value)
        if key not in found and len(found) < MAX_IOCS:
            found[key] = Indicator(kind, value, note)

    for url in URL_RE.findall(text):
        url = url.rstrip(".,;:)]}'\"")
        host = (urlsplit(url).hostname or "").lower()
        if not host:
            continue
        if IP_OK.match(host):
            add("url", url, "" if is_public_ip(host) else "Private or internal address")
            add("ip", host, "" if is_public_ip(host) else "Private or internal address")
        elif DOMAIN_OK.match(host):
            note = _domain_note(host, org)
            add("url", url, note)
            add("domain", registered_domain(host), note)
    for addr in EMAIL_RE.findall(text):
        addr = addr.lower().rstrip(".")
        if EMAIL_OK.match(addr):
            dom = addr.rsplit("@", 1)[1]
            note = _domain_note(dom, org)
            add("email", addr, "" if note.startswith("Free webmail") else note)
            if not note:
                add("domain", registered_domain(dom))
    for ip in IPV4_RE.findall(text):
        add("ip", ip, "" if is_public_ip(ip) else "Private or internal address")
    for kind, pattern in HASHES:
        for h in pattern.findall(text):
            add(kind, h.lower())
    for cve in CVE_RE.findall(text):
        add("cve", cve.upper(), "")
    for dom in DOMAIN_IN_TEXT.findall(text):
        dom = dom.lower()
        if dom.rsplit(".", 1)[-1] in FILE_EXTS or not DOMAIN_OK.match(dom):
            continue  # "report.pdf" is a file name, not a site
        add("domain", registered_domain(dom), _domain_note(dom, org))
    return list(found.values())


def _verdict(kind: str, info: dict) -> tuple[str, str]:
    """Turn a raw intel answer into (verdict, short human text)."""
    if not info or "note" in info and len(info) <= 2:
        return "Not known", info.get("note", "No data") if info else "No data"
    parts, verdict = [], "No reports"
    mal = info.get("malicious") or 0
    if kind != "ip":
        if mal >= 3:
            verdict = "Malicious"
        elif mal >= 1:
            verdict = "Suspicious"
        parts.append(f"{mal} vendor(s) flag it" if mal else "no vendor flags it")
    age = info.get("age_days")
    if age is not None:
        parts.append(f"{age} days old")
        if age < 30 and verdict == "No reports":
            verdict = "Suspicious"
    abuse = info.get("abuse_score")
    if abuse is not None:
        parts.append(f"abuse confidence {abuse}%")
        if abuse >= 50:
            verdict = "Malicious"
        elif abuse >= 20 and verdict == "No reports":
            verdict = "Suspicious"
    if info.get("note"):
        parts.append(info["note"])
    return verdict, ", ".join(parts)


def lookup(indicators: list[Indicator], enricher: Enricher) -> None:
    """Look up the actionable domains, IPs and hashes. Fills .intel and .verdict."""
    targets = [i for i in indicators if i.actionable]
    iocs = IOCs(domains=[i.value for i in targets if i.kind == "domain"],
                ips=[i.value for i in targets if i.kind == "ip"],
                hashes=[i.value for i in targets if i.kind == "sha256"])
    intel = enricher.enrich_all(iocs)
    table = {("domain", k): v for k, v in intel.get("domains", {}).items()}
    table |= {("ip", k): v for k, v in intel.get("ips", {}).items()}
    table |= {("sha256", k): v for k, v in intel.get("hashes", {}).items()}
    for ind in indicators:
        # A URL or an address is judged by its domain (or its IP).
        key = (ind.kind, ind.value)
        if ind.kind == "url":
            host = (urlsplit(ind.value).hostname or "").lower()
            key = ("ip", host) if IP_OK.match(host) else ("domain", registered_domain(host))
        elif ind.kind == "email":
            key = ("domain", registered_domain(ind.value.rsplit("@", 1)[1]))
        if ind.kind == "cve":
            ind.verdict, ind.intel = "Reference", "A vulnerability ID, nothing to block"
        elif not ind.actionable:
            ind.verdict, ind.intel = "Ignored", ind.note
        elif key in table:
            ind.verdict, ind.intel = _verdict(key[0], table[key])
            if key != (ind.kind, ind.value):
                ind.intel = f"via {defang(key[1])}: {ind.intel}"
        elif ind.kind == "email":
            ind.verdict, ind.intel = "Not looked up", "Webmail address: check the sender, not the domain"
        else:
            ind.verdict, ind.intel = "Not looked up", ""


def defanged_list(indicators: list[Indicator]) -> str:
    return "\n".join(f"{i.kind}\t{i.defanged}" for i in indicators) + "\n"


BLOCK_AT = {"url": "web proxy", "domain": "web proxy / DNS / mail gateway",
            "ip": "firewall / web proxy", "email": "mail gateway",
            "sha256": "EDR / mail gateway", "sha1": "EDR", "md5": "EDR"}
VALID = {"url": lambda v: bool(URL_RE.fullmatch(v)), "domain": lambda v: bool(DOMAIN_OK.match(v)),
         "ip": lambda v: bool(IP_OK.match(v)), "email": lambda v: bool(EMAIL_OK.match(v)),
         "sha256": lambda v: bool(SHA_OK.match(v)),
         "sha1": lambda v: bool(re.fullmatch(r"[a-f0-9]{40}", v)),
         "md5": lambda v: bool(re.fullmatch(r"[a-f0-9]{32}", v))}


def blocklist(indicators: list[Indicator]) -> str:
    """Real values for tools. Only actionable, validated indicators."""
    rows = [("type", "value", "block_at")]
    rows += [(i.kind, i.value, BLOCK_AT[i.kind]) for i in indicators
             if i.actionable and i.kind in VALID and VALID[i.kind](i.value)]
    return "\n".join(",".join(_csv_cell(c) for c in row) for row in rows) + "\n"


def ticket_table(indicators: list[Indicator]) -> str:
    from .sanitize import md
    lines = ["| Type | Indicator (defanged) | Lookup | Note |", "|---|---|---|---|"]
    for i in indicators:
        lines.append(f"| {i.kind} | {md(i.defanged)} | {md(i.intel or i.verdict)} | "
                     f"{md(i.note) or '-'} |")
    return "\n".join(lines) + "\n"
