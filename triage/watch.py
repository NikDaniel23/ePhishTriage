"""Domain watch: find look-alikes of our domains BEFORE they are used.

Every HTTPS certificate is published in public Certificate Transparency (CT)
logs, and attackers need a certificate for their fake login page. So a new
look-alike such as c0rp.example usually shows up in CT days before the first
phishing email. crt.sh is a free search over those logs.

We search CT for each of our names (and our suppliers'), then keep only
names that IMITATE them, using the same look-alike rules as BEC detection.

Everything from CT is outside data: names are validated against a strict
domain pattern before they are stored, displayed, exported or queried.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

import requests

from .bec import lookalike_of
from .iocs import is_legit_domain, registered_domain
from .org import Org
from .respond import DOMAIN_OK, _csv_cell, _kql_list

CT_URL = "https://crt.sh/"
TIMEOUT = 45
MAX_RECORDS = 5000
# Words attackers put next to a brand to make a login page look official.
RISKY_WORDS = {
    "login", "signin", "logon", "sso", "secure", "verify", "verification", "account",
    "auth", "mfa", "2fa", "portal", "payroll", "hr", "invoice", "invoices", "pay",
    "payment", "billing", "support", "helpdesk", "it", "mail", "webmail", "office",
    "update", "password", "reset", "docs", "share", "files", "drive",
}


@dataclass
class Hit:
    domain: str        # registered domain to act on (what you would block)
    imitates: str      # our (or our supplier's) domain it copies
    how: str           # plain-language reason
    risk: str          # High | Medium
    first_cert: str    # earliest certificate date seen (YYYY-MM-DD)
    issuer: str        # who issued the certificate


def genuine_domains(org: Org) -> set[str]:
    return set(org.domains) | {d for sup in org.suppliers for d in sup.domains}


def watch_terms(org: Org, extra: list[str] | None = None) -> list[str]:
    """The names to search CT for: the label of each of our / suppliers' domains."""
    terms = set()
    for d in sorted(genuine_domains(org) | set(extra or [])):
        label = registered_domain(d.lower()).split(".")[0]
        if len(label) >= 4 and re.fullmatch(r"[a-z0-9-]+", label):
            terms.add(label)
    return sorted(terms)


def fetch_ct(term: str, timeout: int = TIMEOUT) -> list[dict]:
    """Certificates whose names contain `term`, from crt.sh (live)."""
    r = requests.get(CT_URL, params={"q": f"%{term}%", "output": "json",
                                     "exclude": "expired"}, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    return data[:MAX_RECORDS] if isinstance(data, list) else []


def load_demo(path: str | Path) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _names(record: dict) -> list[str]:
    raw = f"{record.get('name_value', '')}\n{record.get('common_name', '')}"
    out = []
    for name in raw.splitlines():
        name = name.strip().lower().removeprefix("*.").strip(".")
        if name and len(name) <= 253 and DOMAIN_OK.match(name):
            out.append(name)
    return out


def _issuer(record: dict) -> str:
    m = re.search(r"(?:^|,\s*)(?:O|CN)=([^,]+)", str(record.get("issuer_name", "")))
    return (m.group(1) if m else str(record.get("issuer_name", "")))[:80].strip('"')


def assess(name: str, genuine: set[str]) -> tuple[str, str, str] | None:
    """(imitates, how, risk) if `name` copies one of `genuine` without being one."""
    reg = registered_domain(name)
    if not reg or reg in genuine or is_legit_domain(reg):
        return None
    padded = f".{name}."
    embedded = next((g for g in genuine if f".{g}." in padded), None)
    if embedded:
        imitates, how = embedded, "our full domain hidden inside a longer name"
    else:
        hit = lookalike_of(name, genuine)
        if not hit:
            return None
        imitates, how = hit
    words = set(re.split(r"[-_.]", name))
    risky = sorted(words & RISKY_WORDS)
    strong = how != "our name inside a longer domain"
    risk = "High" if strong or risky else "Medium"
    if risky:
        how += f", with {', '.join(risky[:3])}"
    if name != reg:
        how += f" (seen as {name})"
    return imitates, how, risk


def scan(records: list[dict], org: Org) -> list[Hit]:
    """Look-alike domains in CT records, one per registered domain, riskiest first."""
    genuine = genuine_domains(org)
    found: dict[str, Hit] = {}
    for rec in records:
        date = str(rec.get("not_before", ""))[:10]
        for name in _names(rec):
            verdict = assess(name, genuine)
            if not verdict:
                continue
            imitates, how, risk = verdict
            reg = registered_domain(name)
            old = found.get(reg)
            if old is None:
                found[reg] = Hit(reg, imitates, how, risk, date, _issuer(rec))
            else:
                if date and (not old.first_cert or date < old.first_cert):
                    old.first_cert, old.issuer = date, _issuer(rec)
                if risk == "High" and old.risk != "High":
                    old.risk, old.how = risk, how
    newest_first = sorted(found.values(), key=lambda h: h.first_cert or "", reverse=True)
    return sorted(newest_first, key=lambda h: h.risk != "High")  # stable: High first


def blocklist(domains: list[str]) -> str:
    rows = [("type", "value", "block_at")]
    rows += [("lookalike_domain", d, "mail gateway / web proxy / DNS")
             for d in domains if DOMAIN_OK.match(d)]
    return "\n".join(",".join(_csv_cell(c) for c in row) for row in rows) + "\n"


def hunt_query(domains: list[str], days: int = 30) -> str:
    """Did any of these look-alikes already send us mail or appear in a link?"""
    ok = [d for d in domains if DOMAIN_OK.match(d)]
    if not ok:
        return ""
    vals = _kql_list(ok)
    return (f"// Email from, or linking to, our look-alike domains in the last {days} days\n"
            f"EmailEvents\n| where Timestamp > ago({days}d)\n"
            f"| where SenderFromDomain in~ ({vals})\n"
            "| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, DeliveryAction\n"
            f"| union (EmailUrlInfo | where Timestamp > ago({days}d) | where UrlDomain in~ ({vals})\n"
            "    | project Timestamp, Url, UrlDomain, NetworkMessageId)\n"
            "| order by Timestamp desc")
