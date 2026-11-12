"""Glue: run steps 0-5 in order and time them."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass

from .enrich import Enricher
from .iocs import IOCs, extract
from .org import load_org
from .parser import ParsedEmail, parse_eml
from .report import ticket_markdown
from .scoring import Result, score
from .unwrap import ReportInfo, unwrap

# Your company's email domains, e.g. "corp.example,corp-mail.example".
# Optional: when set, only emails FROM these domains are treated as reports
# (see unwrap.py for why).
ORG_DOMAINS = {
    d.strip().lower()
    for d in os.getenv("TRIAGE_ORG_DOMAINS", "").split(",")
    if d.strip()
}


@dataclass
class Analysis:
    parsed: ParsedEmail
    iocs: IOCs
    intel: dict
    result: Result
    elapsed: float
    ticket: str
    report: ReportInfo


def apply_report(result: Result, report: ReportInfo) -> None:
    """Adjust confidence and action using what we know about the report."""
    if report.kind == "inline":
        # Half the evidence (the headers) is missing: do not sound sure.
        result.confidence = "Low"
    if report.interacted:
        if result.verdict == "LIKELY BENIGN":
            first = ("The reporter says they interacted with it. The email looks "
                     "benign, but confirm with them what they clicked or entered. ")
        else:
            first = ("URGENT - the reporter says they interacted with it. Treat as a "
                     "possible compromise: reset their password, revoke sessions and "
                     "MFA tokens, review their sign-in logs, and isolate the device "
                     "if an attachment was opened. Then: ")
        result.action = first + result.action


def analyse(raw: bytes, enricher: Enricher, org_domains: set[str] | None = None) -> Analysis:
    start = time.perf_counter()
    ours = org_domains or (ORG_DOMAINS | set(load_org().domains))
    raw, report = unwrap(raw, ours)       # 0. find the real email
    parsed = parse_eml(raw)             # 1. parse
    iocs = extract(parsed)              # 2. extract IOCs
    intel = enricher.enrich_all(iocs)   # 3. enrich
    result = score(parsed, iocs, intel) # 4. score
    apply_report(result, report)
    elapsed = time.perf_counter() - start
    ticket = ticket_markdown(parsed, iocs, intel, result, elapsed, report)  # 5. report
    return Analysis(parsed, iocs, intel, result, elapsed, ticket, report)
