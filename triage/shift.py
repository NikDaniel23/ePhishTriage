"""Shift report: what happened, what is still open, and the handover note.

At the end of every shift an analyst writes up the same things by hand:
how many reports came in, which were real, what is still waiting, which
campaigns are active, and anything the next shift must know. Everything
except the free-text notes is already in the case history.

Pure functions over case-history rows, so they are easy to test.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from statistics import median

from .iocs import FREE_WEBMAIL, defang, registered_domain
from .parser import domain_of
from .sanitize import md, safe

VERDICT_WORD = {"MALICIOUS": "Malicious", "SUSPICIOUS": "Suspicious",
                "LIKELY BENIGN": "Likely benign"}


@dataclass
class ShiftStats:
    total: int = 0
    by_verdict: Counter = field(default_factory=Counter)      # tool verdicts
    decided: int = 0
    agreed: int = 0
    open_risky: list = field(default_factory=list)            # undecided, not benign
    minutes_to_decision: float | None = None                  # median
    per_day: dict = field(default_factory=dict)               # date -> Counter(verdict)
    tags: Counter = field(default_factory=Counter)
    targeted: Counter = field(default_factory=Counter)        # recipient -> cases
    sender_domains: Counter = field(default_factory=Counter)  # non-benign only


def _ts(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


def summarise(rows) -> ShiftStats:
    s = ShiftStats(total=len(rows))
    waits = []
    for r in rows:
        verdict = r["verdict"]
        s.by_verdict[verdict] += 1
        day = (r["first_seen"] or "")[:10]
        s.per_day.setdefault(day, Counter())[verdict] += 1
        if r["analyst_verdict"]:
            s.decided += 1
            s.agreed += int(r["analyst_verdict"] == verdict)
            start, end = _ts(r["first_seen"]), _ts(r["decided_at"])
            if start and end and end >= start:
                waits.append((end - start).total_seconds() / 60)
        elif verdict != "LIKELY BENIGN":
            s.open_risky.append(r)
        for tag in filter(None, (r["tags"] or "").split("|")):
            s.tags[tag] += 1
        if verdict != "LIKELY BENIGN":
            for rcpt in filter(None, (r["recipients"] or "").split(", ")):
                s.targeted[rcpt] += 1
            dom = registered_domain(domain_of(r["sender"] or ""))
            if dom in FREE_WEBMAIL:  # gmail.com is not the attacker; the address is
                s.sender_domains[(r["sender"] or "").lower()] += 1
            elif dom:
                s.sender_domains[dom] += 1
    s.minutes_to_decision = median(waits) if waits else None
    s.open_risky.sort(key=lambda r: -r["score"])
    return s


def _duration(minutes: float | None) -> str:
    if minutes is None:
        return "-"
    if minutes < 60:
        return f"{minutes:.0f} min"
    return f"{minutes / 60:.1f} h"


def handover_markdown(stats: ShiftStats, campaigns, since: datetime, until: datetime,
                      notes: str = "", analyst: str = "") -> str:
    """The note the next shift reads. Outside values are made Markdown-safe."""
    period = f"{since:%d %b %Y %H:%M} to {until:%d %b %Y %H:%M}"
    mal = stats.by_verdict.get("MALICIOUS", 0)
    sus = stats.by_verdict.get("SUSPICIOUS", 0)
    ben = stats.by_verdict.get("LIKELY BENIGN", 0)
    lines = [
        "## Phishing desk handover",
        f"**Period:** {period}" + (f"  \n**Analyst:** {md(analyst)}" if analyst else ""),
        "",
        "### Summary",
        f"- Reports triaged: **{stats.total}** "
        f"(malicious {mal}, suspicious {sus}, likely benign {ben})",
        f"- Decided by an analyst: {stats.decided} of {stats.total}"
        + (f", tool agreed on {stats.agreed}" if stats.decided else ""),
        f"- Median time to a decision: {_duration(stats.minutes_to_decision)}",
        "",
        "### Needs attention",
    ]
    if stats.open_risky:
        for r in stats.open_risky[:15]:
            lines.append(f"- [{VERDICT_WORD.get(r['verdict'], r['verdict'])} {r['score']}] "
                         f"{safe(r['subject'])} (from {safe(r['sender'])}, "
                         f"first seen {r['first_seen'].replace('T', ' ')})")
        if len(stats.open_risky) > 15:
            lines.append(f"- and {len(stats.open_risky) - 15} more")
    else:
        lines.append("- Nothing open: every malicious or suspicious report has a decision.")

    lines += ["", "### Active campaigns"]
    if campaigns:
        for c in campaigns:
            value = c["value"][:16] + "..." if c["kind"] == "attachment" else defang(c["value"])
            lines.append(f"- {md(c['kind'])} {md(value)}: {c['cases']} cases, "
                         f"top score {c['top_score']}")
    else:
        lines.append("- None: no attacker infrastructure seen in more than one case.")

    if stats.tags:
        lines += ["", "### What hit us"]
        lines += [f"- {md(tag)}: {n}" for tag, n in stats.tags.most_common(6)]
    if stats.targeted:
        lines += ["", "### Most targeted"]
        lines += [f"- {safe(who)}: {n}" for who, n in stats.targeted.most_common(5)]

    lines += ["", "### Notes for the next shift", md(notes.strip()) if notes.strip() else "- None"]
    lines += ["", f"_Generated by ePhishTriage on {until:%d %b %Y %H:%M}._"]
    return "\n".join(lines)
