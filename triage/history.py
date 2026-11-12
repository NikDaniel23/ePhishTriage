"""Case history: remember every triaged email, spot campaigns, learn from analysts.

Three real SOC problems this solves:

  1. DUPLICATES. When a phishing wave hits, forty people report the same
     email. Without memory, an analyst triages it forty times.
  2. CAMPAIGNS. Attackers change the subject and the sender name but reuse
     infrastructure. Two emails that share a link domain, a sending address
     or an attachment hash are the same campaign, whatever they look like.
  3. TRUST. Nobody knows whether the tool's verdicts are right unless the
     analyst's final decision is recorded and compared.

Storage is one SQLite file (no server). An "anchor" is a piece of attacker
infrastructure worth matching on: we deliberately do NOT match on subject or
display name, which are free for the attacker to change.
"""
from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .iocs import FREE_WEBMAIL, IP_HOST_RE, IOCs, is_legit_domain, registered_domain
from .org import Org, load_org
from .parser import ParsedEmail, domain_of
from .scoring import Result
from .unwrap import ReportInfo

VERDICTS = ("MALICIOUS", "SUSPICIOUS", "LIKELY BENIGN")

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY,
    email_key TEXT NOT NULL,
    reporter TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    file_name TEXT, subject TEXT, sender TEXT,
    verdict TEXT NOT NULL, score INTEGER NOT NULL,
    analyst_verdict TEXT, analyst_note TEXT, decided_at TEXT,
    UNIQUE (email_key, reporter)
);
CREATE TABLE IF NOT EXISTS anchors (
    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, value TEXT NOT NULL,
    UNIQUE (case_id, kind, value)
);
CREATE INDEX IF NOT EXISTS anchors_value ON anchors (kind, value);
"""


@dataclass
class Related:
    """An earlier case that shares infrastructure with the current one."""
    case_id: int
    first_seen: str
    reporter: str
    subject: str
    sender: str
    verdict: str
    score: int
    analyst_verdict: str | None
    same_email: bool
    shared: list[tuple[str, str]] = field(default_factory=list)  # (kind, value)


def email_key(parsed: ParsedEmail) -> str:
    """Identity of one email, however many people report it."""
    basis = "|".join([parsed.message_id, parsed.from_addr, parsed.subject, parsed.date])
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()


def anchors(parsed: ParsedEmail, iocs: IOCs, org: Org | None = None) -> set[tuple[str, str]]:
    """Attacker infrastructure worth matching campaigns on."""
    org = org if org is not None else load_org()

    # The recipient's own domain is "us" even when org.json does not list it.
    # A forged internal sender would otherwise link every internal email
    # into one fake campaign.
    recipient_regs = {registered_domain(domain_of(addr)) for addr in parsed.to}

    def ours_or_common(domain: str) -> bool:
        return domain in org.domains or domain in recipient_regs or is_legit_domain(domain)

    out: set[tuple[str, str]] = set()
    for label, addr in (("sender", parsed.from_addr), ("reply-to", parsed.reply_to)):
        reg = registered_domain(domain_of(addr))
        if not reg:
            continue
        # Webmail first: gmail.com is also a "legitimate brand domain", but a
        # Gmail ADDRESS used by an attacker is the best anchor a BEC case has.
        if reg in FREE_WEBMAIL:
            out.add((f"{label} address", addr.lower()))
        elif not ours_or_common(reg):
            out.add((f"{label} domain", reg))
    for u in iocs.urls:
        if IP_HOST_RE.match(u.host):
            out.add(("link IP", u.host))
        elif u.registered_domain and not ours_or_common(u.registered_domain) \
                and u.registered_domain not in FREE_WEBMAIL:
            out.add(("link domain", u.registered_domain))
    for att in parsed.attachments:
        out.add(("attachment", att.sha256))
    return out


class History:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def _db(self):
        """Open, commit and always CLOSE (Windows keeps open files locked)."""
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        try:
            yield db
            db.commit()
        finally:
            db.close()

    # ------------------------------------------------------------ write
    def record(self, parsed: ParsedEmail, iocs: IOCs, result: Result,
               report: ReportInfo | None = None, file_name: str = "",
               org: Org | None = None, now: datetime | None = None) -> int:
        """Save (or refresh) this case and return its id.

        The same email from the same reporter is ONE case, so re-opening a
        file never inflates the counts. The same email from a different
        reporter is a new case: that is exactly the campaign signal.
        """
        ts = (now or datetime.now()).isoformat(timespec="seconds")
        key = email_key(parsed)
        reporter = (report.reporter if report else "") or ""
        with self._db() as db:
            db.execute(
                """INSERT INTO cases (email_key, reporter, first_seen, last_seen, file_name,
                                      subject, sender, verdict, score)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT (email_key, reporter) DO UPDATE SET
                       last_seen = excluded.last_seen, verdict = excluded.verdict,
                       score = excluded.score, file_name = excluded.file_name""",
                (key, reporter, ts, ts, file_name, parsed.subject[:300], parsed.from_addr,
                 result.verdict, result.score),
            )
            case_id = db.execute(
                "SELECT id FROM cases WHERE email_key = ? AND reporter = ?", (key, reporter)
            ).fetchone()["id"]
            db.executemany(
                "INSERT OR IGNORE INTO anchors (case_id, kind, value) VALUES (?, ?, ?)",
                [(case_id, kind, value) for kind, value in anchors(parsed, iocs, org)],
            )
        return case_id

    def decide(self, case_id: int, verdict: str, note: str = "",
               now: datetime | None = None) -> None:
        """Record the analyst's final call. This is the ground truth."""
        if verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {VERDICTS}")
        ts = (now or datetime.now()).isoformat(timespec="seconds")
        with self._db() as db:
            db.execute(
                "UPDATE cases SET analyst_verdict = ?, analyst_note = ?, decided_at = ? "
                "WHERE id = ?", (verdict, note[:1000], ts, case_id))

    # ------------------------------------------------------------ read
    def get(self, case_id: int) -> sqlite3.Row | None:
        with self._db() as db:
            return db.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()

    def related(self, case_id: int) -> list[Related]:
        """Earlier or parallel cases sharing at least one anchor, newest first."""
        with self._db() as db:
            me = db.execute("SELECT email_key FROM cases WHERE id = ?", (case_id,)).fetchone()
            if me is None:
                return []
            rows = db.execute(
                """SELECT c.*, theirs.kind AS kind, theirs.value AS value
                   FROM anchors mine
                   JOIN anchors theirs ON theirs.kind = mine.kind AND theirs.value = mine.value
                   JOIN cases c ON c.id = theirs.case_id
                   WHERE mine.case_id = ? AND theirs.case_id != ?
                   ORDER BY c.first_seen DESC""", (case_id, case_id)).fetchall()
            # The same email reported by someone else, even if it has no anchors.
            twins = db.execute(
                "SELECT * FROM cases WHERE email_key = ? AND id != ?",
                (me["email_key"], case_id)).fetchall()
        found: dict[int, Related] = {}
        for row in list(rows) + list(twins):
            rel = found.get(row["id"])
            if rel is None:
                rel = found[row["id"]] = Related(
                    row["id"], row["first_seen"], row["reporter"], row["subject"] or "",
                    row["sender"] or "", row["verdict"], row["score"], row["analyst_verdict"],
                    same_email=row["email_key"] == me["email_key"])
            if "kind" in row.keys():
                rel.shared.append((row["kind"], row["value"]))
        return sorted(found.values(), key=lambda r: r.first_seen, reverse=True)

    def recent(self, limit: int = 15) -> list[sqlite3.Row]:
        """The latest cases, newest first."""
        with self._db() as db:
            return db.execute(
                "SELECT * FROM cases ORDER BY last_seen DESC, id DESC LIMIT ?", (limit,)).fetchall()

    def campaigns(self, limit: int = 10) -> list[sqlite3.Row]:
        """Infrastructure seen in two or more cases: what is hitting us repeatedly."""
        with self._db() as db:
            return db.execute(
                """SELECT a.kind, a.value, COUNT(DISTINCT a.case_id) AS cases,
                          COUNT(DISTINCT NULLIF(c.reporter, '')) AS reporters,
                          MIN(c.first_seen) AS first_seen, MAX(c.last_seen) AS last_seen,
                          MAX(c.score) AS top_score
                   FROM anchors a JOIN cases c ON c.id = a.case_id
                   GROUP BY a.kind, a.value HAVING COUNT(DISTINCT a.case_id) >= 2
                   ORDER BY cases DESC, last_seen DESC LIMIT ?""", (limit,)).fetchall()

    def accuracy(self) -> tuple[int, int]:
        """(cases where the tool agreed with the analyst, cases the analyst decided)."""
        with self._db() as db:
            row = db.execute(
                """SELECT COUNT(*) AS decided,
                          COALESCE(SUM(analyst_verdict = verdict), 0) AS agreed
                   FROM cases WHERE analyst_verdict IS NOT NULL""").fetchone()
        return row["agreed"], row["decided"]
