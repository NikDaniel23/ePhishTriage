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
CREATE TABLE IF NOT EXISTS watch_hits (
    domain TEXT PRIMARY KEY,
    imitates TEXT NOT NULL, how TEXT NOT NULL, risk TEXT NOT NULL,
    first_cert TEXT, issuer TEXT,
    found_at TEXT NOT NULL, last_checked TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',          -- new | blocked | benign
    note TEXT NOT NULL DEFAULT ''
);
"""
# Columns added after the first release. Older databases get them on open.
MIGRATIONS = {
    "recipients": "ALTER TABLE cases ADD COLUMN recipients TEXT NOT NULL DEFAULT ''",
    "tags": "ALTER TABLE cases ADD COLUMN tags TEXT NOT NULL DEFAULT ''",
}


def case_tags(iocs: IOCs, result: Result, report: ReportInfo | None) -> list[str]:
    """Attack types in plain words, for the shift report's 'what hit us' view."""
    flags = {f for u in iocs.urls for f in u.flags}
    cats = {f.category for f in result.findings if f.points}
    titles = " ".join(f.title.lower() for f in result.findings)
    tags = []
    if "BEC" in cats:
        tags.append("Payment fraud (BEC)")
    if flags & {"brand_impersonation", "anchor_lookalike", "embedded_domain"} or "imitates" in titles:
        tags.append("Look-alike domain")
    if "qr_code" in flags:
        tags.append("QR code")
    if "Attachment" in cats:
        tags.append("Malicious attachment")
    if "Impersonation" in cats:
        tags.append("Impersonation")
    if report and report.interacted:
        tags.append("Reporter clicked")
    if not tags and result.verdict != "LIKELY BENIGN":
        tags.append("Credential phishing" if iocs.urls else "Other")
    return tags


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
            have = {row["name"] for row in db.execute("PRAGMA table_info(cases)")}
            for column, sql in MIGRATIONS.items():
                if column not in have:
                    db.execute(sql)

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
        recipients = ", ".join(a.lower() for a in parsed.to if a)[:300]
        tags = "|".join(case_tags(iocs, result, report))
        with self._db() as db:
            db.execute(
                """INSERT INTO cases (email_key, reporter, first_seen, last_seen, file_name,
                                      subject, sender, verdict, score, recipients, tags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT (email_key, reporter) DO UPDATE SET
                       last_seen = excluded.last_seen, verdict = excluded.verdict,
                       score = excluded.score, file_name = excluded.file_name,
                       recipients = excluded.recipients, tags = excluded.tags""",
                (key, reporter, ts, ts, file_name, parsed.subject[:300], parsed.from_addr,
                 result.verdict, result.score, recipients, tags),
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

    def between(self, since: datetime, until: datetime | None = None) -> list[sqlite3.Row]:
        """Cases first seen in [since, until), newest first. ISO strings sort by time."""
        until_s = (until or datetime.max.replace(microsecond=0)).isoformat(timespec="seconds")
        with self._db() as db:
            return db.execute(
                "SELECT * FROM cases WHERE first_seen >= ? AND first_seen < ? "
                "ORDER BY first_seen DESC",
                (since.isoformat(timespec="seconds"), until_s)).fetchall()

    def campaigns_between(self, since: datetime, limit: int = 10) -> list[sqlite3.Row]:
        """Campaigns (infrastructure in 2+ cases) active since `since`."""
        with self._db() as db:
            return db.execute(
                """SELECT a.kind, a.value, COUNT(DISTINCT a.case_id) AS cases,
                          MAX(c.score) AS top_score, MAX(c.last_seen) AS last_seen
                   FROM anchors a JOIN cases c ON c.id = a.case_id
                   GROUP BY a.kind, a.value
                   HAVING COUNT(DISTINCT a.case_id) >= 2 AND MAX(c.last_seen) >= ?
                   ORDER BY cases DESC, last_seen DESC LIMIT ?""",
                (since.isoformat(timespec="seconds"), limit)).fetchall()

    # ------------------------------------------------------------ domain watch
    def watch_upsert(self, hits, now: datetime | None = None) -> int:
        """Save look-alike domains found in certificate logs. Returns how many are new.

        A domain already on the list keeps its status (blocked / benign) and note:
        checking again never undoes an analyst's decision.
        """
        ts = (now or datetime.now()).isoformat(timespec="seconds")
        new = 0
        with self._db() as db:
            for h in hits:
                existed = db.execute("SELECT 1 FROM watch_hits WHERE domain = ?",
                                     (h.domain,)).fetchone()
                db.execute(
                    """INSERT INTO watch_hits (domain, imitates, how, risk, first_cert, issuer,
                                               found_at, last_checked)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT (domain) DO UPDATE SET
                           last_checked = excluded.last_checked, risk = excluded.risk,
                           first_cert = MIN(COALESCE(watch_hits.first_cert, excluded.first_cert),
                                            excluded.first_cert)""",
                    (h.domain, h.imitates, h.how, h.risk, h.first_cert, h.issuer, ts, ts))
                new += 0 if existed else 1
        return new

    def watch_list(self) -> list[sqlite3.Row]:
        order = "CASE status WHEN 'new' THEN 0 WHEN 'blocked' THEN 1 ELSE 2 END"
        risk = "CASE risk WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END"
        with self._db() as db:
            return db.execute(f"SELECT * FROM watch_hits ORDER BY {order}, {risk}, "
                              "first_cert DESC").fetchall()

    def watch_set(self, domains: list[str], status: str | None = None,
                  note: str | None = None) -> None:
        if status is not None and status not in ("new", "blocked", "benign"):
            raise ValueError("status must be new, blocked or benign")
        with self._db() as db:
            for d in domains:
                if status is not None:
                    db.execute("UPDATE watch_hits SET status = ? WHERE domain = ?", (status, d))
                if note is not None:
                    db.execute("UPDATE watch_hits SET note = ? WHERE domain = ?",
                               (note[:500], d))

    def accuracy(self) -> tuple[int, int]:
        """(cases where the tool agreed with the analyst, cases the analyst decided)."""
        with self._db() as db:
            row = db.execute(
                """SELECT COUNT(*) AS decided,
                          COALESCE(SUM(analyst_verdict = verdict), 0) AS agreed
                   FROM cases WHERE analyst_verdict IS NOT NULL""").fetchone()
        return row["agreed"], row["decided"]
