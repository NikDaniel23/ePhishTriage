"""STEP 4 - Turn evidence into a score, a verdict and a recommended action.

Design rule: every point added must come with a human-readable reason.
An analyst will not trust a number they cannot explain to their L2.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .iocs import (
    IOCs,
    brand_in_text,
    defang,
    is_legit_domain,
    levenshtein,
    registered_domain,
)
from .bec import bec_findings
from .org import Org, load_org
from .parser import ParsedEmail, domain_of
from .sanitize import clean

MALICIOUS_AT = 60
SUSPICIOUS_AT = 25

URGENCY = [
    "urgent", "immediately", "within 24 hours", "suspended", "final notice",
    "account will be closed", "act now", "unusual activity",
    # Bahasa Melayu
    "segera", "serta-merta", "digantung", "dalam masa 24 jam",
    "tindakan segera", "notis terakhir",
]
CREDENTIAL_ASK = [
    "confirm your password", "enter your password", "verify your account",
    "verify your identity", "update your payment", "confirm your details",
    # Bahasa Melayu
    "kata laluan", "nombor tac", "sahkan akaun", "kemas kini maklumat",
]
RISKY_EXT = {
    "exe", "scr", "js", "vbs", "bat", "cmd", "ps1", "lnk", "iso", "img",
    "hta", "html", "htm", "docm", "xlsm", "jar", "msi",
}
DOUBLE_EXT_RE = re.compile(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(\w+)$", re.I)

URL_RULES = {
    # flag: (points, title, explanation)
    "brand_impersonation": (30, "Link impersonates a known brand",
                            "The domain uses a brand name it does not own."),
    "anchor_lookalike": (45, "Link goes to a near-copy of the site it displays",
                         "The real destination is one or two characters off the "
                         "address shown. That does not happen by accident."),
    "text_html_lookalike": (15, "Plain-text and HTML versions link to different look-alike sites",
                            "The text version carries the genuine link, the version "
                            "people actually see carries the near-copy."),
    "embedded_domain": (35, "Link puts a genuine-looking domain in front of the real one",
                        "A browser goes to the END of the host name. Everything before "
                        "it is decoration chosen by the attacker."),
    "qr_code": (25, "Link hidden in a QR code",
                "No clickable link for a scanner to check, and QR codes are opened "
                "on phones, outside the company's web protection."),
    "anchor_mismatch": (20, "Link text does not match its destination",
                        "The visible text shows one site but the link goes elsewhere."),
    "ip_host": (20, "Link points to a raw IP address",
                "Legitimate services use domain names, not bare IPs."),
    "punycode": (15, "Link uses punycode (possible look-alike letters)",
                 "xn-- domains can imitate real ones with foreign characters."),
    "userinfo_trick": (15, "Link hides its real host with an @ sign",
                       "Everything before @ in a URL is ignored by the browser."),
    "shortener": (8, "Link uses a URL shortener",
                  "The real destination is hidden."),
    "suspicious_tld": (8, "Link uses a frequently abused top-level domain",
                       "Cheap TLDs are popular for throwaway phishing sites."),
}


@dataclass
class Finding:
    points: int
    category: str
    title: str
    evidence: str


@dataclass
class Result:
    score: int
    verdict: str
    confidence: str
    action: str
    findings: list[Finding] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)


def _strip_html(html: str) -> str:
    return re.sub(r"<[^>]+>", " ", html)


def score(parsed: ParsedEmail, iocs: IOCs, intel: dict, org: Org | None = None) -> Result:
    org = org if org is not None else load_org()
    findings: list[Finding] = []

    def add(points: int, category: str, title: str, evidence: str) -> None:
        findings.append(Finding(points, category, title, evidence))

    # ---- 1. Sender authentication -----------------------------------------
    auth = parsed.auth
    if auth["spf"] == "fail":
        add(15, "Authentication", "SPF failed",
            "The sending server is not allowed to send for this domain.")
    elif auth["spf"] == "softfail":
        add(8, "Authentication", "SPF soft-failed",
            "The sending server is probably not allowed to send for this domain.")
    from_reg = registered_domain(parsed.from_domain)
    recipient_regs = {registered_domain(domain_of(a)) for a in parsed.to}
    claims_internal = bool(from_reg) and (from_reg in org.domains or from_reg in recipient_regs)
    rp_reg = registered_domain(domain_of(parsed.return_path)) if parsed.return_path else ""
    reply_reg = registered_domain(domain_of(parsed.reply_to)) if parsed.reply_to else ""

    # Mailing lists re-send mail from their own servers, which normally breaks
    # DKIM and DMARC for the original sender. That is routine, not an attack,
    # PROVIDED the email gives an attacker nothing: every link goes back to
    # the claimed sender's own site, there is no attachment, replies are not
    # redirected, and it does not claim to be from inside our organisation.
    # (List-Id is attacker-writable, so the header alone excuses nothing.)
    list_reg = registered_domain(parsed.list_id.strip().strip("<>").split("<")[-1].lower()) \
        if parsed.list_id else ""
    list_forward = bool(
        list_reg and list_reg == rp_reg and auth["spf"] == "pass" and not claims_internal
        and iocs.urls and all(u.registered_domain == from_reg for u in iocs.urls)
        and not parsed.attachments and (not reply_reg or reply_reg == from_reg))

    failed = [m.upper() for m in ("dkim", "dmarc") if auth[m] == "fail"]
    if failed and list_forward:
        add(0, "Authentication", f"{' and '.join(failed)} failed, explained by a mailing list",
            f"Re-sent by the list at {defang(list_reg)}, which breaks the original "
            f"signature. Every link goes to the sender's own site ({defang(from_reg)}), "
            "so a forger would gain nothing.")
    else:
        if auth["dkim"] == "fail":
            add(10, "Authentication", "DKIM failed",
                "The signature is invalid; the message may have been altered or forged.")
        if auth["dmarc"] == "fail":
            add(20, "Authentication", "DMARC failed",
                "The From domain's own policy says this message is not genuine.")
    if claims_internal and auth["dmarc"] == "fail":
        add(30, "Impersonation", "Claims to be internal, but failed DMARC",
            f"The From address uses our own domain ({defang(from_reg)}) yet the message "
            + (f"was actually sent through {defang(rp_reg)}. " if rp_reg and rp_reg != from_reg
               else "did not come from our servers. ")
            + "Real internal mail does not fail our own DMARC.")
    if parsed.auth_conflicts:
        add(15, "Authentication", "A planted header claims authentication passed",
            "A second Authentication-Results header, below our gateway's, says "
            f"{', '.join(m.upper() for m in parsed.auth_conflicts)} passed. Our gateway says "
            "otherwise. Only an attacker benefits from adding that.")
    if set(auth.values()) == {"none"}:
        add(0, "Authentication", "No authentication results in headers",
            "Cannot verify the sender. Re-export the email from the mail gateway.")

    # ---- 2. Header mismatches ----------------------------------------------
    if parsed.reply_to:
        if reply_reg != from_reg:
            add(15, "Headers", "Reply-To goes to a different domain",
                f"From {defang(parsed.from_addr)} but replies go to "
                f"{defang(parsed.reply_to)}.")
            # oakspan.invalid -> oakspan-finance.invalid: the sender's name
            # reused in a different domain, so the diversion looks official.
            mine = {t for t in re.split(r"[-_]", from_reg.split(".")[0]) if len(t) >= 5}
            theirs = set(re.split(r"[-_]", reply_reg.split(".")[0]))
            if mine & theirs:
                add(25, "Impersonation", "Reply-To domain is a variation of the sender's",
                    f"{defang(reply_reg)} reuses \"{sorted(mine & theirs)[0]}\" from "
                    f"{defang(from_reg)} but is a different domain. Replies, and whatever "
                    "you send in them, leave the real sender's control.")
    if parsed.return_path and not list_forward:
        if rp_reg != from_reg:
            add(5, "Headers", "Return-Path differs from From domain",
                f"Bounces go to {defang(parsed.return_path)}. Common with "
                "mailing services, so this is a weak signal.")

    brand = brand_in_text(parsed.from_name)
    if brand and not is_legit_domain(from_reg):
        add(25, "Impersonation", f"Display name claims to be '{brand}'",
            f"Sender shows as \"{clean(parsed.from_name, 80)}\" but the address is "
            f"{defang(parsed.from_addr)}, which {brand} does not own.")

    # ---- 3. URLs -------------------------------------------------------------
    seen: set[tuple[str, str]] = set()
    for url in iocs.urls:
        for flag in url.flags:
            key = (flag, url.registered_domain)
            if key in seen or flag not in URL_RULES:
                continue
            seen.add(key)
            points, title, why = URL_RULES[flag]
            copy_of = f" Imitates {defang(url.imitates)}." if url.imitates else ""
            where = f" Found in {clean(url.source, 60)}." if url.source else ""
            add(points, "URL", title, f"{url.defanged} - {why}{copy_of}{where}")

    # A link that imitates the SENDER's own name: "stonebrldge-files" in an
    # email from stonebridge-design. Typical of a hijacked thread or a
    # compromised supplier mailbox, where everything else is genuine.
    def name_parts(domain: str) -> list[str]:
        return [t for t in re.split(r"[-_.]", domain.rsplit(".", 1)[0]) if len(t) >= 6]

    for url in iocs.urls:
        hit = next(((mine, theirs) for theirs in name_parts(url.registered_domain)
                    for mine in name_parts(from_reg)
                    if theirs != mine and levenshtein(theirs, mine) <= (2 if len(mine) >= 9 else 1)),
                   None)
        if hit:
            add(25, "URL", "Link domain imitates the sender's own name",
                f"{defang(url.registered_domain)} contains \"{hit[1]}\", a near-copy of "
                f"\"{hit[0]}\" in the sender's domain. If the sender is genuine, their "
                "mailbox may be compromised: warn them by phone, not by reply.")
            break

    # ---- 4. Threat intelligence --------------------------------------------
    for domain, info in intel.get("domains", {}).items():
        mal = info.get("malicious") or 0
        if mal >= 3:
            add(40, "Threat intel", "Domain flagged malicious",
                f"{defang(domain)}: {mal} security vendors flag it.")
        elif mal >= 1:
            add(20, "Threat intel", "Domain flagged by a few vendors",
                f"{defang(domain)}: {mal} vendor(s) flag it.")
        age = info.get("age_days")
        if age is not None and age < 30:
            add(20, "Threat intel", "Domain registered very recently",
                f"{defang(domain)} is {age} days old. Phishing domains are "
                "usually used within days of registration.")
        elif age is not None and age < 90:
            add(10, "Threat intel", "Domain is fairly new",
                f"{defang(domain)} is {age} days old.")
    for ip, info in intel.get("ips", {}).items():
        abuse = info.get("abuse_score") or 0
        if abuse >= 50:
            # iocs.ips mixes the sender's IP with IPs found in links.
            role = "Sending IP" if ip == parsed.origin_ip else "Linked IP"
            add(20, "Threat intel", f"{role} has abuse reports",
                f"{defang(ip)}: abuse confidence {abuse}%.")
    hash_to_name = {a.sha256: a.filename for a in parsed.attachments}
    for sha, info in intel.get("hashes", {}).items():
        mal = info.get("malicious") or 0
        if mal >= 1:
            add(50, "Threat intel", "Attachment is known malware",
                f"{clean(hash_to_name.get(sha, 'attachment'), 80)} (sha256 {sha[:16]}...): "
                f"{mal} vendors flag it.")

    # ---- 5b. Links inside calendar invites and attached emails -----------------
    body_regs = {u.registered_domain for u in iocs.urls if not u.source}
    stray = [u for u in iocs.urls if "in_calendar" in u.flags
             and u.registered_domain != from_reg and u.registered_domain not in body_regs]
    if stray:
        add(25, "Attachment", "Calendar invite links somewhere the email does not mention",
            f"'{clean(stray[0].source, 60)}' opens {defang(stray[0].registered_domain)}, which "
            "is neither the sender's site nor the link shown in the email. Calendar links "
            "are clicked from the calendar, long after any email warning is forgotten.")
    for nested_name, inner in parsed.nested:
        inner_from = registered_domain(inner.from_domain)
        links = [u for u in iocs.urls if "in_attached_email" in u.flags]
        away = [u for u in links if u.registered_domain not in (from_reg, inner_from)]
        shown = clean(nested_name, 60)
        if away:
            add(40, "Attachment", "Link hidden inside an attached email",
                f"The only way to {defang(away[0].registered_domain)} is through '{shown}', "
                "an email attached to this one. Scanners read the outer message; the link "
                "sits one level down and leaves the sender's own domain.")
        if links and not inner.hops:
            add(15, "Attachment", "Attached email was never delivered by a mail server",
                f"'{shown}' has no Received headers. A genuinely forwarded email keeps "
                "them: this one was written to be attached.")
        if links and inner.body_html and "http" not in inner.body_text.lower():
            add(10, "Attachment", "Attached email shows its link only in the HTML version",
                f"The plain-text part of '{shown}' has no link, so text-based checks see "
                "nothing.")
        break  # one attached email is enough to make the point

    # ---- 5a. Inside HTML attachments (see attachments.py) ---------------------
    for rep in iocs.html_reports:
        shown = clean(rep.filename, 80)
        hosts = sorted({urlsplit(u).hostname or "" for u in rep.form_actions} - {""})
        if rep.password_field and hosts:
            add(35, "Attachment", "Attachment is a login form that sends passwords outside",
                f"'{shown}' has a password field and sends what is typed to "
                f"{', '.join(defang(h) for h in hosts[:3])}.")
        elif rep.password_field:
            add(30, "Attachment", "Attachment contains a password form",
                f"'{shown}' asks for a password. A genuine document never does.")
        if rep.redirects:
            targets = sorted({urlsplit(u).hostname or "" for u in rep.redirects} - {""})
            add(15, "Attachment", "Attachment redirects to another site",
                f"'{shown}' sends the reader to {', '.join(defang(h) for h in targets[:3])}.")
        if rep.obfuscation:
            add(15, "Attachment", "Attachment hides its code",
                f"'{shown}': script that {'; '.join(rep.obfuscation[:3])}.")

    # ---- 5. Attachments ------------------------------------------------------
    for att in parsed.attachments:
        ext = att.filename.rsplit(".", 1)[-1].lower() if "." in att.filename else ""
        if DOUBLE_EXT_RE.search(att.filename):
            add(25, "Attachment", "Attachment uses a double extension",
                f"'{clean(att.filename, 80)}' pretends to be a document but is a .{ext} file.")
        elif ext in RISKY_EXT:
            add(20, "Attachment", "Attachment has a risky file type",
                f"'{clean(att.filename, 80)}' (.{ext}) can run code or host a fake login page.")

    # ---- 6. Language ---------------------------------------------------------
    text = " ".join(
        [parsed.subject, parsed.body_text, _strip_html(parsed.body_html)]
    ).lower()
    hits = [w for w in URGENCY if w in text]
    if hits:
        add(10, "Content", "Urgent or threatening language",
            "Found: " + ", ".join(hits[:4]))
    hits = [w for w in CREDENTIAL_ASK if w in text]
    if hits:
        add(15, "Content", "Asks for credentials or account details",
            "Found: " + ", ".join(hits[:4]))

    # ---- 7. Business email compromise (see bec.py) -----------------------------
    for finding in bec_findings(parsed, iocs, text, org):
        add(*finding)
    is_bec = any(f.category == "BEC" for f in findings)

    # ---- Verdict ---------------------------------------------------------------
    findings.sort(key=lambda f: f.points, reverse=True)
    total = min(100, sum(f.points for f in findings))

    if total >= MALICIOUS_AT:
        verdict = "MALICIOUS"
        action = (
            "Block the sender domain and URLs at the mail gateway and proxy. "
            "Purge the email from all mailboxes. Search proxy logs for anyone "
            "who clicked. Escalate to L2 if a user clicked or opened the attachment."
        )
    elif total >= SUSPICIOUS_AT:
        verdict = "SUSPICIOUS"
        action = (
            "Do not close. Escalate to L2 with this report, or confirm with the "
            "named sender through a separate channel (phone, chat)."
        )
    else:
        verdict = "LIKELY BENIGN"
        action = (
            "No indicators found. Close as legitimate and thank the reporter. "
            "Re-open if the same sender is reported again."
        )

    if is_bec and verdict != "LIKELY BENIGN":
        if iocs.urls or parsed.attachments:
            # A phish with a link AND a money angle: keep the link playbook,
            # add the payment warning.
            action += (
                " It also asks for money or bank details: do not pay or change any "
                "bank details without calling the requester on a number you already have."
            )
        else:
            # Pure BEC has no link to block or file to scan: it is stopped by a
            # phone call and by Finance, so it gets its own playbook.
            action = (
                ("" if verdict == "MALICIOUS" else "Treat as possible BEC until confirmed. ")
                + "Do not pay and do not change any bank details. Confirm the request by "
                "calling the person on a number you already have, never one from this "
                "email. Alert Finance to hold pending payments to this recipient. Block the "
                "sender address (and the domain if it imitates ours), purge the email from "
                "all mailboxes, and check whether anyone replied or paid: if money was "
                "sent, contact the bank immediately to recall the transfer."
            )

    auth_all_pass = set(auth.values()) == {"pass"}
    if total >= 75 or (total < 15 and auth_all_pass):
        confidence = "High"
    elif SUSPICIOUS_AT <= total < MALICIOUS_AT:
        confidence = "Low"  # the grey zone is exactly where a human is needed
    else:
        confidence = "Medium"

    mitre = []
    if iocs.urls:
        mitre.append("T1566.002 Phishing: Spearphishing Link")
    if parsed.attachments:
        mitre.append("T1566.001 Phishing: Spearphishing Attachment")
    if any(f.category == "Impersonation" or "imitates our own" in f.title
           or f.title.startswith("Uses the name of our") or f.title.startswith("Executive's name")
           for f in findings):
        mitre.append("T1656 Impersonation")
    if any(f.category == "BEC" and "payment" in f.title for f in findings):
        mitre.append("T1657 Financial Theft")
    if verdict == "LIKELY BENIGN":
        mitre = []

    return Result(total, verdict, confidence, action, findings, mitre)
