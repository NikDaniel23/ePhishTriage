"""BEC - Business Email Compromise detection.

BEC is the phishing that steals the most money and trips the fewest alarms:
  - no link, no attachment, so link and malware checks see nothing
  - sent from a real Gmail account or a domain the attacker owns, so
    SPF, DKIM and DMARC all PASS
  - just a short, believable request: "Are you at your desk? I need an urgent
    transfer done before 3pm. Keep this between us."

So instead of looking for malicious THINGS we look for a malicious SITUATION:
someone who is not who they claim to be, asking for money, quietly.

Rules (each returns points and a human-readable reason):
  1. Executive impersonation: one of OUR executives' names, from outside
  2. Executive name with replies diverted outside the company
  3. Look-alike of OUR domain (c0rp.example, corp-payroll.example)
  4. Payment / bank-change / gift-card request
  5. Pretext and secrecy ("are you at your desk", "keep this confidential")
  6. The BEC pattern: a money request with no links or attachments, plus a
     sender red flag. This combination is what lets BEC slip through filters.
"""
from __future__ import annotations

import re

from .iocs import FREE_WEBMAIL, IOCs, levenshtein, normalise, registered_domain
from .org import Org
from .parser import ParsedEmail, domain_of
from .sanitize import clean

CATEGORY = "BEC"


PAYMENT = [
    "wire transfer", "bank transfer", "telegraphic transfer", "fund transfer",
    "make a payment", "process a payment", "process the payment", "urgent payment",
    "outstanding invoice", "overdue invoice", "remittance",
    "new bank account", "new account details", "change of bank", "bank details have changed",
    "updated bank details", "update my bank", "update the bank", "direct deposit",
    "payroll account", "salary account", "receiving account", "beneficiary",
    "vendor record", "remittance details", "payment run",
    "gift card", "itunes card", "google play card", "steam card", "apple card",
    # Bahasa Melayu
    "pindahan wang", "pemindahan wang", "pindahan bank", "akaun bank baru",
    "tukar akaun bank", "butiran bank", "maklumat bank", "bayaran segera",
    "invois tertunggak", "kad hadiah",
]
PRETEXT = [
    "are you available", "are you at your desk", "are you in the office",
    "quick favour", "quick favor", "need a favour", "need a favor",
    "keep this confidential", "keep this between us", "strictly confidential",
    "don't tell", "do not discuss", "i'm in a meeting", "i am in a meeting",
    "can't talk", "cannot take calls", "reply only by email", "respond by email only",
    # Bahasa Melayu
    "ada di pejabat", "boleh tolong", "jangan beritahu", "rahsiakan",
    "sedang mesyuarat", "dalam mesyuarat", "sulit",
]
NAME_RE = re.compile(r"[a-z]+")


def _name_tokens(name: str) -> set[str]:
    return set(NAME_RE.findall(name.lower()))


def impersonated_executive(display_name: str, org: Org):
    """The executive whose full name appears in the display name, if any.

    "Dato' Rahman Ismail (CEO)" matches Rahman Ismail: extra words such as
    titles are fine, but every word of the executive's name must be present,
    so "Rahman" alone does not match. Word order does not matter
    ("Mei Ling Tan" matches Tan Mei Ling).
    """
    shown = _name_tokens(display_name)
    for exe in org.executives:
        needed = _name_tokens(exe.name)
        if needed and needed <= shown:
            return exe
    return None


def own_domain_lookalike(domain: str, org: Org) -> tuple[str, str] | None:
    """(our domain, how) if `domain` imitates one of ours without being it."""
    return lookalike_of(domain, org.domains)


def lookalike_of(domain: str, genuine) -> tuple[str, str] | None:
    """(genuine domain, how) if `domain` imitates one in `genuine` without being one."""
    domain = (domain or "").lower().strip(".")
    if not domain:
        return None
    reg = registered_domain(domain)
    if reg in genuine:
        return None
    label = reg.split(".")[0]
    for ours in genuine:
        our_label = ours.split(".")[0]
        if domain.startswith(ours + "."):
            return ours, "our domain with an extra ending added"
        if normalise(label) == normalise(our_label):
            return ours, "same name, different spelling or ending"
        limit = 2 if len(our_label) >= 8 else 1
        if len(our_label) >= 4 and 0 < levenshtein(normalise(label), normalise(our_label)) <= limit:
            return ours, "one or two characters off our name"
        if our_label in re.split(r"[-_]", label):
            return ours, "our name inside a longer domain"
    return None


def _hits(words: list[str], text: str) -> list[str]:
    return [w for w in words if w in text]


def bec_findings(parsed: ParsedEmail, iocs: IOCs, text: str, org: Org) -> list[tuple]:
    """Return (points, category, title, evidence) tuples for BEC signals.

    `text` is the lower-cased subject + body the language rules search.
    """
    out: list[tuple] = []
    sender = parsed.from_addr
    sender_dom = domain_of(sender)
    sender_reg = registered_domain(sender_dom)
    internal = sender_reg in org.domains
    reply_dom = domain_of(parsed.reply_to)
    shown_sender = clean(sender, 80)

    exe = impersonated_executive(parsed.from_name, org)
    if exe and not internal:
        where = "a free webmail account" if sender_reg in FREE_WEBMAIL else "an outside domain"
        out.append((30, CATEGORY, f"Uses the name of our {exe.title or 'executive'}",
                    f"Shows as \"{clean(parsed.from_name, 80)}\" but was sent from {where} "
                    f"({shown_sender}). Our executives write from our own domain."))
    elif exe and internal and parsed.reply_to and registered_domain(reply_dom) not in org.domains:
        out.append((25, CATEGORY, "Executive's name, but replies go outside the company",
                    f"From {shown_sender} as \"{clean(parsed.from_name, 80)}\", but Reply-To "
                    f"is {clean(parsed.reply_to, 80)}. Your answer would reach the attacker."))

    lookalike = own_domain_lookalike(sender_dom, org)
    if lookalike:
        ours, how = lookalike
        out.append((35, CATEGORY, "Sender domain imitates our own",
                    f"{clean(sender_dom, 80)} looks like {ours}: {how}."))
    reply_lookalike = own_domain_lookalike(reply_dom, org) if reply_dom else None
    if reply_lookalike and not lookalike:
        ours, how = reply_lookalike
        out.append((30, CATEGORY, "Reply-To domain imitates our own",
                    f"Replies go to {clean(reply_dom, 80)}, which looks like {ours}: {how}."))

    # Supplier impersonation: a near-copy of a vendor we really work with.
    supplier_of = {d: sup.name for sup in org.suppliers for d in sup.domains}
    supplier_hit = None
    candidates = [("Sender", sender_dom)] + ([("Reply-To", reply_dom)] if reply_dom else []) \
        + [("Link", u.registered_domain) for u in iocs.urls]
    for what, dom in candidates:
        hit = lookalike_of(dom, set(supplier_of))
        if hit:
            genuine, how = hit
            supplier_hit = (30, "Impersonation",
                            f"{what} domain imitates our supplier {supplier_of[genuine]}",
                            f"{clean(dom, 80)} looks like {genuine}: {how}. Fake supplier "
                            "file shares and invoices are a common route to payment fraud.")
            out.append(supplier_hit)
            break

    pay = _hits(PAYMENT, text)
    if pay:
        out.append((20, CATEGORY, "Asks for a payment or a change of bank details",
                    "Found: " + ", ".join(pay[:4])))
    pretext = _hits(PRETEXT, text)
    if pretext:
        out.append((10, CATEGORY, "Pretext or secrecy language",
                    "Found: " + ", ".join(pretext[:4]) + ". Attackers isolate the target "
                    "so nobody double-checks."))

    red_flag = bool(exe and not internal) or bool(lookalike) or bool(reply_lookalike) \
        or bool(supplier_hit) \
        or sender_reg in FREE_WEBMAIL \
        or bool(parsed.reply_to and registered_domain(reply_dom) != sender_reg)
    if pay and not iocs.urls and not parsed.attachments and red_flag:
        out.append((20, CATEGORY, "Classic BEC pattern: money request with no links or files",
                    "Nothing for a filter to scan: the attack is the request itself. "
                    "This is how BEC passes link and attachment checks."))
    return out
