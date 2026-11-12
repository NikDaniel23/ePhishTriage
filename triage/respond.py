"""After the verdict: the three things an analyst does next, pre-written.

  1. HUNT. "Who else received it, and did anyone click?" decides whether this
     is a closed ticket or an incident. hunt_queries() writes the searches.
  2. BLOCK. blocklist_csv() exports the indicators in a form tools can import.
  3. REPLY. reporter_reply() drafts the message back to the person who
     reported it. People who get an answer keep reporting; reporting is the
     SOC's early-warning system.

SECURITY NOTE. Queries and block lists need the REAL indicator (not the
defanged one) because machines consume them. That makes this the one place
where attacker-controlled values leave the tool in executable form, so:
  - every value must match a strict allow-list pattern or it is dropped
    (a sender address like  a"|drop table  never reaches a query)
  - free text (subject, display name) is never put into a query at all
  - CSV cells are guarded against spreadsheet formula injection
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .iocs import FREE_WEBMAIL, IP_HOST_RE, IOCs, is_legit_domain, registered_domain
from .org import Org, load_org
from .parser import ParsedEmail, domain_of
from .scoring import Result
from .unwrap import ReportInfo

DOMAIN_OK = re.compile(r"^(?:[a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$", re.I)
EMAIL_OK = re.compile(r"^[a-z0-9._%+\-]{1,64}@(?:[a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$", re.I)
IP_OK = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
SHA_OK = re.compile(r"^[a-f0-9]{64}$", re.I)
LOOKBACK_DAYS = 7


@dataclass
class Hunt:
    title: str        # what question this answers
    platform: str     # where to run it
    language: str     # for syntax highlighting
    query: str


@dataclass
class Indicators:
    """Validated, de-duplicated indicators that are safe to act on."""
    sender_addresses: list[str]
    sender_domains: list[str]   # attacker-owned only: never webmail, never ours
    link_domains: list[str]
    link_ips: list[str]         # IPs that appear in links: devices may have visited them
    sender_ips: list[str]       # the sending server, only when the attacker runs it
    hashes: list[str]

    def any(self) -> bool:
        return any((self.sender_addresses, self.sender_domains, self.link_domains,
                    self.link_ips, self.sender_ips, self.hashes))


def actionable(parsed: ParsedEmail, iocs: IOCs, org: Org | None = None) -> Indicators:
    org = org if org is not None else load_org()

    def blockable(domain: str) -> bool:
        return bool(DOMAIN_OK.match(domain)) and domain not in org.domains \
            and domain not in FREE_WEBMAIL and not is_legit_domain(domain)

    addresses, domains = [], []
    for addr in (parsed.from_addr, parsed.reply_to, parsed.return_path):
        if not addr or not EMAIL_OK.match(addr):
            continue
        reg = registered_domain(domain_of(addr))
        # A webmail ADDRESS is actionable even though its domain never is.
        if reg in org.domains or (is_legit_domain(reg) and reg not in FREE_WEBMAIL):
            continue
        addresses.append(addr.lower())
        if blockable(reg):
            domains.append(reg)
    links = [u.registered_domain for u in iocs.urls
             if not IP_HOST_RE.match(u.host) and blockable(u.registered_domain)]
    link_ips = [u.host for u in iocs.urls if IP_HOST_RE.match(u.host) and IP_OK.match(u.host)]
    # The sending server is only the attacker's when they own the sending
    # domain. For Gmail or Microsoft 365 it is the provider's shared server:
    # blocking or hunting it would hit millions of legitimate senders.
    sender_reg = registered_domain(domain_of(parsed.from_addr))
    sender_ips = ([parsed.origin_ip] if parsed.origin_ip and IP_OK.match(parsed.origin_ip)
                  and blockable(sender_reg) else [])
    hashes = [a.sha256 for a in parsed.attachments if SHA_OK.match(a.sha256)]

    def uniq(items: list[str]) -> list[str]:
        return sorted(dict.fromkeys(items))

    return Indicators(uniq(addresses), uniq(domains), uniq(links), uniq(link_ips),
                      uniq(sender_ips), uniq(hashes))


def _kql_list(values: list[str]) -> str:
    # Values already passed the allow-list patterns, so no quote can appear.
    return ", ".join(f'"{v}"' for v in values)


def hunt_queries(parsed: ParsedEmail, iocs: IOCs, org: Org | None = None) -> list[Hunt]:
    """Searches that answer: who received it, who clicked, who ran the file."""
    ind = actionable(parsed, iocs, org)
    hunts: list[Hunt] = []
    days = LOOKBACK_DAYS

    sender_filters = []
    if ind.sender_addresses:
        sender_filters.append(f"SenderFromAddress in~ ({_kql_list(ind.sender_addresses)})")
    if ind.sender_domains:
        sender_filters.append(f"SenderFromDomain in~ ({_kql_list(ind.sender_domains)})")
    if sender_filters:
        hunts.append(Hunt(
            "Who else received email from this sender?", "Microsoft Defender XDR (KQL)", "kusto",
            f"EmailEvents\n| where Timestamp > ago({days}d)\n| where "
            + "\n    or ".join(sender_filters)
            + "\n| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject,"
              " DeliveryAction, DeliveryLocation, NetworkMessageId\n| order by Timestamp desc"))

    if ind.link_domains:
        doms = _kql_list(ind.link_domains)
        hunts.append(Hunt(
            "Who received an email containing these links?", "Microsoft Defender XDR (KQL)",
            "kusto",
            f"EmailUrlInfo\n| where Timestamp > ago({days}d)\n| where UrlDomain in~ ({doms})\n"
            "| join kind=inner EmailEvents on NetworkMessageId\n"
            "| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, Url,"
            " DeliveryAction\n| order by Timestamp desc"))
        hunts.append(Hunt(
            "Did anyone click? (Safe Links)", "Microsoft Defender XDR (KQL)", "kusto",
            f"UrlClickEvents\n| where Timestamp > ago({days}d)\n"
            f"| where Url has_any ({doms})\n"
            "| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, IPAddress\n"
            "| order by Timestamp desc"))

    net_terms = ind.link_domains + ind.link_ips
    if net_terms:
        parts = []
        if ind.link_domains:
            parts.append(f"RemoteUrl has_any ({_kql_list(ind.link_domains)})")
        if ind.link_ips:
            parts.append(f"RemoteIP in ({_kql_list(ind.link_ips)})")
        hunts.append(Hunt(
            "Did any device connect to the attacker's site?", "Microsoft Defender XDR (KQL)",
            "kusto",
            f"DeviceNetworkEvents\n| where Timestamp > ago({days}d)\n| where "
            + "\n    or ".join(parts)
            + "\n| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl,"
              " RemoteIP, InitiatingProcessFileName\n| order by Timestamp desc"))
        hunts.append(Hunt(
            "Same question for proxy or DNS logs", "Splunk (SPL)", "splunk-spl",
            f"index=proxy OR index=dns earliest=-{days}d ("
            + " OR ".join(f'"{t}"' for t in net_terms)
            + ")\n| stats count earliest(_time) as first latest(_time) as last by user, src_ip"
              "\n| convert ctime(first) ctime(last)\n| sort - count"))

    if ind.hashes:
        hunts.append(Hunt(
            "Did the attachment land on, or run on, any device?", "Microsoft Defender XDR (KQL)",
            "kusto",
            f"union withsource=SourceTable EmailAttachmentInfo, DeviceFileEvents,"
            f" DeviceProcessEvents\n"
            f"| where Timestamp > ago({days}d)\n| where SHA256 in ({_kql_list(ind.hashes)})\n"
            "| project Timestamp, SourceTable, DeviceName, RecipientEmailAddress, FileName,"
            " FolderPath, InitiatingProcessAccountName\n| order by Timestamp desc"))
    return hunts


def _csv_cell(value: str) -> str:
    """Quote a CSV cell and stop spreadsheets running it as a formula."""
    value = str(value).replace("\r", " ").replace("\n", " ")
    if value[:1] in ("=", "+", "-", "@", "\t"):
        value = "'" + value
    return '"' + value.replace('"', '""') + '"'


def blocklist_csv(parsed: ParsedEmail, iocs: IOCs, org: Org | None = None) -> str:
    """type,value,where-to-block rows. Real values: this file is for machines."""
    ind = actionable(parsed, iocs, org)
    rows = [("type", "value", "block_at")]
    rows += [("sender_address", v, "mail gateway") for v in ind.sender_addresses]
    rows += [("sender_domain", v, "mail gateway") for v in ind.sender_domains]
    rows += [("url_domain", v, "web proxy / DNS") for v in ind.link_domains]
    rows += [("link_ip", v, "firewall / web proxy") for v in ind.link_ips]
    rows += [("sender_ip", v, "mail gateway") for v in ind.sender_ips]
    rows += [("file_sha256", v, "EDR / mail gateway") for v in ind.hashes]
    return "\n".join(",".join(_csv_cell(c) for c in row) for row in rows) + "\n"


def reporter_reply(result: Result, report: ReportInfo | None = None) -> str:
    """A short, human reply to whoever reported the email."""
    name = ""
    if report and report.reporter:
        name = report.reporter.split("@")[0].split(".")[0].capitalize()
    hello = f"Hi {name}," if name else "Hi,"
    clicked = bool(report and report.interacted)
    is_bec = any(f.category == "BEC" for f in result.findings)

    if result.verdict == "MALICIOUS":
        body = ["Thank you for reporting this email. You were right: it is a phishing "
                "attempt, and we have started blocking it for everyone."]
        if is_bec:
            body.append("It was written to trick someone into sending money or gift cards. "
                        "Please do not act on it or reply to it. If you already paid, bought "
                        "anything or shared bank details, tell us right away so we can "
                        "contact the bank.")
        if clicked:
            body.append("You mentioned that you interacted with it. Thank you for telling us, "
                        "that is exactly the right thing to do. To be safe, we will reset your "
                        "password and sign you out of your sessions shortly. Please do not "
                        "enter your password anywhere until we contact you, and let us know "
                        "what you clicked or typed.")
        else:
            body.append("You do not need to do anything else. Please delete the email if it "
                        "is still in your mailbox.")
        body.append("If colleagues mention the same email, ask them to report it too.")
    elif result.verdict == "SUSPICIOUS":
        body = ["Thank you for reporting this email. It has some warning signs, so we are "
                "taking a closer look.",
                "Until you hear back from us, please do not click its links, open its "
                "attachments or reply to it. If you already did, let us know."]
    else:
        body = ["Thank you for reporting this email. We checked it and found no signs of "
                "phishing, so it is safe to treat as normal mail.",
                "Reporting it was still the right call: when in doubt, please keep "
                "sending them our way."]
    return "\n\n".join([hello, *body, "Security Operations"])
