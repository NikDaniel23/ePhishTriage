"""Triage page: analyse reported emails, one or a whole queue.

Look: .streamlit/config.toml (Streamlit's own widgets) + ui/console.css.
Security rule for this file: every value that came from the email is passed
through esc() before it goes into HTML. esc() = clean() + html.escape(), so
attacker text is shown, never rendered (see triage/sanitize.py).
"""
import hashlib
import html
import os
from collections import Counter
from datetime import datetime
from pathlib import Path

import streamlit as st

from triage.attachments import qr_supported
from triage.enrich import Enricher
from triage.history import History
from triage.iocs import defang
from triage.parser import domain_of
from triage.pipeline import analyse
from triage.report import llm_summary
from triage.respond import blocklist_csv, hunt_queries, reporter_reply
from triage.sanitize import clean
from triage.scoring import MALICIOUS_AT, SUSPICIOUS_AT
from triage.unwrap import UnsupportedFormat
from ui.kit import esc, icon, raw_esc, section, show

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = sorted((ROOT / "samples").glob("*.eml"))


def tone(result: str) -> str:
    """Authentication result -> card colour."""
    return {"pass": "ok", "fail": "bad", "softfail": "warn"}.get(result, "none")


def severity(points: int) -> tuple[str, str]:
    """How much one finding moves the score -> (colour, word)."""
    if points >= 30:
        return "bad", "High"
    if points >= 15:
        return "warn", "Medium"
    if points > 0:
        return "none", "Low"
    return "none", "Info"



# ------------------------------------------------------------- the queue
# Files live in OUR queue, not in the uploader. An uploader cannot drop one
# file from code and cannot remember "done" or notes, so it is only an inbox:
# whatever lands in it moves into the queue, then the uploader resets itself
# (by getting a new key). The queue lasts for this browser session.
Q: dict = st.session_state.setdefault("queue", {})  # id -> item, in arrival order
st.session_state.setdefault("inbox_ver", 0)
st.session_state.setdefault("qedit_ver", 0)


def intake(files: list[tuple[str, bytes]]) -> None:
    added = 0
    for file_name, data in files:
        qid = hashlib.sha256(data).hexdigest()[:16]
        if qid not in Q:
            Q[qid] = {"name": file_name, "raw": data, "done": False, "note": "", "sel": False}
            added += 1
    dupes = len(files) - added
    if added:
        st.toast(f"Added {added} email{'s' if added != 1 else ''} to the queue"
                 + (f", {dupes} already there" if dupes else ""), icon=":material/inbox:")
    elif dupes:
        st.toast("Already in the queue", icon=":material/info:")
    st.session_state["qedit_ver"] += 1


def from_inbox() -> None:
    key = f"inbox-{st.session_state['inbox_ver']}"
    files = st.session_state.get(key) or []
    if files:
        intake([(f.name, f.getvalue()) for f in files])
        st.session_state["inbox_ver"] += 1  # a fresh, empty uploader next run


def from_sample() -> None:
    picked = st.session_state.get("sample")
    if picked is not None:
        intake([(picked.name, picked.read_bytes())])
        st.session_state["sample"] = None


UPLOADER = dict(
    label="Upload .eml or .msg files", type=["eml", "msg"], accept_multiple_files=True,
    key=f"inbox-{st.session_state['inbox_ver']}", on_change=from_inbox,
    help="One email, or the whole morning queue at once. They join the queue, "
         "sorted worst first. A report with the phish attached is unwrapped.")

# ------------------------------------------------------------------ section menu
NAV = [("overview", "dashboard", "Overview"), ("auth", "verified_user", "Authentication"),
       ("evidence", "warning", "Evidence"), ("iocs", "fingerprint", "Indicators"),
       ("route", "route", "Mail route"), ("intel", "travel_explore", "Threat intel"),
       ("respond", "bolt", "Respond"), ("decision", "gavel", "Your decision"),
       ("history", "history", "Case history"), ("ticket", "description", "Ticket")]


def render_nav(badges: dict[str, str] | None) -> None:
    """The sidebar menu. badges=None means no email is open: same menu, dimmed."""
    if badges is None:
        items = "".join(
            f'<span class="off" aria-disabled="true">{icon(ic)}{label}</span>'
            for _, ic, label in NAV)
        html_ = (f'<nav class="nav idle" aria-label="Sections">{items}</nav>'
                 '<p class="nav-hint">Sections open when an email is loaded.</p>')
    else:
        html_ = '<nav class="nav" aria-label="Sections">' + "".join(
            f'<a href="#{sid}">{icon(ic)}{label}{badges.get(sid, "")}</a>'
            for sid, ic, label in NAV) + "</nav>"
    with nav_slot:
        show(html_)


# ------------------------------------------------------------------ sidebar
with st.sidebar:
    nav_slot = st.empty()  # replaced by the live menu once an email is open
    render_nav(None)
    show('<hr class="side-rule">')
    st.header("Add emails")
    if Q:  # on the welcome page the big drop zone takes this role
        st.file_uploader(**UPLOADER)
    st.selectbox("...or add a sample", SAMPLES, index=None, key="sample",
                 placeholder="Choose a sample", format_func=lambda x: x.name,
                 on_change=from_sample)

    st.header("Intel source")
    live = st.toggle("Live API lookups", value=False,
                     help="Off = offline demo intel. On = real VirusTotal / AbuseIPDB.")
    vt_key = abuse_key = None
    if live:
        # Keys come from the environment (injected by `infisical run`, see
        # GUIDE.md). A key found there is NEVER put into a widget: a widget's
        # value is sent to the browser, so pre-filling it would leak the key
        # to anyone who can open the page. Only ask when a key is missing.
        def key_from(env: str, label: str) -> str | None:
            if os.getenv(env):
                st.caption(f":material/lock: {label} key loaded from the environment")
                return os.environ[env]
            return st.text_input(f"{label} API key", type="password",
                                 help=f"Or set {env} through Infisical") or None

        vt_key = key_from("VT_API_KEY", "VirusTotal")
        abuse_key = key_from("ABUSEIPDB_API_KEY", "AbuseIPDB")

header_slot = st.container()  # filled once we know which email is open

enricher = (
    Enricher(vt_key=vt_key or None, abuse_key=abuse_key or None)
    if live
    else Enricher(offline_file=ROOT / "samples" / "mock_intel.json")
)
history = History(ROOT / ".cache" / "cases.db")


def triage(raw: bytes):
    """Analyse once per session per email (so a queue is not re-run on every click)."""
    key = (hashlib.sha256(raw).hexdigest(), live)
    cache = st.session_state.setdefault("analyses", {})
    if key not in cache:
        try:
            cache[key] = analyse(raw, enricher)
        except UnsupportedFormat as exc:
            cache[key] = exc
    return cache[key]


now = datetime.now().strftime("%d %b %Y, %H:%M")
mode = ('<span class="pill live"><span class="dot"></span>Live intel</span>' if live
        else '<span class="pill"><span class="dot"></span>Offline intel</span>')


def header(file_name: str) -> None:
    with header_slot:
        show(f"""
<header class="top">
  <div><h1>Email triage</h1>
    <p>Analysing <code>{esc(file_name) or "no email loaded"}</code></p></div>
  <div style="display:flex;gap:8px;flex-wrap:wrap">{mode}<span class="pill">{now}</span></div>
</header>""")


if not Q:
    # ------------------------------------------------------- welcome
    show("""
<section class="welcome">
  <h1>Drop reported emails to start triage</h1>
  <p>A verdict with its reasons in under a second. Then the hunt queries, the block
  list and the reply to the reporter, so the ticket can be closed.</p>
</section>""")
    with st.container(key="welcome-drop"):
        st.file_uploader(**UPLOADER)
    show(f"""
<div class="grid3">
  <div class="card tip">{icon("stacks")}<div><b>One email or the whole queue</b>
    <span>Drop thirty at once. Mark them done, add notes, remove what you have finished.</span></div></div>
  <div class="card tip">{icon("forward_to_inbox")}<div><b>Reports are unwrapped</b>
    <span>Forwarded as an attachment, .eml or Outlook .msg: the original is analysed.</span></div></div>
  <div class="card tip">{icon("shield_lock")}<div><b>Nothing is opened or run</b>
    <span>Attachments are read as text and pixels. Links are never visited.</span></div></div>
</div>
<p class="welcome-hint">No email to hand? Choose a sample in the sidebar.</p>""")
    st.stop()

# ------------------------------------------------------------- analyse + remember
analysed = {qid: triage(item["raw"]) for qid, item in Q.items()}
case_ids: dict[str, int] = {}
for qid, res in analysed.items():
    if not isinstance(res, Exception):  # remember every email, opened or not
        case_ids[qid] = history.record(res.parsed, res.iocs, res.result, res.report,
                                       file_name=Q[qid]["name"])


def risk(qid: str) -> int:
    res = analysed[qid]
    return -1 if isinstance(res, Exception) else res.result.score


# Open work first, worst first; finished work sinks to the bottom.
order = sorted(Q, key=lambda qid: (Q[qid]["done"], -risk(qid)))
hide_done = st.session_state.get("hide_done", False)
visible = [qid for qid in order if not (hide_done and Q[qid]["done"])]


# ---- actions (run as callbacks, before the page redraws)
def refresh() -> None:
    st.session_state["qedit_ver"] += 1  # editor redraws from the queue


def remove(ids: list[str]) -> None:
    for qid in ids:
        Q.pop(qid, None)
    if ids:
        st.toast(f"Removed {len(ids)} email{'s' if len(ids) != 1 else ''}",
                 icon=":material/delete:")
    refresh()


def mark(ids: list[str], done: bool) -> None:
    for qid in ids:
        Q[qid]["done"] = done
        Q[qid]["sel"] = False
    refresh()


def select(ids: list[str], flag: bool) -> None:
    for qid in ids:
        Q[qid]["sel"] = flag
    refresh()


def apply_edits() -> None:
    """Copy ticks and notes typed into the table back into the queue."""
    ids = st.session_state.get("qedit_ids", [])
    edits = st.session_state.get(f"qedit-{st.session_state['qedit_ver']}", {})
    for row, changes in edits.get("edited_rows", {}).items():
        if row >= len(ids) or ids[row] not in Q:
            continue
        item = Q[ids[row]]
        if "Select" in changes:
            item["sel"] = bool(changes["Select"])
        if "Done" in changes:
            item["done"] = bool(changes["Done"])
        if "Note" in changes:
            item["note"] = (changes["Note"] or "")[:500]
    refresh()


def step(delta: int) -> None:
    ids = st.session_state.get("qnav_ids", [])
    if st.session_state.get("open_id") in ids:
        i = ids.index(st.session_state["open_id"]) + delta
        st.session_state["open_id"] = ids[max(0, min(len(ids) - 1, i))]


n_done = sum(1 for item in Q.values() if item["done"])
selected = [qid for qid in order if Q[qid]["sel"]]
n_bad = sum(1 for qid in Q if not isinstance(analysed[qid], Exception)
            and analysed[qid].result.verdict == "MALICIOUS" and not Q[qid]["done"])

show(section("queue", "Queue",
             f"{len(Q)} emails: {len(Q) - n_done} to do ({n_bad} malicious), {n_done} done. "
             "Open work first, highest risk first."))
with st.container(key="card-queue"):
    if not visible:
        show('<p class="empty" style="padding:0">Everything here is done. Turn off '
             "\"Hide done\" to see it, or add more emails.</p>")
    else:
        if st.session_state.get("open_id") not in visible:
            st.session_state["open_id"] = visible[0]
        st.session_state["qnav_ids"] = visible
        pos = visible.index(st.session_state["open_id"])
        c_prev, c_pick, c_next = st.columns([1, 5, 1], vertical_alignment="bottom")
        c_prev.button("Previous", key="q-prev", icon=":material/arrow_back:", width="stretch",
                      on_click=step, args=(-1,), disabled=pos == 0)

        def label(qid: str) -> str:
            res = analysed[qid]
            verdict = "Unreadable" if isinstance(res, Exception) else \
                f"{res.result.verdict.capitalize()} {res.result.score}/100"
            return (f"{visible.index(qid) + 1}.  {'Done  ' if Q[qid]['done'] else ''}"
                    f"{verdict}   {Q[qid]['name']}")

        c_pick.selectbox(f"Open email ({pos + 1} of {len(visible)})", visible, key="open_id",
                         format_func=label)
        c_next.button("Next", key="q-next", icon=":material/arrow_forward:", width="stretch",
                      on_click=step, args=(1,), disabled=pos == len(visible) - 1)

        rows = []
        for k, qid in enumerate(visible):
            res, item = analysed[qid], Q[qid]
            bad = isinstance(res, Exception)
            seen = 0 if bad else len(history.related(case_ids[qid]))
            rows.append({
                "Select": item["sel"], "Done": item["done"],
                "Open": "▶" if qid == st.session_state["open_id"] else "",
                "#": k + 1,
                "Verdict": "Unreadable" if bad else res.result.verdict.capitalize(),
                "Score": 0 if bad else res.result.score,
                "File": item["name"],
                "From": "" if bad else clean(res.parsed.from_addr, 60),  # clean() already defangs
                "Subject": "" if bad else clean(res.parsed.subject, 80),
                "Note": item["note"],
                "Seen before": f"{seen} related" if seen else "",
            })
        st.session_state["qedit_ids"] = visible
        st.data_editor(  # plain-text grid: no markup risk
            rows, key=f"qedit-{st.session_state['qedit_ver']}", on_change=apply_edits,
            hide_index=True, width="stretch",
            disabled=["Open", "#", "Verdict", "Score", "File", "From", "Subject", "Seen before"],
            column_config={
                "Select": st.column_config.CheckboxColumn(width="small", help="Tick to act on it"),
                "Done": st.column_config.CheckboxColumn(width="small", help="Finished with it"),
                "Open": st.column_config.TextColumn(" ", width=28),
                "#": st.column_config.NumberColumn(width=40),
                "Score": st.column_config.ProgressColumn(
                    min_value=0, max_value=100, format="%d", width="small"),
                "Note": st.column_config.TextColumn(
                    width="medium", max_chars=500, help="Your own note for this email"),
            },
        )

    with st.container(horizontal=True, key="queue-actions"):
        n_sel = len(selected)
        st.button(f"Remove selected ({n_sel})", key="q-rm-sel", icon=":material/delete:",
                  on_click=remove, args=(selected,), disabled=not n_sel)
        st.button("Mark done", key="q-done", icon=":material/task_alt:",
                  on_click=mark, args=(selected, True), disabled=not n_sel)
        st.button("Mark not done", key="q-undone", icon=":material/undo:",
                  on_click=mark, args=(selected, False), disabled=not n_sel)
        all_sel = bool(visible) and all(Q[qid]["sel"] for qid in visible)
        st.button("Clear selection" if all_sel else "Select all", key="q-sel-all",
                  icon=":material/deselect:" if all_sel else ":material/select_all:",
                  on_click=select, args=(visible, not all_sel), disabled=not visible)
        st.button(f"Remove done ({n_done})", key="q-rm-done", icon=":material/delete_sweep:",
                  on_click=remove, args=([q for q in Q if Q[q]["done"]],), disabled=not n_done)
        with st.popover("Remove all", icon=":material/clear_all:"):
            st.write(f"Remove all {len(Q)} emails from the queue? Your notes and done marks "
                     "go with them. Saved decisions and case history are kept.")
            st.button("Yes, remove all", key="q-rm-all", type="primary",
                      on_click=remove, args=(list(Q),))
        st.toggle("Hide done", key="hide_done", on_change=refresh)

if not visible:
    header("")
    st.stop()

open_id = st.session_state["open_id"]
name, raw, a = Q[open_id]["name"], Q[open_id]["raw"], analysed[open_id]
header(name)
if isinstance(a, Exception):
    show(f'<div class="alert bad">{icon("error")}<div><b>Could not read {esc(name)}</b>'
         f"<span>{raw_esc(a)}</span></div></div>")
    st.stop()
case_id = case_ids[open_id]
case = history.get(case_id)
related = history.related(case_id)
r, p, rep, iocs = a.result, a.parsed, a.report, a.iocs

# ------------------------------------------------------------- toasts
# One toast per NEW email (not on every rerun, e.g. toggling a widget).
# Streamlit's native st.toast plays the role Sonner plays in React apps.
email_id = hashlib.sha256(raw).hexdigest()
if st.session_state.get("toasted") != email_id:
    st.session_state["toasted"] = email_id
    words = {"MALICIOUS": "Malicious", "SUSPICIOUS": "Suspicious", "LIKELY BENIGN": "Likely benign"}
    icons = {"MALICIOUS": ":material/gpp_bad:", "SUSPICIOUS": ":material/gpp_maybe:",
             "LIKELY BENIGN": ":material/verified_user:"}
    extra = (" Possible BEC: do not pay." if any(f.category == "BEC" for f in r.findings)
             and r.verdict != "LIKELY BENIGN" else "")
    # Toast text is plain Markdown: only our own words and the escaped file name.
    st.toast(f"**{words[r.verdict]}, {r.score}/100.** {len(r.findings)} findings.{extra}",
             icon=icons[r.verdict])
    if rep.interacted:
        st.toast("**The reporter says they clicked.** Treat as a possible compromise.",
                 icon=":material/emergency_home:", duration="long")
scored = [f for f in r.findings if f.points]
n_iocs = (len(iocs.urls) + len(iocs.domains) + len(iocs.ips) + len(iocs.emails)
          + len(p.attachments))

# ------------------------------------------------------------- sidebar nav
high = any(f.points >= 30 for f in r.findings)
render_nav({
    "evidence": f'<span class="badge{" hot" if high else ""}">{len(scored)}</span>',
    "iocs": f'<span class="badge">{n_iocs}</span>',
    "route": f'<span class="badge">{len(p.hops)}</span>',
    "decision": '<span class="badge">done</span>' if case["analyst_verdict"] else "",
})

# ------------------------------------------------- report: how it reached us
if rep.kind != "direct":
    if rep.interacted:
        show(f'<div class="alert bad">{icon("emergency_home")}<div><b>The reporter says they '
             "interacted with this email: handle it as a possible compromise</b><span>Matched: "
             f'{raw_esc(", ".join(rep.interacted))}</span></div></div>')
    for w in rep.warnings:
        show(f'<div class="alert warn">{icon("warning")}<div><b>Original headers are lost</b>'
             f"<span>{raw_esc(w)}</span></div></div>")
    how = ("Forwarded as an attachment. Analysing the attached original."
           if rep.kind == "attached" else "Forwarded inline.")
    rows = [("Reporter", esc(rep.reporter) or "-"), ("Reported", esc(rep.reported_at) or "-"),
            ("How", raw_esc(how))]
    if rep.note:
        rows.append(("Their note", "&ldquo;" + html.escape(clean(rep.note, 500)) + "&rdquo;"))
    show(section("report", "User report", "Who sent this to the SOC, and what they said.")
         + '<div class="card"><dl class="kv">'
         + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows) + "</dl></div>")

# ------------------------------------------------------------- seen before
# The biggest time-saver in a phishing wave: this exact email, or one that
# shares its infrastructure, was already triaged.
if related:
    decided = next((x for x in related if x.analyst_verdict), None)
    twins = sum(1 for x in related if x.same_email)
    title = (f"Seen before: {len(related)} related "
             f"{'case' if len(related) == 1 else 'cases'}"
             + (f", {twins} of them this same email" if twins else ""))
    if decided:
        title += f". An analyst already decided: {decided.analyst_verdict.capitalize()}"
    lines = ""
    for x in related[:4]:
        shared = ", ".join(f"{kind} {defang(value) if kind != 'attachment' else value[:12] + '…'}"
                           for kind, value in dict.fromkeys(x.shared)) or "the same email"
        who = f"reported by {esc(x.reporter)}" if x.reporter else "uploaded directly"
        lines += (f"<li>{raw_esc(x.first_seen.replace('T', ' '))}, {who}: "
                  f"{raw_esc(x.verdict.capitalize())} {x.score}/100. "
                  f"Shares {html.escape(shared)}.</li>")
    if len(related) > 4:
        lines += f"<li>and {len(related) - 4} more.</li>"
    show(f'<div class="alert info">{icon("history")}<div><b>{raw_esc(title)}</b>'
         f'<ul class="rel">{lines}</ul></div></div>')

# ------------------------------------------------------------- verdict hero
# The verdict is the answer the analyst came for, so it owns the first screen:
# the word, the score, the top reasons, and what to do. Everything else on
# the page is supporting evidence.
v_icon = {"MALICIOUS": "gpp_bad", "SUSPICIOUS": "gpp_maybe",
          "LIKELY BENIGN": "verified_user"}[r.verdict]
meaning = {
    "MALICIOUS": "Strong evidence this email is an attack.",
    "SUSPICIOUS": "Warning signs, but not conclusive. A human should decide.",
    "LIKELY BENIGN": "No meaningful warning signs found.",
}[r.verdict]
band = {"LIKELY BENIGN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}[r.verdict]
scale = "".join(f'<span aria-current="{"true" if i == band else "false"}">{lbl}</span>'
                for i, lbl in enumerate(("Benign 0", f"Suspicious {SUSPICIOUS_AT}",
                                         f"Malicious {MALICIOUS_AT}")))
why = "".join(
    f'<li><span class="pts">+{f.points}</span><span>{raw_esc(f.title)}</span></li>'
    for f in scored[:3]
) or "<li><span>Nothing in this email scored points.</span></li>"
more = (f'<a class="more" href="#evidence">and {len(scored) - 3} more in Evidence</a>'
        if len(scored) > 3 else "")
summary = llm_summary(r)
ai = (f'<div class="hero-action"><span class="label">AI summary</span><p>{esc(summary)}</p></div>'
      if summary else "")
show(f"""
<section class="hero" id="overview" data-v="{raw_esc(r.verdict)}" aria-label="Verdict">
  <div class="hero-main">
    <span class="label">Verdict</span>
    <h2 class="hero-word">{icon(v_icon)}{raw_esc(r.verdict.capitalize())}</h2>
    <p class="hero-sub">{meaning}</p>
    <span class="label" style="margin-top:20px">Top reasons</span>
    <ol class="why">{why}</ol>{more}
  </div>
  <div class="hero-dial">
    <div class="dial" style="--s:{r.score / 100:.2f}" role="meter" aria-valuemin="0"
         aria-valuemax="100" aria-valuenow="{r.score}" aria-label="Risk score {r.score} of 100">
      <div class="dial-num">{r.score}<small>/100</small></div>
    </div>
    <span class="label" style="margin:12px 0 0">Risk score</span>
  </div>
  <div class="hero-scale">
    <div class="bar" aria-hidden="true">
      <span class="fill" style="--s:{r.score / 100:.2f}"></span>
      <span class="tick" style="left:{SUSPICIOUS_AT}%"></span>
      <span class="tick" style="left:{MALICIOUS_AT}%"></span>
    </div>
    <div class="scale">{scale}</div>
  </div>
  <div class="hero-action"><span class="label">What to do now</span>
    <p>{raw_esc(r.action)}</p></div>
  {ai}
</section>""")

# ------------------------------------------------------------- supporting facts
by_cat = Counter()
for f in r.findings:
    by_cat[f.category] += f.points
top = max(by_cat.values(), default=0) or 1
bars = "".join(
    f'<div class="cat"><span>{raw_esc(c)}</span><span class="track">'
    f'<span class="fill" style="--s:{pts / top:.2f}"></span></span>'
    f'<span class="n">+{pts}</span></div>'
    for c, pts in by_cat.most_common() if pts
) or '<p class="empty" style="padding:0">No points scored.</p>'
mitre = "".join(f'<span class="chip">{raw_esc(m)}</span>' for m in r.mitre)
score_card = ('<div class="card"><span class="label">Where the score came from</span>'
              f'<div class="cats">{bars}</div></div>')
conf_note = " (grey zone: a human should decide)" if r.confidence == "Low" else ""
facts = [
    ("Confidence", raw_esc(r.confidence) + conf_note),
    ("Findings", f"{len(scored)} scored points"),
    ("Indicators", f"{n_iocs} you could block"),
    ("Triage time", f"{a.elapsed:.2f}s"),
    ("MITRE ATT&amp;CK", f'<div class="tags" style="margin:0">{mitre}</div>' if mitre else "-"),
]
facts_card = ('<div class="card"><dl class="kv">'
              + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in facts) + "</dl></div>")
show(f'<div class="grid2" style="margin-top:14px">{score_card}{facts_card}</div>')

# ------------------------------------------------------------- authentication
from_dom = domain_of(p.from_addr)
reply_dom = domain_of(p.reply_to)
if not p.reply_to:
    reply = ("none", "Not set", "replies go to the sender")
elif reply_dom == from_dom:
    reply = ("ok", "Matches", reply_dom)
else:
    reply = ("bad", "Different", reply_dom)
cards = [
    ("dns", "SPF", "Is the sending server allowed to send mail for this domain?",
     tone(p.auth["spf"]), p.auth["spf"].capitalize(), from_dom),
    ("key", "DKIM", "Does the message's cryptographic signature check out?",
     tone(p.auth["dkim"]), p.auth["dkim"].capitalize(), from_dom),
    ("policy", "DMARC", "Does SPF or DKIM pass for the domain shown in From?",
     tone(p.auth["dmarc"]), p.auth["dmarc"].capitalize(), from_dom),
    ("reply", "Reply-To", "Do replies go back to the same domain as the sender?",
     reply[0], reply[1], reply[2]),
]
auth_html = "".join(
    f'<div class="card auth {t}"><div class="auth-top"><span class="tile">{icon(ic)}</span>'
    f'<span class="chip">{raw_esc(status)}</span></div>'
    f'<div><h3>{title}</h3><p class="desc">{desc}</p></div>'
    f'<div class="auth-foot"><span class="st">{raw_esc(status)}</span>'
    f'<span class="detail">{esc(defang(detail)) if "." in (detail or "") else esc(detail)}'
    "</span></div></div>"
    for ic, title, desc, t, status, detail in cards
)
fields = [
    ("From", f'{esc(p.from_name)} <span class="ioc">{esc(p.from_addr)}</span>'),
    ("Subject", esc(p.subject)),
    ("Date", esc(p.date)),
    ("Reply-To", f'<span class="ioc">{esc(p.reply_to)}</span>' if p.reply_to else "-"),
    ("Return-Path", f'<span class="ioc">{esc(p.return_path)}</span>' if p.return_path else "-"),
    ("Origin IP", f'<span class="ioc">{raw_esc(defang(p.origin_ip))}</span>'
     if p.origin_ip else "-"),
]
show(section("auth", "Sender authentication",
             "Who really sent this email, and whether the receiving server could verify it.")
     + f'<div class="grid4">{auth_html}</div>'
     + '<div class="card" style="margin-top:14px"><dl class="kv">'
     + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in fields) + "</dl></div>")

# ------------------------------------------------------------- evidence
if r.findings:
    rows_html = ""
    for f in r.findings:
        t, word = severity(f.points)
        rows_html += (
            f'<tr><td><div class="who"><span class="avatar {t}">+{f.points}</span>'
            f"<div><b>{raw_esc(f.title)}</b><small>{raw_esc(f.evidence)}</small></div></div></td>"
            f'<td class="nowrap"><span class="chip">{raw_esc(f.category)}</span></td>'
            f'<td class="nowrap"><span class="sev {t}">{word}</span></td>'
            f'<td class="num">+{f.points}</td></tr>')
    evidence = ('<div class="card tbl-card"><table class="tbl"><thead><tr><th>Finding</th>'
                "<th>Category</th><th>Severity</th><th style=\"text-align:right\">Points</th>"
                f"</tr></thead><tbody>{rows_html}</tbody></table></div>")
else:
    evidence = '<div class="card"><p class="empty" style="padding:0">No suspicious indicators found.</p></div>'
show(section("evidence", "Evidence",
             f"{len(scored)} findings that added points, highest first. Every point has a reason.")
     + evidence)

# ------------------------------------------------------------- indicators
url_rows = "".join(
    f'<tr><td><span class="ioc">{esc(u.defanged)}</span>'
    + (f'<small style="display:block;color:var(--muted);margin-top:2px">Link text: '
       f"{esc(u.anchor_text)}</small>" if u.anchor_text else "")
    + (f'<small style="display:block;color:var(--amber);margin-top:2px">'
       f'{"Hidden in a QR code in" if "qr_code" in u.flags else "Found inside"} '
       f"{esc(u.source)}</small>" if u.source else "")
    + '</td><td><div class="tags" style="margin:0">'
    + ("".join(f'<span class="chip flag">{raw_esc(fl)}</span>' for fl in u.flags)
       or '<span style="color:var(--muted)">None</span>')
    + "</div></td></tr>"
    for u in iocs.urls
)
other_rows = (
    [("Email", defang(addr)) for addr in iocs.emails]
    + [("Domain", defang(d)) for d in iocs.domains]
    + [("IP", defang(i)) for i in iocs.ips]
    + [("File", f"{clean(x.filename)}  sha256 {x.sha256}") for x in p.attachments]
)
other_html = "".join(
    f'<tr><td class="nowrap"><span class="chip">{k}</span></td>'
    f'<td><span class="ioc">{html.escape(v)}</span></td></tr>' for k, v in other_rows
)
if p.images and not qr_supported():
    show(f'<div class="alert warn">{icon("qr_code_2")}<div><b>{len(p.images)} image(s) were not '
         "checked for QR codes</b><span>Install the reader with: pip install "
         "opencv-python-headless</span></div></div>")
show(section("iocs", "Indicators",
             "Everything you could search for or block. Defanged, so nothing here is clickable.")
     + '<div class="grid2">'
     + ('<div class="card tbl-card"><table class="tbl"><thead><tr><th>URL</th><th>Flags</th>'
        f"</tr></thead><tbody>{url_rows}</tbody></table></div>" if url_rows
        else '<div class="card"><p class="empty" style="padding:0">No URLs found.</p></div>')
     + ('<div class="card tbl-card"><table class="tbl"><thead><tr><th>Type</th><th>Value</th>'
        f"</tr></thead><tbody>{other_html}</tbody></table></div>" if other_html
        else '<div class="card"><p class="empty" style="padding:0">No other indicators.</p></div>')
     + "</div>")

# ------------------------------------------------------------- mail route
hops = "".join(
    f'<tr><td class="num" style="text-align:left">{h.index}</td>'
    f'<td><span class="ioc">{esc(defang(h.from_host))}</span></td>'
    f'<td><span class="ioc">{esc(defang(h.by_host))}</span></td>'
    f'<td class="nowrap"><span class="ioc">{raw_esc(", ".join(defang(i) for i in h.ips)) or "-"}'
    "</span></td></tr>"
    for h in p.hops
)
show(section("route", "Mail route",
             "Every server the message passed through, oldest first. The first public IP "
             "is the best guess at where it came from.")
     + ('<div class="card tbl-card"><table class="tbl"><thead><tr><th>Hop</th><th>From</th>'
        f"<th>By</th><th>IPs</th></tr></thead><tbody>{hops}</tbody></table></div>" if hops
        else '<div class="card"><p class="empty" style="padding:0">No Received headers.</p></div>'))

# ------------------------------------------------------------- threat intel
show(section("intel", "Threat intel",
             "What VirusTotal, AbuseIPDB and RDAP know about each indicator."))
with st.container(key="card-intel"):
    rows = []
    for kind, items in a.intel.items():
        for indicator, info in items.items():
            # Full hashes are in Indicators and the ticket; 16 chars identify it here.
            shown = indicator[:16] + "…" if kind == "hashes" else defang(indicator)
            rows.append({"Type": kind[:-1] if kind != "hashes" else "hash",
                         "Indicator": shown, **info})
    if rows:
        st.dataframe(  # plain-text grid: no markup risk
            rows, hide_index=True,
            column_config={"Indicator": st.column_config.TextColumn(width="medium")},
        )
    else:
        show('<p class="empty" style="padding:0">No indicators needed a lookup.</p>')

# ------------------------------------------------------------- respond
show(section("respond", "Respond", "Find who else is affected, block it, and answer the reporter."))
with st.container(key="card-respond"):
    tab_hunt, tab_block, tab_reply = st.tabs(["Hunt", "Block list", "Reply to reporter"])
    with tab_hunt:
        hunts = hunt_queries(p, iocs)
        if not hunts:
            show('<p class="empty" style="padding:0">Nothing to hunt for: this email has no '
                 "outside sender, link or attachment.</p>")
        for h in hunts:
            show(f'<div class="hunt"><b>{raw_esc(h.title)}</b>'
                 f'<span class="chip">{raw_esc(h.platform)}</span></div>')
            st.code(h.query, language=h.language)
        if hunts:
            st.caption("Queries contain the real indicator values and look back 7 days. "
                       "Table and index names vary: check them against your environment.")
    with tab_block:
        if r.verdict == "LIKELY BENIGN":
            st.caption(":material/info: This email looks benign. Block these only if you "
                       "decide it is malicious.")
        csv = blocklist_csv(p, iocs)
        st.code(csv, language="csv")
        st.download_button("Download block list", csv, key="blocklist", icon=":material/block:",
                           file_name=f"{Path(name).stem}_blocklist.csv", mime="text/csv")
    with tab_reply:
        st.code(reporter_reply(r, rep), language=None, wrap_lines=True)
        st.caption("A draft. Read it before you send it.")

# ------------------------------------------------------------- your decision
show(section("decision", "Your decision",
             "The tool suggests, you decide. Your call is saved with the case and is how we "
             "measure whether the tool can be trusted."))
with st.container(key="card-decision"):
    labels = {"Malicious": "MALICIOUS", "Suspicious": "SUSPICIOUS", "Benign": "LIKELY BENIGN"}
    saved = next((k for k, v in labels.items() if v == case["analyst_verdict"]), None)
    with st.form(key=f"decision-{case_id}", border=False):
        choice = st.segmented_control("Final verdict", list(labels), default=saved)
        note = st.text_input("Note (optional)", value=case["analyst_note"] or "",
                             placeholder="Why, or what you did about it")
        if st.form_submit_button("Save decision", icon=":material/gavel:"):
            if choice is None:
                st.toast("Pick a verdict first", icon=":material/info:")
            else:
                history.decide(case_id, labels[choice], note)
                Q[open_id]["done"] = True  # a decided case is a finished case
                st.session_state["qedit_ver"] += 1
                st.toast("Decision saved, marked done", icon=":material/check:")
                st.rerun()
    if saved:
        agrees = "matches" if case["analyst_verdict"] == r.verdict else "differs from"
        st.caption(f"Saved {case['decided_at'].replace('T', ' ')}: {saved}. "
                   f"This {agrees} the tool's verdict.")
    agreed, decided_n = history.accuracy()
    if decided_n:
        st.caption(f":material/monitoring: The tool agreed with analysts on {agreed} of "
                   f"{decided_n} decided cases ({agreed / decided_n:.0%}).")

# ------------------------------------------------------------- case history
show(section("history", "Case history",
             "What has been hitting us. Campaigns are attacker infrastructure seen in two or "
             "more cases."))
with st.container(key="card-history"):
    tab_camp, tab_recent = st.tabs(["Campaigns", "Recent cases"])
    with tab_camp:
        camps = history.campaigns()
        if camps:
            st.dataframe([{  # plain-text grid: no markup risk
                "Shared": c["kind"],
                "Value": c["value"][:16] + "…" if c["kind"] == "attachment" else defang(c["value"]),
                "Cases": c["cases"], "Reporters": c["reporters"], "Top score": c["top_score"],
                "First seen": c["first_seen"].replace("T", " "),
                "Last seen": c["last_seen"].replace("T", " "),
            } for c in camps], hide_index=True)
        else:
            show('<p class="empty" style="padding:0">No campaigns yet: nothing has been seen '
                 "in more than one case.</p>")
    with tab_recent:
        st.dataframe([{
            "Seen": c["last_seen"].replace("T", " "), "Verdict": c["verdict"].capitalize(),
            "Score": c["score"],
            "Analyst": (c["analyst_verdict"] or "").capitalize(),
            "From": defang(c["sender"] or ""), "Subject": clean(c["subject"], 70),
            "Reporter": defang(c["reporter"] or ""),
        } for c in history.recent()], hide_index=True)

# ------------------------------------------------------------- ticket
head, act = st.columns([4, 1], vertical_alignment="bottom")
with head:
    show(section("ticket", "Ticket", "Markdown, ready to paste into your ticketing system."))
with act:
    st.download_button("Export ticket", a.ticket, key="export", width="stretch",
                       on_click=lambda: st.toast("Ticket exported", icon=":material/check:"),
                       file_name=f"{Path(name).stem}_triage.md", icon=":material/download:")
with st.container(key="card-ticket"):
    st.code(a.ticket, language="markdown")
