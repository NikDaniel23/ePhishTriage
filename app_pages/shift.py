"""Shift report page: metrics for a period, what is open, and the handover note."""
from datetime import datetime, timedelta
from pathlib import Path

import streamlit as st

from triage.history import History
from triage.iocs import defang
from triage.sanitize import clean
from triage.shift import VERDICT_WORD, handover_markdown, summarise
from ui.kit import empty, page_header, pill, section, show, stat_cards

ROOT = Path(__file__).resolve().parent.parent
history = History(ROOT / ".cache" / "cases.db")

header_slot = st.container()  # filled once the period is known
with st.container(horizontal=True, vertical_alignment="bottom", key="shift-controls"):
    period = st.segmented_control(
        "Period", ["This shift", "Today", "7 days", "30 days"], default="This shift",
        key="shift_period")
    shift_hours = st.number_input("Shift length (hours)", 1, 24, 8, key="shift_hours",
                                  width=170, disabled=period not in (None, "This shift"),
                                  help='"This shift" covers this many hours back from now.')

now = datetime.now().replace(microsecond=0)
since = {
    "This shift": now - timedelta(hours=shift_hours),
    "Today": now.replace(hour=0, minute=0, second=0),
    "7 days": now - timedelta(days=7),
    "30 days": now - timedelta(days=30),
}[period or "This shift"]

with header_slot:
    page_header("Shift report", "What came in, what is still open, and the note for the next shift.",
                right=pill(f"{since:%d %b, %H:%M} to now"))
rows = history.between(since)
stats = summarise(rows)
campaigns = history.campaigns_between(since)

if not rows:
    empty("No emails were triaged in this period. Triage some on the Triage page, "
          "or choose a longer period above.")
    st.stop()

mal = stats.by_verdict.get("MALICIOUS", 0)
agree = (f"{stats.agreed / stats.decided:.0%}<small> of {stats.decided}</small>"
         if stats.decided else "-<small> none yet</small>")
stat_cards([
    ("Reports", f"{stats.total}", "inbox", ""),
    ("Malicious", f"{mal}", "gpp_bad", "red" if mal else ""),
    ("Needs a decision", f"{len(stats.open_risky)}", "pending_actions",
     "amber" if stats.open_risky else "green"),
    ("Tool agreement", agree, "rule", "lav"),
])

# ------------------------------------------------------------- needs attention
show(section("attention", "Needs attention",
             "Malicious or suspicious reports with no analyst decision yet, highest risk first."))
if stats.open_risky:
    st.dataframe([{  # plain-text grid: no markup risk
        "Score": r["score"], "Verdict": VERDICT_WORD.get(r["verdict"], r["verdict"]),
        "Subject": clean(r["subject"], 90), "From": clean(r["sender"], 60),
        "First seen": r["first_seen"].replace("T", " "),
    } for r in stats.open_risky], hide_index=True, column_config={
        "Score": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%d",
                                                 width="small")})
else:
    empty("Nothing open: every malicious or suspicious report has a decision.")

# ------------------------------------------------------------- trends
show(section("trends", "What came in",
             f"Median time to an analyst decision: "
             + (f"{stats.minutes_to_decision:.0f} minutes." if stats.minutes_to_decision
                is not None else "no decisions yet.")))
left, right = st.columns([3, 2])
with left:
    # One column per verdict so each gets the app's verdict colour.
    day_rows = [{"Day": day, **{VERDICT_WORD[v]: counts.get(v, 0) for v in VERDICT_WORD}}
                for day, counts in sorted(stats.per_day.items())]
    st.bar_chart(day_rows, x="Day", y=["Malicious", "Suspicious", "Likely benign"],
                 color=["#ff6b63", "#f2c14e", "#5fd38a"], height=260, stack=True,
                 x_label="", y_label="Reports")
with right:
    if stats.tags:
        top_tag = max(stats.tags.values())
        st.dataframe([{"What hit us": t, "Cases": n} for t, n in stats.tags.most_common(6)],
                     hide_index=True, height=260, column_config={
                         "Cases": st.column_config.ProgressColumn(
                             min_value=0, max_value=top_tag, format="%d")})
    else:
        empty("No attack types recorded in this period.")

c1, c2 = st.columns(2)
with c1:
    show('<span class="label">Most targeted staff</span>')
    if stats.targeted:
        st.dataframe([{"Recipient": clean(w, 60), "Malicious or suspicious emails": n}
                      for w, n in stats.targeted.most_common(8)], hide_index=True)
    else:
        empty("No targeted staff recorded.")
with c2:
    show('<span class="label">Senders behind the bad ones</span>')
    if stats.sender_domains:
        st.dataframe([{"Domain or address": defang(d), "Emails": n}
                      for d, n in stats.sender_domains.most_common(8)], hide_index=True)
    else:
        empty("No malicious or suspicious senders in this period.")

# ------------------------------------------------------------- handover
head, act = st.columns([4, 1], vertical_alignment="bottom")
with head:
    show(section("handover", "Handover note",
                 "Ready to paste into the shift log or chat. Add anything the numbers do not say."))
write, preview = st.columns([2, 3])
with write:
    analyst = st.text_input("Your name (optional)", key="shift_analyst", max_chars=80)
    notes = st.text_area("Notes for the next shift", key="shift_notes", height=180,
                         placeholder="e.g. Finance warned about the Oakspan payment change; "
                                     "waiting on L2 for the device-portal campaign.")
note_md = handover_markdown(stats, campaigns, since, now, notes=notes, analyst=analyst)
with preview, st.container(key="card-ticket"):
    st.code(note_md, language="markdown", height=360)
with act:
    st.download_button("Export handover", note_md, key="export", width="stretch",
                       icon=":material/download:", file_name=f"handover_{now:%Y%m%d_%H%M}.md")
