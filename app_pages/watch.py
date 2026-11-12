"""Domain watch page: look-alikes of our domains in public certificate logs."""
from datetime import datetime
from pathlib import Path

import requests
import streamlit as st

from triage.history import History
from triage.iocs import defang
from triage.org import load_org
from triage.respond import DOMAIN_OK
from triage.watch import (blocklist, fetch_ct, genuine_domains, hunt_query, load_demo,
                          scan, watch_terms)
from ui.kit import empty, page_header, raw_esc, section, show, stat_cards

ROOT = Path(__file__).resolve().parent.parent
history = History(ROOT / ".cache" / "cases.db")
org = load_org()
st.session_state.setdefault("wedit_ver", 0)

with st.sidebar:
    st.header("Certificate source")
    live = st.toggle("Live CT logs (crt.sh)", value=False, key="watch_live",
                     help="Off = demo certificates in samples/mock_ct.json. "
                          "On = search the public crt.sh service.")
    if live:
        st.caption(":material/info: Live mode sends the watched names to crt.sh, a public "
                   "service. Searches can take up to a minute each.")
    extra_raw = st.text_input("Also watch (comma-separated domains)", key="watch_extra",
                              placeholder="mycompany.com, mysupplier.com",
                              help="Added to the domains in org.json for this session.")
extra = [d.strip().lower() for d in extra_raw.split(",") if DOMAIN_OK.match(d.strip().lower())]
terms = watch_terms(org, extra)

page_header("Domain watch",
            "Attackers need a certificate for their fake login page, and every certificate is "
            "published. Catch look-alikes of our domains before the first email arrives.")

watched = sorted(genuine_domains(org) | set(extra))
show('<div class="card"><span class="label">Watching</span><div class="tags" style="margin:4px 0 0">'
     + "".join(f'<span class="chip">{raw_esc(d)}</span>' for d in watched)
     + '</div><p class="empty" style="padding:8px 0 0">Edit org.json to change the list '
       "permanently. Searched by name: "
     + raw_esc(", ".join(terms)) + ".</p></div>")

if st.button("Check certificate logs now", key="check-now", icon=":material/radar:",
             type="primary", disabled=not terms):
    records, failed = [], []
    with st.status("Searching certificate logs...", expanded=False) as box:
        if live:
            for term in terms:
                box.update(label=f"Searching crt.sh for {term}...")
                try:
                    records += fetch_ct(term)
                except (requests.RequestException, ValueError) as exc:
                    failed.append(f"{term}: {type(exc).__name__}")
        else:
            records = load_demo(ROOT / "samples" / "mock_ct.json")
        hits = scan(records, org)
        new = history.watch_upsert(hits)
        box.update(label=f"Checked {len(records)} certificates, {len(hits)} look-alikes, "
                         f"{new} new.", state="error" if failed and not records else "complete")
    if failed:
        st.warning("Some searches failed (crt.sh is often busy, try again later): "
                   + "; ".join(failed))
    st.toast(f"{new} new look-alike{'s' if new != 1 else ''} found" if new
             else "No new look-alikes", icon=":material/radar:")
    st.session_state["wedit_ver"] += 1

rows = history.watch_list()
if not rows:
    empty("No look-alikes on record yet. Press \"Check certificate logs now\".")
    st.stop()

n_new = sum(r["status"] == "new" for r in rows)
n_high = sum(r["risk"] == "High" and r["status"] == "new" for r in rows)
n_blocked = sum(r["status"] == "blocked" for r in rows)
stat_cards([
    ("Look-alikes on record", f"{len(rows)}", "travel_explore", ""),
    ("Awaiting review", f"{n_new}", "pending_actions", "amber" if n_new else "green"),
    ("High risk, unreviewed", f"{n_high}", "gpp_bad", "red" if n_high else ""),
    ("Marked to block", f"{n_blocked}", "block", "lav"),
])

show(section("lookalikes", "Look-alike domains",
             "Review each one: block it, or mark it benign if it is legitimate (a partner, a "
             "campaign site). Your decision is kept when you check again."))

domains = [r["domain"] for r in rows]


def apply_edits() -> None:
    edits = st.session_state.get(f"wedit-{st.session_state['wedit_ver']}", {})
    for i, change in edits.get("edited_rows", {}).items():
        if i >= len(domains):
            continue
        if "Status" in change:
            history.watch_set([domains[i]], status=change["Status"].lower())
        if "Note" in change:
            history.watch_set([domains[i]], note=change["Note"] or "")
        if "Select" in change:
            sel = st.session_state.setdefault("watch_sel", set())
            (sel.add if change["Select"] else sel.discard)(domains[i])
    st.session_state["wedit_ver"] += 1


selected = st.session_state.setdefault("watch_sel", set())
selected &= set(domains)
with st.container(key="card-watch"):
    st.data_editor(  # plain-text grid: no markup risk
        [{"Select": r["domain"] in selected, "Status": r["status"].capitalize(),
          "Risk": r["risk"], "Domain": defang(r["domain"]), "Imitates": r["imitates"],
          "Why": r["how"], "First certificate": r["first_cert"] or "-",
          "Issuer": r["issuer"] or "-", "Note": r["note"]} for r in rows],
        key=f"wedit-{st.session_state['wedit_ver']}", on_change=apply_edits,
        hide_index=True, width="stretch",
        disabled=["Risk", "Domain", "Imitates", "Why", "First certificate", "Issuer"],
        column_config={
            "Select": st.column_config.CheckboxColumn(width="small"),
            "Status": st.column_config.SelectboxColumn(
                options=["New", "Blocked", "Benign"], required=True, width="small"),
            "Why": st.column_config.TextColumn(width="large"),
            "Note": st.column_config.TextColumn(max_chars=500),
        })

    def set_status(status: str) -> None:
        history.watch_set(sorted(selected), status=status)
        selected.clear()
        st.session_state["wedit_ver"] += 1

    with st.container(horizontal=True, key="queue-actions"):
        st.button(f"Mark blocked ({len(selected)})", key="w-block", icon=":material/block:",
                  on_click=set_status, args=("blocked",), disabled=not selected)
        st.button("Mark benign", key="w-benign", icon=":material/verified_user:",
                  on_click=set_status, args=("benign",), disabled=not selected)
        st.button("Back to new", key="w-new", icon=":material/undo:",
                  on_click=set_status, args=("new",), disabled=not selected)

# ------------------------------------------------------------- act on it
to_act = [r["domain"] for r in rows if r["status"] == "blocked"] or \
         [r["domain"] for r in rows if r["status"] == "new" and r["risk"] == "High"]
which = "domains marked blocked" if any(r["status"] == "blocked" for r in rows) else \
    "high-risk domains awaiting review"
show(section("act", "Act on it",
             f"Built from the {len(to_act)} {which}. Real (not defanged) values: these are "
             "for your tools."))
if to_act:
    tab_block, tab_hunt = st.tabs(["Block list", "Did they already reach us?"])
    with tab_block:
        csv = blocklist(to_act)
        st.code(csv, language="csv")
        st.download_button("Download block list", csv, key="w-blocklist", mime="text/csv",
                           icon=":material/download:",
                           file_name=f"lookalike_blocklist_{datetime.now():%Y%m%d}.csv")
    with tab_hunt:
        st.code(hunt_query(to_act), language="kusto")
        st.caption("Microsoft Defender XDR. Check the table names against your environment.")
else:
    empty("Nothing to act on: no domains are marked blocked or awaiting review at high risk.")
