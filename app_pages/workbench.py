"""IOC workbench page: paste any text, extract and look up every indicator."""
import os
from collections import Counter
from pathlib import Path

import streamlit as st

from triage.enrich import Enricher
from triage.org import load_org
from triage.workbench import (MAX_TEXT, blocklist, defanged_list, extract, lookup,
                              ticket_table)
from ui.kit import empty, page_header, section, show, stat_cards

ROOT = Path(__file__).resolve().parent.parent
org = load_org()
st.session_state.setdefault("wb_ver", 0)

with st.sidebar:
    st.header("Lookups")
    live = st.toggle("Live API lookups", value=False, key="wb_live",
                     help="Off = demo intel in samples/mock_intel.json. "
                          "On = VirusTotal / AbuseIPDB, keys from the environment.")
    if live:
        have = [n for n, e in (("VirusTotal", "VT_API_KEY"), ("AbuseIPDB", "ABUSEIPDB_API_KEY"))
                if os.getenv(e)]
        st.caption((":material/lock: Keys loaded: " + ", ".join(have)) if have else
                   ":material/warning: No API keys in the environment. Start the app with "
                   "run.ps1 (Infisical) or set VT_API_KEY / ABUSEIPDB_API_KEY.")
        st.caption("Free API tiers are slow: at most 8 of each type are looked up per run, "
                   "about 15 seconds apart.")

page_header("IOC workbench",
            "Paste a threat report, an advisory or a chat message. Defanged text is fine: "
            "every indicator is pulled out, looked up and made ready to block.")


def load_example() -> None:
    st.session_state["wb_text"] = (ROOT / "samples" / "ioc_example.txt").read_text(encoding="utf-8")


def from_file() -> None:
    f = st.session_state.get(f"wb_file-{st.session_state['wb_ver']}")
    if f is not None:
        st.session_state["wb_text"] = f.getvalue()[:MAX_TEXT].decode("utf-8", "replace")


text = st.text_area("Text to analyse", key="wb_text", height=220, max_chars=MAX_TEXT,
                    placeholder="hxxp://evil[.]com/login, 203.0.113.45, a sha256 hash, "
                                "an email address...", label_visibility="collapsed")
with st.container(horizontal=True, vertical_alignment="center"):
    run = st.button("Extract and look up", key="extract", icon=":material/biotech:",
                    disabled=not text.strip())
    st.button("Load example", key="wb_example", icon=":material/description:",
              on_click=load_example)
    st.file_uploader("Or load a text file", type=["txt", "csv", "log", "md", "json", "eml"],
                     key=f"wb_file-{st.session_state['wb_ver']}", on_change=from_file,
                     label_visibility="collapsed")

if run:
    with st.spinner("Extracting and looking up..."):
        found = extract(text, org)
        enricher = (Enricher(vt_key=os.getenv("VT_API_KEY"),
                             abuse_key=os.getenv("ABUSEIPDB_API_KEY")) if live
                    else Enricher(offline_file=ROOT / "samples" / "mock_intel.json",
                                  max_lookups=500))
        lookup(found, enricher)
    st.session_state["wb_found"] = found
    st.session_state["wb_ver"] += 1

found = st.session_state.get("wb_found")
if not found:
    if found is not None:
        empty("No indicators found in that text.")
    st.stop()

verdicts = Counter(i.verdict for i in found)
bad = verdicts["Malicious"] + verdicts["Suspicious"]
stat_cards([
    ("Indicators", f"{len(found)}", "biotech", ""),
    ("Malicious or suspicious", f"{bad}", "gpp_bad", "red" if bad else ""),
    ("To block", f"{sum(i.actionable for i in found)}", "block", "lav"),
    ("Safe to ignore", f"{sum(not i.actionable for i in found)}", "verified_user", "green"),
])

show(section("found", "Indicators",
             "Untick anything you do not want in the exports. Ours, known-good sites, private "
             "addresses and vulnerability IDs are never put in the block list."))
order = {"Malicious": 0, "Suspicious": 1, "Not known": 2, "No reports": 3, "Not looked up": 4,
         "Reference": 5, "Ignored": 6}
found.sort(key=lambda i: order.get(i.verdict, 9))
rows = st.data_editor(  # plain-text grid: no markup risk
    [{"Include": True, "Verdict": i.verdict, "Type": i.kind, "Indicator": i.defanged,
      "Lookup": i.intel or "-"} for i in found],
    key=f"wb_grid-{st.session_state['wb_ver']}", hide_index=True, width="stretch",
    disabled=["Verdict", "Type", "Indicator", "Lookup"],
    column_config={"Include": st.column_config.CheckboxColumn(width="small"),
                   "Indicator": st.column_config.TextColumn(width="large"),
                   "Lookup": st.column_config.TextColumn(width="large")})
chosen = [i for i, row in zip(found, rows) if row["Include"]]

show(section("export", "Export", f"{len(chosen)} of {len(found)} indicators included."))
tab_block, tab_list, tab_ticket = st.tabs(["Block list (for tools)", "Defanged list (for people)",
                                           "Ticket table"])
with tab_block:
    csv = blocklist(chosen)
    st.code(csv, language="csv")
    st.download_button("Download block list", csv, key="wb_csv", mime="text/csv",
                       icon=":material/download:", file_name="ioc_blocklist.csv")
    st.caption("Real values, validated. Only indicators that are safe to block are included.")
with tab_list:
    st.code(defanged_list(chosen), language=None)
with tab_ticket:
    st.code(ticket_table(chosen), language="markdown")
