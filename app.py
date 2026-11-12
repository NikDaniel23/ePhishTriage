"""ePhishTriage: phishing response console for SOC analysts.

Run with:  .\\run.ps1   (or: python -m streamlit run app.py)

This entry script only sets up the theme and the navigation. Each tool is a
page in app_pages/:
  Triage        analyse reported emails, one or a whole queue
  Shift report  what happened this shift, metrics, and the handover note
  Domain watch  look-alikes of our domains in public certificate logs
  IOC workbench paste any text, extract and look up every indicator
"""
from pathlib import Path

import streamlit as st

from ui.kit import show

ROOT = Path(__file__).resolve().parent

st.set_page_config(page_title="ePhishTriage", page_icon=":material/phishing:",
                   layout="wide", initial_sidebar_state="auto")
st.logo(str(ROOT / "assets" / "logo-light.png"), size="large")
show(f"<style>{(ROOT / 'ui' / 'console.css').read_text(encoding='utf-8')}</style>")

pages = st.navigation(
    [
        st.Page("app_pages/triage.py", title="Triage", icon=":material/mail_lock:",
                default=True),
        st.Page("app_pages/shift.py", title="Shift report", icon=":material/summarize:"),
        st.Page("app_pages/watch.py", title="Domain watch", icon=":material/travel_explore:"),
        st.Page("app_pages/workbench.py", title="IOC workbench", icon=":material/biotech:"),
    ],
    position="top",
)
pages.run()
