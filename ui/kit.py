"""Display helpers shared by every page.

Security rule: any value that came from outside (an email, a certificate log,
pasted text) goes through esc() before it is placed in HTML. esc() is
clean() + html.escape(), so outside text is shown, never rendered.
"""
from __future__ import annotations

import html

import streamlit as st

from triage.sanitize import clean


def esc(value) -> str:
    """Outside (attacker-controllable) text -> safe to place inside HTML."""
    return html.escape(clean(value), quote=True)


def raw_esc(value) -> str:
    """For text that is ours or already defanged: escape only."""
    return html.escape(str(value or ""), quote=True)


def show(markup: str) -> None:
    # st.html renders HTML directly (sanitised by Streamlit, scripts stripped)
    # and never runs it through Markdown, so escaped text stays literal.
    st.html(markup)


def icon(name: str) -> str:
    return f'<span class="ms" aria-hidden="true">{name}</span>'


def section(sid: str, title: str, subtitle: str) -> str:
    return (f'<div class="sec" id="{sid}"><div class="sec-h"><div><h2>{title}</h2>'
            f"<p>{subtitle}</p></div></div></div>")


def page_header(title: str, subtitle: str) -> None:
    show(f'<header class="top"><div><h1>{raw_esc(title)}</h1>'
         f"<p>{raw_esc(subtitle)}</p></div></header>")


def stat_cards(cards: list[tuple[str, str, str, str]]) -> None:
    """cards: (label, value_html, material icon, tone: '' | red | amber | green | lav)."""
    show('<div class="stats">' + "".join(
        f'<dl class="stat {tone}"><div><dt>{raw_esc(label)}</dt><dd>{value}</dd></div>{icon(ic)}</dl>'
        for label, value, ic, tone in cards) + "</div>")


def empty(text: str) -> None:
    show(f'<div class="card"><p class="empty" style="padding:0">{raw_esc(text)}</p></div>')
