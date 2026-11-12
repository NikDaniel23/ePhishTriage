"""Who 'we' are: our email domains and the executives attackers impersonate.

Read from org.json at the project root. TRIAGE_ORG_DOMAINS (comma-separated)
adds domains on top, so a deployment can set them without editing the file.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

ORG_FILE = Path(__file__).resolve().parent.parent / "org.json"


@dataclass(frozen=True)
class Executive:
    name: str
    title: str = ""


@dataclass(frozen=True)
class Supplier:
    name: str
    domains: tuple[str, ...] = ()


@dataclass(frozen=True)
class Org:
    domains: frozenset[str] = frozenset()
    executives: tuple[Executive, ...] = field(default_factory=tuple)
    suppliers: tuple[Supplier, ...] = field(default_factory=tuple)


def load_org(path: Path | None = None) -> Org:
    """Load the org config. A missing or broken file means 'no org known'."""
    if path is None:
        return _default_org()
    data: dict = {}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}
    domains = {d.strip().lower() for d in data.get("org_domains", []) if d.strip()}
    domains |= {d.strip().lower() for d in os.getenv("TRIAGE_ORG_DOMAINS", "").split(",")
                if d.strip()}
    execs = tuple(Executive(e["name"], e.get("title", ""))
                  for e in data.get("executives", []) if e.get("name"))
    suppliers = tuple(
        Supplier(sup["name"], tuple(d.strip().lower() for d in sup.get("domains", []) if d.strip()))
        for sup in data.get("suppliers", []) if sup.get("name"))
    return Org(frozenset(domains), execs, suppliers)


@lru_cache(maxsize=1)
def _default_org() -> Org:
    return load_org(ORG_FILE)
