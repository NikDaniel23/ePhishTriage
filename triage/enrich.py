"""STEP 3 - Enrichment: ask threat-intel sources what they know about each IOC.

Sources (all have free tiers):
  - VirusTotal  : reputation of domains and file hashes
  - AbuseIPDB   : abuse reports for an IP address
  - RDAP        : when a domain was registered (no key needed)

Two modes:
  - offline : read answers from a local JSON file (safe for demos, no keys)
  - live    : call the real APIs, with a cache so rate limits don't bite

We only ever LOOK UP indicators. We never visit the suspicious URL itself.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

from .iocs import IOCs, is_legit_domain

CACHE_TTL = 24 * 3600  # seconds
TIMEOUT = 10
# Don't waste API quota on domains everyone knows.
SKIP_DOMAINS = {"gmail.com", "outlook.com", "yahoo.com", "hotmail.com"}


class Enricher:
    def __init__(
        self,
        vt_key: str | None = None,
        abuse_key: str | None = None,
        offline_file: str | Path | None = None,
        cache_file: str | Path = ".cache/intel.json",
        max_lookups: int = 8,
        vt_interval: float = 15.0,
    ) -> None:
        self.vt_key = vt_key
        self.abuse_key = abuse_key
        self.max_lookups = max_lookups
        self.vt_interval = vt_interval  # seconds between VirusTotal calls
        self._last_vt_call = float("-inf")
        self.offline: dict | None = None
        if offline_file:
            self.offline = json.loads(Path(offline_file).read_text())
        self.cache_file = Path(cache_file)
        self.cache: dict = {}
        if self.offline is None and self.cache_file.exists():
            try:
                self.cache = json.loads(self.cache_file.read_text())
            except json.JSONDecodeError:
                self.cache = {}

    # ---------------------------------------------------------------- public
    def enrich_all(self, iocs: IOCs) -> dict:
        domains = [
            d for d in iocs.domains if d not in SKIP_DOMAINS and not is_legit_domain(d)
        ]
        out = {
            "domains": {d: self._lookup("domain", d) for d in domains[: self.max_lookups]},
            "ips": {i: self._lookup("ip", i) for i in iocs.ips[: self.max_lookups]},
            "hashes": {h: self._lookup("hash", h) for h in iocs.hashes[: self.max_lookups]},
        }
        self._save_cache()
        return out

    # --------------------------------------------------------------- helpers
    def _lookup(self, kind: str, value: str) -> dict:
        key = f"{kind}:{value}"
        if self.offline is not None:
            hit = self.offline.get(key)
            if hit is None:
                return {"source": "offline", "note": "not in offline intel file"}
            return {"source": "offline", **hit}

        cached = self.cache.get(key)
        if cached and time.time() - cached["ts"] < CACHE_TTL:
            return {**cached["data"], "cached": True}

        try:
            data = getattr(self, f"_live_{kind}")(value)
        except requests.RequestException as exc:
            # A failed lookup must never crash the triage. Report and move on.
            return {"source": "error", "note": f"lookup failed: {exc}"}
        # Only cache real answers. A "note" means no key, rate limit or similar;
        # caching that would hide the indicator for 24 hours.
        if "note" not in data:
            self.cache[key] = {"ts": time.time(), "data": data}
        return data

    def _save_cache(self) -> None:
        if self.offline is None and self.cache:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(self.cache, indent=2))

    def _vt(self, path: str) -> dict:
        """Call VirusTotal API v3 and return the vendor verdict counts."""
        if not self.vt_key:
            return {"note": "no VirusTotal key"}
        # Free tier allows about 4 requests/minute: space the calls out.
        wait = self.vt_interval - (time.monotonic() - self._last_vt_call)
        if wait > 0:
            time.sleep(wait)
        self._last_vt_call = time.monotonic()
        r = requests.get(
            f"https://www.virustotal.com/api/v3/{path}",
            headers={"x-apikey": self.vt_key},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            return {"note": "unknown to VirusTotal"}
        if r.status_code == 429:
            return {"note": "VirusTotal rate limit hit"}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
        }

    def _live_domain(self, domain: str) -> dict:
        data = {"source": "virustotal+rdap", **self._vt(f"domains/{domain}")}
        age = self._domain_age_days(domain)
        if age is not None:
            data["age_days"] = age
        return data

    def _live_hash(self, sha256: str) -> dict:
        return {"source": "virustotal", **self._vt(f"files/{sha256}")}

    def _live_ip(self, ip: str) -> dict:
        if not self.abuse_key:
            return {"source": "abuseipdb", "note": "no AbuseIPDB key"}
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self.abuse_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        d = r.json()["data"]
        return {
            "source": "abuseipdb",
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
        }

    @staticmethod
    def _domain_age_days(domain: str) -> int | None:
        """RDAP is the modern replacement for WHOIS and returns clean JSON."""
        try:
            r = requests.get(f"https://rdap.org/domain/{domain}", timeout=TIMEOUT)
            if r.status_code != 200:
                return None
            for event in r.json().get("events", []):
                if event.get("eventAction") == "registration":
                    created = datetime.fromisoformat(
                        event["eventDate"].replace("Z", "+00:00")
                    )
                    return (datetime.now(timezone.utc) - created).days
        except (requests.RequestException, ValueError, KeyError):
            return None
        return None
