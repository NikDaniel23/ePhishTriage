"""Command-line version. Usage:

    python cli.py samples/01_obvious_phish.eml            # offline demo intel
    python cli.py suspicious.eml --live                   # real API lookups
"""
import argparse
import os
from pathlib import Path

from triage.enrich import Enricher
from triage.pipeline import analyse
from triage.unwrap import UnsupportedFormat

ROOT = Path(__file__).parent


def main() -> None:
    ap = argparse.ArgumentParser(description="ePhishTriage: phishing email triage")
    ap.add_argument("eml", help="path to a .eml or Outlook .msg file "
                                "(a report with the phish attached is unwrapped)")
    ap.add_argument("--live", action="store_true",
                    help="use VT_API_KEY / ABUSEIPDB_API_KEY instead of offline intel")
    args = ap.parse_args()

    if args.live:
        enricher = Enricher(vt_key=os.getenv("VT_API_KEY"),
                            abuse_key=os.getenv("ABUSEIPDB_API_KEY"))
    else:
        enricher = Enricher(offline_file=ROOT / "samples" / "mock_intel.json")

    try:
        analysis = analyse(Path(args.eml).read_bytes(), enricher)
    except UnsupportedFormat as exc:
        raise SystemExit(f"error: {exc}")
    print(analysis.ticket)


if __name__ == "__main__":
    main()
