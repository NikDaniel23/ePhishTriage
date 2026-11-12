<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-light.png">
    <img src="assets/logo-dark.png" alt="ePhishTriage" width="420">
  </picture>
</p>

<p align="center">
  <b>Phishing email triage for SOC analysts.</b><br>
  Drop in reported emails, get a verdict with its reasons in under a second,<br>
  then the hunt queries, block list and reporter reply needed to close the ticket.
</p>

---

## Why

When an employee clicks "Report phishing", an L1 analyst has to read the headers, check SPF/DKIM/DMARC, pull out every link and attachment, look each one up, decide, write the ticket, and answer the reporter. Most reports are harmless, and the same phishing wave gets reported dozens of times.

ePhishTriage does that groundwork and shows its evidence. **The analyst still decides**: every point in the score comes with a plain-language reason.

## Features

**Detection**
- Sender authentication (SPF, DKIM, DMARC), trusting only your own gateway's header and flagging planted "pass" headers lower down
- Look-alike and impersonation checks: brands, your own domain (`c0rp.example`), your suppliers, your executives' names, and links one character off the address they display
- Hidden links: inside QR code images, HTML attachments (fake login forms), calendar invites (`.ics`), and emails attached to emails
- Business email compromise: payment and bank-change requests with no link or file, in English and Malay
- Threat intel from VirusTotal, AbuseIPDB and RDAP (domain age), with an offline mode for demos
- Mailing-list forwards are recognised, so broken signatures from a list do not raise false alarms

**Workflow**
- Bulk queue: drop many files, sorted worst first; select, remove, mark done and add notes
- Reported emails are unwrapped: forwarded as an attachment (`.eml` or Outlook `.msg`), inline forwards are detected, and "I clicked it" in the reporter's note escalates the case
- Case history: repeat reports and campaigns that share infrastructure are linked
- Respond: hunt queries for Microsoft Defender (KQL) and Splunk, a block list CSV, and a drafted reply to the reporter
- Your decision: the analyst's final verdict is saved, and the agreement rate with the tool is shown
- A Markdown ticket ready to paste, with every indicator defanged

## Quick start

Requires Python 3.10 or newer.

```bash
git clone https://github.com/<your-username>/ePhishTriage.git
cd ePhishTriage
python -m venv .venv
```

Windows:

```powershell
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m streamlit run app.py
```

macOS / Linux:

```bash
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m streamlit run app.py
```

The dashboard opens at http://localhost:8501. It starts in offline mode, using the demo threat intel in `samples/mock_intel.json`, so it works without API keys or internet. Drop an email onto the page, or pick one of the samples in the sidebar.

### Command line

```bash
python cli.py samples/01_obvious_phish.eml
python cli.py suspicious.eml --live      # real VirusTotal / AbuseIPDB lookups
```

## Live threat intel

Live mode uses free VirusTotal and AbuseIPDB API keys, read from the `VT_API_KEY` and `ABUSEIPDB_API_KEY` environment variables. Keys are never written into the page: a key found in the environment is not shown in, or sent to, the browser.

The recommended setup keeps the keys in [Infisical](https://infisical.com) and injects them at start-up, so they never sit in a file:

```powershell
.\run.ps1                                    # dashboard, keys from Infisical
.\run.ps1 cli samples\01_obvious_phish.eml   # command line, live intel
```

See [GUIDE.md](GUIDE.md) for the one-time Infisical setup.

## Configuration

`org.json` tells the tool who "we" are. Business email compromise detection depends on it:

```json
{
  "org_domains": ["corp.example"],
  "executives": [{"name": "Rahman Ismail", "title": "Chief Executive Officer"}],
  "suppliers": [{"name": "Example Supplies", "domains": ["example-supplies.example"]}]
}
```

The values shipped in the file are fictional. `TRIAGE_ORG_DOMAINS` (comma-separated) adds domains without editing the file.

## Tests

```bash
python -m pytest -q
```

The suite includes every challenge email that once beat the tool, kept as permanent regression tests, alongside checks that honest versions of the same emails stay quiet.

## Project layout

```
app.py              dashboard (Streamlit)
cli.py              command-line version
run.ps1             start with API keys from Infisical
org.json            your domains, executives and suppliers
triage/
  unwrap.py         0. find the reported email (attachments, .msg, inline forwards)
  parser.py         1. parse headers, bodies, attachments, images, calendar invites
  iocs.py           2. extract and inspect links and indicators
  attachments.py       QR codes and HTML attachments
  enrich.py         3. threat intel lookups (with cache)
  scoring.py        4. points, verdict, recommended action
  bec.py               business email compromise rules
  report.py         5. the ticket
  history.py        case history, campaigns, analyst decisions
  respond.py        hunt queries, block list, reporter reply
  sanitize.py       making attacker text safe to display
samples/            fictional sample emails and demo intel
tests/              test suite and challenge-email fixtures
ui/console.css      dashboard styles
GUIDE.md            how each part works and why
```

## Security design

- **Nothing is opened or run.** Attachments are hashed, HTML is read as text, images are decoded as pixels. Links are never visited; only their reputation is looked up.
- **Attacker text is never rendered.** Subjects, names, file names and link text are escaped and defanged before they reach the dashboard or the ticket.
- **Indicators leave the tool only after validation.** Hunt queries and block lists need real values, so each one must match a strict pattern, free text is never put into a query, and CSV cells are guarded against formula injection.
- **Case history is local** (`.cache/cases.db`, git-ignored). It holds senders and subjects of reported mail: treat it as sensitive.

## Limitations

ePhishTriage is a rule-based decision-support tool, not a mail filter:

- It catches what it has rules for. A careful attacker using a clean, unrelated domain with valid authentication can score low, especially in offline mode.
- It does not detonate attachments or follow links, so it cannot see what a page or file actually does.
- Links inside PDF and Office documents are not extracted yet.
- Score weights are hand-set starting values, not tuned on labelled data.
- The hunt queries follow documented Microsoft Defender and Splunk table names but have not been run against a production environment. Check them against yours.

## Disclaimer

Built for learning and for SOC training. All sample emails, companies, people and domains are fictional; sample domains use the reserved `.example` and `.invalid` names and IP addresses come from documentation ranges. Do not upload real users' email to a shared instance without permission.
