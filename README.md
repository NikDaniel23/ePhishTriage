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

## Installation

ePhishTriage runs on your own computer. Nothing is uploaded anywhere: the dashboard is a local web page at `http://localhost:8501` that only your machine can open.

### 1. Install the prerequisites

You need **Python 3.10 or newer** and **Git**. Check whether you already have them:

```bash
python --version
git --version
```

If either command is not found, install it:

| System | Python | Git |
|---|---|---|
| **Windows** | `winget install Python.Python.3.12`, or the installer from [python.org](https://www.python.org/downloads/) (tick **"Add python.exe to PATH"**) | `winget install Git.Git`, or [git-scm.com](https://git-scm.com/download/win) |
| **macOS** | `brew install python` | `brew install git` (or run `git` once and accept the Xcode tools prompt) |
| **Ubuntu / Debian** | `sudo apt install python3 python3-venv python3-pip` | `sudo apt install git` |

Close and reopen your terminal after installing, so it finds the new commands. On macOS and Linux the command may be `python3` instead of `python`.

### 2. Download the project

```bash
git clone https://github.com/NikDaniel23/ePhishTriage.git
cd ePhishTriage
```

No Git? Use **Code > Download ZIP** on this page, unzip it, and open a terminal in the unzipped folder.

### 3. Create a virtual environment and install the dependencies

A virtual environment (`.venv`) keeps this project's packages separate from the rest of your system.

**Windows (PowerShell):**

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install --upgrade pip
.venv\Scripts\python -m pip install -r requirements.txt
```

**macOS / Linux:**

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

This downloads about 150 MB (Streamlit, OpenCV for QR codes, and the Outlook `.msg` reader) and takes a minute or two.

## Run it on your own localhost

**Windows:**

```powershell
.venv\Scripts\python -m streamlit run app.py
```

**macOS / Linux:**

```bash
.venv/bin/python -m streamlit run app.py
```

Your browser opens **http://localhost:8501** automatically. If it does not, open that address yourself.

- **It is local only.** `.streamlit/config.toml` binds the server to `localhost`, so other computers on your network cannot open your dashboard or your case history.
- **No API keys needed.** It starts in offline mode with the demo threat intel in `samples/mock_intel.json`, so everything works without keys or internet.
- **Try it:** drag a `.eml` or `.msg` file onto the page, or pick one of the samples in the sidebar.
- **To stop it:** press `Ctrl + C` in the terminal.
- **To run it again later:** open a terminal in the project folder and run the same command. There is no need to reinstall.

**Using a different port** (if 8501 is busy):

```bash
python -m streamlit run app.py --server.port 8600
```

Then open http://localhost:8600. Use the `.venv` Python path shown above, as in the other commands.

### Command line (no dashboard)

**Windows:**

```powershell
.venv\Scripts\python cli.py samples\01_obvious_phish.eml
.venv\Scripts\python cli.py path\to\suspicious.eml --live      # real VirusTotal / AbuseIPDB lookups
```

**macOS / Linux:**

```bash
.venv/bin/python cli.py samples/01_obvious_phish.eml
.venv/bin/python cli.py path/to/suspicious.eml --live
```

The report is printed as Markdown, ready to paste into a ticket.

### Troubleshooting

| Problem | Fix |
|---|---|
| `python` is not recognized (Windows) | Reinstall Python with **"Add python.exe to PATH"** ticked, then open a new terminal. Or use the `py` launcher: `py -m venv .venv` |
| `streamlit` is not recognized | You ran `streamlit` directly. Use the full command above (`.venv\Scripts\python -m streamlit run app.py`), which does not depend on PATH |
| `No module named ...` | The packages were installed into a different Python. Rerun step 3 using the `.venv` Python path |
| `Port 8501 is already in use` | ePhishTriage (or another Streamlit app) is already running. Use that tab, stop it with `Ctrl + C`, or pick another port as shown above |
| `running scripts is disabled on this system` (when using `run.ps1`) | Run once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| "Images were not checked for QR codes" | OpenCV did not install. Run `.venv\Scripts\python -m pip install opencv-python-headless` (or the macOS / Linux equivalent) |

### Check that everything works

```bash
.venv/bin/python -m pytest -q          # macOS / Linux
.venv\Scripts\python -m pytest -q      # Windows
```

All tests should pass.

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
