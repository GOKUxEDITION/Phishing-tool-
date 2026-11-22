# Phishing-tool- · 90X Defensive Suite

Local defensive triage tools, designed for Termux/Linux. No credential harvesting, OTP/session capture, stealth, login impersonation, or automated fetching of submitted URLs.

## Modules
- URL heuristic analysis and batch scanning
- Raw email/header triage: Reply-To mismatch, supplied Authentication-Results hints, URL analysis, suspicious attachment extensions
- IOC extraction: URLs, IPv4 strings, domains
- Local awareness simulation (click-only)
- SQLite event history
- CSV and JSON exports
- Loopback-only Flask server

## Install (Termux)
```bash
git clone https://github.com/GOKUxEDITION/Phishing-tool-.git
cd Phishing-tool-
pkg install python -y
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Browse http://127.0.0.1:5000

## Email triage
Paste raw message/header text into the UI. Authentication-Results is parsed as a supplied claim and is not independently validated. Strip personal information before using.

## Safety and limits
Submitted URLs are parsed only; the suite does not fetch them. IOC extraction is text-based, and extracted IP/domain strings are not validated against live threat intelligence. Heuristic scores are not a verdict.

## Hardening and CI
- API request body cap (256 KiB)
- Lightweight per-IP API rate limiter (local process)
- CSP and common browser security response headers
- GitHub Actions test workflow on push, pull request, or manual run
- Security model and roadmap: `SECURITY.md`, `docs/ROADMAP.md`

## Tests
```bash
python -m unittest discover -s tests -v
```
The workflow runs tests automatically in GitHub Actions. Tests have not yet been executed on your Termux device.
