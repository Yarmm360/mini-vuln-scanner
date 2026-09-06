# MiniVuln Scanner

A simplified, Nessus-style web vulnerability scanner built with **Flask**, developed
as a coursework project. It performs network/service discovery, basic web security
checks, known-CVE matching, and presents results through a multi-user web
application with saved scan history and exportable PDF reports.

---

## 1. Overview

MiniVuln Scanner demonstrates the core workflow of a vulnerability assessment tool
like Nessus, at a scale appropriate for a class assignment:

1. **Scan a target** (IP, hostname, or URL) for open ports and running services.
2. **Match detected services** against known public CVEs.
3. **Check basic web hygiene** (security headers, SSL certificate status).
4. **Visualize results** with in-browser charts.
5. **Save every scan** to a personal account and review it later.
6. **Export a PDF report** suitable for a lab write-up or submission.

---

## 2. Features

| # | Feature | Details |
|---|---------|---------|
| 1 | Network / port scan | Uses `nmap` (via `python-nmap`) with service/version detection (`-sV`) |
| 2 | Web checks | Missing security headers (HSTS, CSP, X-Frame-Options, etc.), `Server`/`X-Powered-By` banner disclosure |
| 3 | SSL/TLS check | Certificate validity and expiry date |
| 4 | Known CVE lookup | Curated **offline** database (`cve_db.py`) matching product + version to public CVE IDs |
| 5 | Optional live CVE lookup | Queries the real NIST NVD CVE API 2.0 (`nvd_client.py`), merged with the offline list, cached locally |
| 6 | PDF report | Downloadable report (`report.py`) with summary tables and charts (matplotlib + reportlab) |
| 7 | In-browser visualizations | Chart.js bar/pie/line charts on the results and history pages |
| 8 | User accounts | Sign up / log in / log out (SQLite + Flask-Login), passwords hashed with werkzeug's scrypt |
| 9 | Scan history | Every scan is saved per-user; a History page lists past scans with an all-time dashboard |

---

## 3. Architecture

```
mini-vulnnn-scanner/
├── app.py            # Flask routes, scan orchestration
├── auth.py           # Registration / login / logout (Flask-Login)
├── database.py       # SQLite schema + user/scan persistence
├── cve_db.py          # Curated offline CVE database + version matching
├── nvd_client.py      # Optional live NIST NVD API client with local caching
├── report.py          # PDF report generation (matplotlib charts + reportlab layout)
├── requirements.txt
├── static/
│   └── chart.umd.min.js   # Chart.js, vendored locally (no CDN dependency)
└── templates/
    ├── base.html       # Shared layout, nav bar, shared styles
    ├── login.html
    ├── register.html
    ├── index.html       # Scan form
    ├── results.html     # Scan results + charts
    └── history.html     # Scan history + dashboard charts
```

**Tech stack:** Flask, Flask-Login, SQLite (via `sqlite3`), `python-nmap`, `requests`,
`reportlab`, `matplotlib`, Chart.js.

**Data flow:** `Scan form → app.py orchestrates nmap + header/SSL checks → CVE
lookup (cve_db.py, optionally nvd_client.py) → saved to SQLite (database.py) → rendered
in results.html with Chart.js → optionally exported as PDF (report.py)`.

---

## 4. Setup

### 4.1 Prerequisites

Install `nmap` on your system (required for the network scan):

```bash
# Debian/Ubuntu
sudo apt install nmap

# macOS (Homebrew)
brew install nmap

# Windows — download the installer from https://nmap.org/download.html
```

### 4.2 Install and run

```bash
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000` in your browser. You'll be redirected to sign up
or log in before you can run a scan.

A local SQLite file `minivuln.db` is created automatically on first run, in the same
folder as `app.py`. It's just a file — delete it any time to reset all accounts and
scan history.

### 4.3 (Optional) Enable live NIST NVD lookups

By default, CVE matching uses only the small curated offline list. To also pull
live data from the real NVD:

1. Request a free API key: https://nvd.nist.gov/developers/request-an-api-key
   (optional — without one you're limited to ~5 requests/30s instead of 50).
2. Set it as an environment variable before running the app:
   ```bash
   export NVD_API_KEY="your-key-here"    # macOS/Linux
   set NVD_API_KEY=your-key-here         # Windows (cmd)
   ```
3. Check **"Also query live NIST NVD database"** on the scan form.

Live results are cached in `nvd_cache.json` for 24 hours so repeat scans don't
re-hit the rate-limited API.

---

## 5. Usage

1. **Sign up** for an account (or log in if you already have one).
2. On the **Scan** page, enter a target — an IP, hostname, or full URL — and choose
   which checks to run (network scan, web checks, or both).
3. Click **Run Scan**. The results page shows:
   - A bar chart of open ports and a pie chart of CVE severity
   - A detailed port/service/CVE table
   - Missing security headers and SSL certificate status
4. Click **Download PDF Report** for a exportable version with the same charts and
   tables — useful for attaching to a lab write-up.
5. Click **History** in the nav bar to see every scan you've run, with an all-time
   severity dashboard and a scans-over-time chart. You can re-view or re-download
   the PDF for any past scan from here.

---

## 6. ⚠️ Authorized use only

Only scan systems you **own** or have **explicit written permission** to test.
Scanning systems without authorization is illegal in most jurisdictions (e.g. the
U.S. Computer Fraud and Abuse Act, UK Computer Misuse Act), even for coursework.

For practice, use intentionally scannable/legal targets such as:
- [`scanme.nmap.org`](https://nmap.org/book/legal-issues.html) — nmap's official public test target
- A local VM lab (e.g. **Metasploitable 2**, **DVWA**, **OWASP Juice Shop**)

---

## 7. Known limitations & scope notes

For an accurate write-up, it's worth being explicit about where this differs from a
real product like Nessus:

- **CVE coverage is a small curated subset (~15 entries)**, not the full NVD —
  matched by product name + version range in `cve_db.py`. "No CVEs found" does
  **not** mean a service has no vulnerabilities. The optional live NVD lookup
  (Section 4.3) narrows this gap but was validated with mocked API responses,
  not exhaustive real-world testing.
- **No CPE mapping** — real scanners map detected software to standardized CPE
  identifiers for precise matching; this project matches on raw product/version
  strings from nmap, which is simpler but less precise.
- **No authenticated scanning** — Nessus can log into a host (SSH/WinRM) for
  deeper, credentialed checks; this tool is unauthenticated/external only.
- **No aggregate risk scoring** — findings are shown per-port with a severity
  label, but there's no combined CVSS-style score per host.
- **SQLite, single file, no connection pooling** — appropriate for a local,
  single-user demo; not intended for concurrent multi-user production traffic.

### Possible extensions
- Index the full NVD JSON feeds by CPE and refresh on a schedule, replacing the
  curated list with genuinely comprehensive data.
- Map nmap product/version output to CPE identifiers for higher-precision matching.
- Add authenticated scanning and a combined per-host risk score.

---

## 8. Security notes on the account system

- Passwords are hashed with werkzeug's `generate_password_hash` (scrypt-based) —
  never stored in plaintext.
- Scan history is scoped to the owning user at the database query level
  (`get_scan_by_id(scan_id, user_id)`), so one user cannot view or download another
  user's report by guessing a scan ID. This was verified with an automated test
  simulating a second account attempting cross-user access.
- `app.secret_key` in `app.py` is a placeholder string. **Replace it with a long
  random value** before any real or shared deployment:
  ```bash
  python -c "import secrets; print(secrets.token_hex(32))"
  ```
  A predictable secret key allows an attacker to forge session cookies.

---

## 9. Credits / academic note

Built as a coursework project using Flask, nmap, and open public CVE data
(NIST NVD). Intended for educational use in a controlled lab environment.
