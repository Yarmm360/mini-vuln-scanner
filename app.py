"""
MiniVuln Scanner - A simplified vulnerability scanner (Nessus-style) built with Flask.

Features:
1. Network/port scan using nmap (service + version detection)
2. Basic web vulnerability checks (headers, SSL, banner disclosure)
3. Known CVE lookup (curated offline list + optional live NIST NVD)
4. Downloadable PDF report with charts
5. Inline visualizations (Chart.js) on the results & history pages
6. User accounts (SQLite) with per-user scan history

Requirements:
- nmap binary installed on the host system (apt install nmap / brew install nmap)
- pip install -r requirements.txt

Run:
    python app.py
Then open http://127.0.0.1:5000
"""

import socket
import ssl
import datetime
import shutil
import ipaddress
from urllib.parse import urlparse

import requests
import nmap  # python-nmap
from flask import Flask, render_template, request, flash, redirect, url_for, send_file
from flask_login import login_required, current_user

import database
from auth import auth_bp, login_manager
from cve_db import find_cves
from nvd_client import find_cves_live
from report import build_pdf_report

app = Flask(__name__)
app.secret_key = "change-this-secret-key"  # replace with a random value in production

database.init_db()
login_manager.init_app(app)
app.register_blueprint(auth_bp)

# ---------------------------------------------------------------------------
# Security headers we check for (common OWASP recommendations)
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS connections (HSTS).",
    "X-Frame-Options": "Protects against clickjacking.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "Content-Security-Policy": "Mitigates XSS and data injection attacks.",
    "Referrer-Policy": "Controls how much referrer info is leaked.",
    "Permissions-Policy": "Restricts use of browser features/APIs.",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def is_valid_target(target: str) -> bool:
    """Basic validation to avoid garbage input. Allows hostnames and IPs."""
    if not target or len(target) > 255:
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")
    return all(c in allowed for c in target)


def run_nmap_scan(target: str, ports: str = "1-1000", use_live_nvd: bool = False):
    """
    Run an nmap service/version scan against the target.
    Returns {"results": [{port, protocol, state, service, product, version, cves}, ...]} or {"error": ...}
    """
    if shutil.which("nmap") is None:
        return {"error": "nmap binary not found on this system. Install it with 'sudo apt install nmap'."}

    scanner = nmap.PortScanner()
    try:
        scanner.scan(target, ports, arguments="-sV -T4")
    except Exception as e:
        return {"error": f"nmap scan failed: {e}"}

    results = []
    if target not in scanner.all_hosts() and scanner.all_hosts():
        target = scanner.all_hosts()[0]

    if target in scanner.all_hosts():
        host_data = scanner[target]
        for proto in host_data.all_protocols():
            ports_list = host_data[proto].keys()
            for port in sorted(ports_list):
                p = host_data[proto][port]
                product = p.get("product") or ""
                version = p.get("version") or ""
                cves = find_cves(product, version)
                if use_live_nvd and product:
                    live_cves = find_cves_live(product, version)
                    known_ids = {c["cve_id"] for c in cves}
                    cves.extend(c for c in live_cves if c["cve_id"] not in known_ids)
                results.append({
                    "port": port,
                    "protocol": proto,
                    "state": p.get("state"),
                    "service": p.get("name"),
                    "product": product,
                    "version": version,
                    "cves": cves,
                })
    return {"results": results}


def check_security_headers(url: str):
    """Fetch a URL and check which recommended security headers are missing."""
    try:
        resp = requests.get(url, timeout=6, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        return {"error": f"Could not connect to {url}: {e}"}

    present = {}
    missing = []
    for header, description in SECURITY_HEADERS.items():
        if header in resp.headers:
            present[header] = resp.headers[header]
        else:
            missing.append({"header": header, "description": description})

    return {
        "status_code": resp.status_code,
        "present_headers": present,
        "missing_headers": missing,
        "server_banner": resp.headers.get("Server"),
        "powered_by": resp.headers.get("X-Powered-By"),
    }


def check_ssl_certificate(hostname: str, port: int = 443):
    """Check certificate validity and expiry for a given hostname."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.datetime.utcnow()).days
        return {
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "not_after": not_after.strftime("%Y-%m-%d"),
            "days_left": days_left,
            "expired": days_left < 0,
            "expiring_soon": 0 <= days_left <= 30,
        }
    except Exception as e:
        return {"error": f"SSL check failed: {e}"}


def _severity_counts(network_results):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    if not network_results or not network_results.get("results"):
        return counts
    for r in network_results["results"]:
        for c in r.get("cves", []):
            sev = c.get("severity", "Low")
            if sev in counts:
                counts[sev] += 1
            else:
                counts.setdefault("Low", 0)
    return counts


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
@login_required
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
@login_required
def scan():
    target_input = request.form.get("target", "").strip()
    scan_ports = request.form.get("ports", "1-1000").strip() or "1-1000"
    do_network = request.form.get("do_network") == "on"
    do_web = request.form.get("do_web") == "on"
    use_live_nvd = request.form.get("use_live_nvd") == "on"

    if not target_input:
        flash("Please enter a target hostname, IP, or URL.")
        return redirect(url_for("index"))

    parsed = urlparse(target_input if "://" in target_input else f"//{target_input}", scheme="http")
    host = parsed.hostname or target_input
    scheme = parsed.scheme if "://" in target_input else "http"

    if not is_valid_target(host):
        flash("Invalid target format.")
        return redirect(url_for("index"))

    network_results = None
    web_results = None
    ssl_results = None

    if do_network:
        network_results = run_nmap_scan(host, scan_ports, use_live_nvd)

    if do_web:
        web_url = f"{scheme}://{host}" if "://" not in target_input else target_input
        web_results = check_security_headers(web_url)
        ssl_results = check_ssl_certificate(host, 443)

    scan_id = database.save_scan(
        int(current_user.id), target_input, host, network_results, web_results, ssl_results
    )

    return render_template(
        "results.html",
        target=target_input,
        host=host,
        network_results=network_results,
        web_results=web_results,
        ssl_results=ssl_results,
        scan_id=scan_id,
        severity_counts=_severity_counts(network_results),
    )


@app.route("/history")
@login_required
def history():
    scans = database.get_scans_for_user(int(current_user.id))

    total_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    scans_over_time = []
    for s in scans:
        sev = _severity_counts(s["network_results"])
        for k in total_severity:
            total_severity[k] += sev[k]
        scans_over_time.append(s["scanned_at"][:10])

    return render_template(
        "history.html",
        scans=scans,
        total_severity=total_severity,
        scans_over_time=scans_over_time,
    )


@app.route("/history/<int:scan_id>")
@login_required
def view_past_scan(scan_id):
    s = database.get_scan_by_id(scan_id, int(current_user.id))
    if not s:
        flash("Scan not found.")
        return redirect(url_for("history"))

    return render_template(
        "results.html",
        target=s["target"],
        host=s["host"],
        network_results=s["network_results"],
        web_results=s["web_results"],
        ssl_results=s["ssl_results"],
        scan_id=s["id"],
        severity_counts=_severity_counts(s["network_results"]),
        from_history=True,
    )


@app.route("/report/<int:scan_id>")
@login_required
def download_report(scan_id):
    s = database.get_scan_by_id(scan_id, int(current_user.id))
    if not s:
        flash("That report doesn't exist or you don't have access to it.")
        return redirect(url_for("index"))

    pdf_buf = build_pdf_report(
        s["target"], s["host"], s["network_results"], s["web_results"], s["ssl_results"],
    )
    filename = f"minivuln_report_{s['host']}.pdf".replace("/", "_")
    return send_file(pdf_buf, mimetype="application/pdf",
                      as_attachment=True, download_name=filename)


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
