"""
report.py

Generates a downloadable PDF report (with charts) summarizing a scan:
- Cover section: target, scan time, summary counts
- Bar chart: open ports by port number
- Pie chart: CVE findings by severity
- Detailed tables: ports/services/CVEs, missing security headers, SSL status

Uses matplotlib (charts, rendered headless with the 'Agg' backend) and
reportlab (PDF layout).
"""

import io
import datetime

import matplotlib
matplotlib.use("Agg")  # headless rendering, no display needed
import matplotlib.pyplot as plt

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
)

SEVERITY_COLORS = {
    "Critical": "#b91c1c",
    "High": "#c2410c",
    "Medium": "#b45309",
    "Low": "#15803d",
}


def _severity_counts(network_results):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    if not network_results or "results" not in network_results:
        return counts
    for r in network_results["results"]:
        for c in r.get("cves", []):
            sev = c.get("severity", "Low")
            if sev in counts:
                counts[sev] += 1
    return counts


def _make_ports_chart(network_results):
    """Bar chart of open ports (x-axis: port number, y-axis: just presence)."""
    if not network_results or not network_results.get("results"):
        return None

    ports = [r["port"] for r in network_results["results"]]
    services = [r.get("service") or "unknown" for r in network_results["results"]]

    fig, ax = plt.subplots(figsize=(6.5, 3))
    bars = ax.bar([str(p) for p in ports], [1] * len(ports), color="#38bdf8")
    ax.set_yticks([])
    ax.set_xlabel("Port")
    ax.set_title("Open Ports Discovered")
    for bar, svc in zip(bars, services):
        ax.text(bar.get_x() + bar.get_width() / 2, 1.02, svc,
                 ha="center", va="bottom", fontsize=7, rotation=45)
    ax.set_ylim(0, 1.4)
    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150)
    plt.close(fig)
    buf.seek(0)
    return buf


def _make_severity_chart(severity_counts):
    """Pie chart of CVE findings by severity. Returns None if no findings."""
    labels = [k for k, v in severity_counts.items() if v > 0]
    values = [v for v in severity_counts.values() if v > 0]
    if not values:
        return None

    fig, ax = plt.subplots(figsize=(4.5, 4))
    colors_list = [SEVERITY_COLORS[l] for l in labels]
    ax.pie(values, labels=labels, autopct="%1.0f%%", colors=colors_list,
           textprops={"fontsize": 9})
    ax.set_title("Known CVE Findings by Severity")
    fig.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150)
    plt.close(fig)
    buf.seek(0)
    return buf


def build_pdf_report(target, host, network_results, web_results, ssl_results):
    """Returns a BytesIO buffer containing the finished PDF."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                             topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleCustom", parent=styles["Title"], textColor=colors.HexColor("#0f172a"))
    h2_style = ParagraphStyle("H2Custom", parent=styles["Heading2"], textColor=colors.HexColor("#1e40af"), spaceBefore=14)
    normal = styles["Normal"]

    story = []

    # --- Cover ---
    story.append(Paragraph("MiniVuln Scanner Report", title_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Target: <b>{target}</b> (resolved host: {host})", normal))
    story.append(Paragraph(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal))
    story.append(Spacer(1, 16))

    severity_counts = _severity_counts(network_results)
    open_ports_count = len(network_results["results"]) if network_results and network_results.get("results") else 0
    total_cves = sum(severity_counts.values())

    summary_data = [
        ["Open Ports", "Total CVE Findings", "Critical", "High", "Medium", "Low"],
        [str(open_ports_count), str(total_cves),
         str(severity_counts["Critical"]), str(severity_counts["High"]),
         str(severity_counts["Medium"]), str(severity_counts["Low"])],
    ]
    summary_table = Table(summary_data, hAlign="LEFT")
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f1f5f9")),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    # --- Charts ---
    ports_chart_buf = _make_ports_chart(network_results)
    if ports_chart_buf:
        story.append(Paragraph("Open Ports Overview", h2_style))
        story.append(Image(ports_chart_buf, width=6.2 * inch, height=2.9 * inch))

    severity_chart_buf = _make_severity_chart(severity_counts)
    if severity_chart_buf:
        story.append(Paragraph("CVE Severity Breakdown", h2_style))
        story.append(Image(severity_chart_buf, width=3.8 * inch, height=3.4 * inch))

    story.append(PageBreak())

    # --- Detailed port/service/CVE table ---
    story.append(Paragraph("Network / Port Scan Detail", h2_style))
    if network_results and network_results.get("error"):
        story.append(Paragraph(f"Error: {network_results['error']}", normal))
    elif network_results and network_results.get("results"):
        table_data = [["Port", "Proto", "Service", "Product", "Version", "CVEs"]]
        for r in network_results["results"]:
            cve_text = ", ".join(c["cve_id"] for c in r.get("cves", [])) or "-"
            table_data.append([
                str(r["port"]), r["protocol"], r.get("service") or "-",
                r.get("product") or "-", r.get("version") or "-", cve_text
            ])
        t = Table(table_data, hAlign="LEFT", colWidths=[0.5*inch, 0.5*inch, 0.9*inch, 1.2*inch, 0.8*inch, 2.1*inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No network scan was run or no open ports were found.", normal))

    # --- Web / headers ---
    story.append(Paragraph("Web Security Headers", h2_style))
    if web_results and web_results.get("error"):
        story.append(Paragraph(f"Error: {web_results['error']}", normal))
    elif web_results:
        story.append(Paragraph(f"HTTP status: {web_results.get('status_code')}", normal))
        if web_results.get("server_banner"):
            story.append(Paragraph(f"Server banner disclosed: {web_results['server_banner']}", normal))
        missing = web_results.get("missing_headers", [])
        if missing:
            md = [["Missing Header", "Why it matters"]] + [[m["header"], m["description"]] for m in missing]
            mt = Table(md, hAlign="LEFT", colWidths=[2*inch, 4*inch])
            mt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7f1d1d")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ]))
            story.append(mt)
        else:
            story.append(Paragraph("All checked security headers were present.", normal))
    else:
        story.append(Paragraph("Web checks were not run.", normal))

    # --- SSL ---
    story.append(Paragraph("SSL/TLS Certificate", h2_style))
    if ssl_results and ssl_results.get("error"):
        story.append(Paragraph(f"Error: {ssl_results['error']}", normal))
    elif ssl_results:
        status = "Expired" if ssl_results.get("expired") else ("Expiring soon" if ssl_results.get("expiring_soon") else "Valid")
        story.append(Paragraph(f"Expires: {ssl_results.get('not_after')} ({ssl_results.get('days_left')} days left) — Status: {status}", normal))
    else:
        story.append(Paragraph("SSL check was not run.", normal))

    story.append(Spacer(1, 16))
    story.append(Paragraph(
        "Note: CVE matches are from a small curated offline list for common lab services, "
        "not the full NVD database. Absence of a listed CVE does not guarantee a service is secure.",
        ParagraphStyle("Note", parent=normal, textColor=colors.grey, fontSize=8)
    ))

    doc.build(story)
    buf.seek(0)
    return buf
