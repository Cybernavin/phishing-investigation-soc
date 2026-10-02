from pathlib import Path
from datetime import datetime
from html import escape
import json


def _safe(value):
    """Convert a value to safe HTML text."""
    if value is None:
        return "Unknown"
    return escape(str(value))


def _status_class(value):
    """Return a CSS class based on a status/value."""
    text = str(value or "").lower()

    if any(word in text for word in [
        "malicious", "fail", "failed", "error", "high", "suspicious"
    ]):
        return "danger"

    if any(word in text for word in [
        "medium", "redirect", "warning", "pending"
    ]):
        return "warning"

    if any(word in text for word in [
        "pass", "clean", "safe", "success", "low", "not malicious"
    ]):
        return "success"

    return "neutral"


def _badge(value):
    css = _status_class(value)
    return f'<span class="badge {css}">{_safe(value)}</span>'


def _card(title, value, subtitle=""):
    return f"""
    <div class="metric-card">
        <div class="metric-title">{_safe(title)}</div>
        <div class="metric-value">{_safe(value)}</div>
        <div class="metric-subtitle">{_safe(subtitle)}</div>
    </div>
    """


def _list(items, empty_text="No data available."):
    if not items:
        return f'<div class="empty">{_safe(empty_text)}</div>'

    html = ['<ul class="clean-list">']

    for item in items:
        if isinstance(item, dict):
            text = item.get("description") or item.get("message") or json.dumps(
                item, ensure_ascii=False, default=str
            )
        else:
            text = str(item)

        html.append(f"<li>{_safe(text)}</li>")

    html.append("</ul>")
    return "\n".join(html)


def _render_ioc_list(title, values):
    values = values or []

    if not values:
        return ""

    rows = []

    for value in values:
        safe_value = _safe(value)

        if title.lower() == "urls":
            display = (
                f'<a href="{safe_value}" target="_blank" '
                f'rel="noopener noreferrer">{safe_value}</a>'
            )
        else:
            display = safe_value

        rows.append(f"<tr><td>{display}</td></tr>")

    return f"""
    <div class="subsection">
        <h3>{_safe(title)}</h3>
        <table>
            <thead>
                <tr><th>Value</th></tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </div>
    """


def _render_attachments(attachments):
    successful = [
        item for item in (attachments or [])
        if item.get("status") == "success"
    ]

    if not successful:
        return '<div class="empty">No successfully analyzed attachments.</div>'

    rows = []

    for item in successful:
        rows.append(
            "<tr>"
            f"<td>{_safe(item.get('filename', 'Unknown'))}</td>"
            f"<td>{_safe(item.get('size', 'Unknown'))}</td>"
            f"<td><code>{_safe(item.get('sha256', 'Unknown'))}</code></td>"
            f"<td><code>{_safe(item.get('md5', 'Unknown'))}</code></td>"
            "</tr>"
        )

    return f"""
    <table>
        <thead>
            <tr>
                <th>Filename</th>
                <th>Size</th>
                <th>SHA-256</th>
                <th>MD5</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """


def _render_threat_intelligence(results, title):
    results = results or []

    if not results:
        return '<div class="empty">No checks were performed.</div>'

    rows = []

    for result in results:
        if not isinstance(result, dict):
            rows.append(
                f"<tr><td colspan='4'>{_safe(result)}</td></tr>"
            )
            continue

        indicator = (
            result.get("url")
            or result.get("hash")
            or result.get("indicator")
            or result.get("type")
            or "Unknown"
        )

        status = result.get("status", "unknown")
        message = result.get("message", "")

        malicious = result.get("malicious")
        suspicious = result.get("suspicious")

        detection = ""

        if malicious is not None or suspicious is not None:
            detection = (
                f"Malicious: {_safe(malicious if malicious is not None else 0)}"
                f"<br>Suspicious: {_safe(suspicious if suspicious is not None else 0)}"
            )

        rows.append(
            "<tr>"
            f"<td>{_safe(indicator)}</td>"
            f"<td>{_badge(status)}</td>"
            f"<td>{detection or '—'}</td>"
            f"<td>{_safe(message) if message else '—'}</td>"
            "</tr>"
        )

    return f"""
    <table>
        <thead>
            <tr>
                <th>Indicator</th>
                <th>Status</th>
                <th>Detection</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """


def _render_authentication(results):
    results = results or {}

    checks = [
        ("SPF", results.get("spf", "unknown")),
        ("DKIM", results.get("dkim", "unknown")),
        ("DMARC", results.get("dmarc", "unknown")),
    ]

    rows = []

    for name, value in checks:
        rows.append(
            f"""
            <div class="auth-item">
                <span class="auth-name">{name}</span>
                {_badge(value)}
            </div>
            """
        )

    return f'<div class="auth-grid">{"".join(rows)}</div>'


def _render_header_analysis(results):
    results = results or {}
    findings = results.get("findings", [])

    if findings:
        return _list(findings)

    return '<div class="empty success-box">No obvious header anomalies found.</div>'


def _render_evidence(results):
    results = results or {}
    summary = results.get("summary", {})
    correlations = results.get("correlations", [])

    correlation_count = summary.get("correlation_count", len(correlations))
    finding_count = summary.get("finding_count", 0)

    content = f"""
    <div class="evidence-summary">
        {_card("Correlations", correlation_count, "Detected relationships")}
        {_card("Findings", finding_count, "Investigation findings")}
    </div>
    """

    if correlations:
        content += _list(correlations)
    else:
        content += (
            '<div class="empty success-box">'
            "No evidence correlations were identified."
            "</div>"
        )

    return content


def _render_risk(results):
    results = results or {}

    score = results.get("score", 0)
    severity = results.get("severity", "Unknown")
    reasons = results.get("reasons", [])

    try:
        score_number = int(score)
    except (TypeError, ValueError):
        score_number = 0

    score_number = max(0, min(100, score_number))

    if str(severity).lower() == "high":
        risk_class = "risk-high"
    elif str(severity).lower() == "medium":
        risk_class = "risk-medium"
    else:
        risk_class = "risk-low"

    return f"""
    <div class="risk-panel {risk_class}">
        <div>
            <div class="risk-label">Risk Score</div>
            <div class="risk-score">{score_number}<span>/100</span></div>
        </div>
        <div class="risk-severity">
            <div class="risk-label">Severity</div>
            <div class="severity-text">{_safe(severity)}</div>
        </div>
    </div>

    <div class="risk-bar">
        <div class="risk-fill" style="width: {score_number}%"></div>
    </div>

    <h3>Risk Factors</h3>
    {_list(reasons, "No risk factors identified.")}
    """


def generate_report(
    file_name,
    email_details,
    header_results,
    authentication_results,
    ioc_results,
    attachment_results,
    virustotal_results,
    urlscan_results,
    evidence_results,
    risk_results
):
    """
    Generate a clean standalone HTML SOC investigation report.

    This function intentionally accepts the same investigation data that
    main.py already produces. It does not perform any additional analysis.
    """

    email_details = email_details or {}
    ioc_results = ioc_results or {}

    subject = email_details.get("subject", "Unknown Subject")
    sender = email_details.get("from", "Unknown")
    recipient = email_details.get("to", "Unknown")

    urls = ioc_results.get("urls", [])
    domains = ioc_results.get("domains", [])
    ip_addresses = ioc_results.get("ip_addresses", [])
    email_addresses = ioc_results.get("email_addresses", [])

    score = (risk_results or {}).get("score", 0)
    severity = (risk_results or {}).get("severity", "Unknown")

    try:
        score_number = int(score)
    except (TypeError, ValueError):
        score_number = 0

    score_number = max(0, min(100, score_number))

    # Make the whole report background red for critical-risk reports.
    body_class = "critical-risk" if score_number >= 80 else ""

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Phishing Investigation - {_safe(file_name)}</title>

<style>
:root {{
    --bg: #070b14;
    --bg-soft: #0b1220;
    --panel: rgba(15, 23, 42, .82);
    --panel-solid: #0f172a;
    --panel-light: #131e31;
    --border: rgba(148, 163, 184, .16);
    --border-strong: rgba(148, 163, 184, .28);
    --text: #f1f5f9;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --green: #22c55e;
    --yellow: #f59e0b;
    --red: #ef4444;
    --red-dark: #7f1d1d;
    --purple: #a78bfa;
    --shadow: 0 18px 50px rgba(0, 0, 0, .28);
}}

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    min-height: 100vh;
    background:
        radial-gradient(circle at 8% 0%, rgba(56,189,248,.12), transparent 28%),
        radial-gradient(circle at 92% 4%, rgba(129,140,248,.12), transparent 26%),
        linear-gradient(180deg, #080d18 0%, var(--bg) 55%, #060a12 100%);
    color: var(--text);
    font-family: "Segoe UI", Inter, Arial, sans-serif;
    line-height: 1.55;
}}

body.critical-risk {{
    background:
        radial-gradient(circle at 8% 0%, rgba(239,68,68,.38), transparent 30%),
        radial-gradient(circle at 92% 4%, rgba(185,28,28,.28), transparent 28%),
        linear-gradient(180deg, #25080b 0%, #10070a 55%, #080407 100%);
}}

body::before {{
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
    background-image: linear-gradient(rgba(255,255,255,.018) 1px, transparent 1px),
                      linear-gradient(90deg, rgba(255,255,255,.018) 1px, transparent 1px);
    background-size: 42px 42px;
    mask-image: linear-gradient(to bottom, black, transparent 85%);
    z-index: -1;
}}

.container {{
    max-width: 1320px;
    margin: 0 auto;
    padding: 34px 24px 70px;
}}

.hero {{
    position: relative;
    overflow: hidden;
    background:
        linear-gradient(135deg, rgba(15,23,42,.94), rgba(17,24,39,.78));
    border: 1px solid var(--border);
    border-radius: 24px;
    padding: 30px;
    box-shadow: var(--shadow);
    margin-bottom: 24px;
    backdrop-filter: blur(16px);
}}

.hero::after {{
    content: "";
    position: absolute;
    width: 280px;
    height: 280px;
    right: -90px;
    top: -130px;
    background: radial-gradient(circle, rgba(56,189,248,.20), transparent 68%);
    pointer-events: none;
}}

body.critical-risk .hero {{
    border-color: rgba(239,68,68,.42);
    background: linear-gradient(135deg, rgba(69,10,10,.92), rgba(31,12,16,.86));
}}

body.critical-risk .hero::after {{
    background: radial-gradient(circle, rgba(239,68,68,.30), transparent 68%);
}}

.hero-top {{
    display: flex;
    justify-content: space-between;
    gap: 20px;
    align-items: flex-start;
}}

.logo {{
    width: 58px;
    height: 58px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 16px;
    background: linear-gradient(135deg, #0ea5e9, #6366f1);
    color: white;
    font-size: 26px;
    font-weight: 900;
    box-shadow: 0 10px 28px rgba(14,165,233,.22);
}}

body.critical-risk .logo {{
    background: linear-gradient(135deg, #ef4444, #991b1b);
    box-shadow: 0 10px 30px rgba(239,68,68,.28);
}}

h1 {{
    margin: 0 0 7px;
    font-size: 30px;
}}

.hero p {{
    color: var(--muted);
    margin: 4px 0;
}}

.report-meta {{
    margin-top: 22px;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
    gap: 12px;
}}

.meta {{
    background: rgba(255,255,255,.035);
    border: 1px solid var(--border);
    padding: 13px 15px;
    border-radius: 12px;
}}

.meta-label {{
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: .08em;
}}

.meta-value {{
    margin-top: 4px;
    font-weight: 600;
    word-break: break-word;
}}

section {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 26px;
    margin: 18px 0;
    box-shadow: 0 14px 38px rgba(0,0,0,.18);
    backdrop-filter: blur(14px);
}}

section:hover {{
    border-color: var(--border-strong);
}}

.section-title {{
    display: flex;
    align-items: center;
    gap: 13px;
    margin-bottom: 21px;
    padding-bottom: 14px;
    border-bottom: 1px solid rgba(148,163,184,.10);
}}

.section-number {{
    width: 34px;
    height: 34px;
    border-radius: 10px;
    background: rgba(56,189,248,.13);
    color: var(--accent);
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 800;
}}

h2 {{
    margin: 0;
    font-size: 21px;
}}

h3 {{
    margin-top: 24px;
    color: #cbd5e1;
}}

.metrics {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(175px, 1fr));
    gap: 13px;
}}

.metric-card {{
    position: relative;
    overflow: hidden;
    background: linear-gradient(145deg, rgba(19,30,49,.96), rgba(12,19,32,.96));
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 19px;
    box-shadow: 0 8px 24px rgba(0,0,0,.14);
}}

.metric-card::before {{
    content: "";
    position: absolute;
    left: 0;
    top: 0;
    width: 3px;
    height: 100%;
    background: var(--accent);
    opacity: .75;
}}

.metric-title {{
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: .06em;
}}

.metric-value {{
    font-size: 27px;
    font-weight: 800;
    margin-top: 5px;
}}

.metric-subtitle {{
    color: var(--muted);
    font-size: 12px;
    margin-top: 3px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    overflow: hidden;
    border-radius: 12px;
    margin-top: 12px;
}}

th {{
    background: rgba(30,41,59,.88);
    color: #cbd5e1;
    text-align: left;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .08em;
}}

th, td {{
    padding: 12px 13px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
    word-break: break-word;
}}

td {{
    color: #dbe4ef;
}}

tr:hover td {{
    background: rgba(255,255,255,.025);
}}

a {{
    color: var(--accent);
    text-decoration: none;
}}

a:hover {{
    text-decoration: underline;
}}

code {{
    color: #c4b5fd;
    font-family: Consolas, monospace;
    font-size: 12px;
}}

.badge {{
    display: inline-block;
    padding: 5px 10px;
    border-radius: 999px;
    font-size: 10px;
    font-weight: 900;
    text-transform: uppercase;
    letter-spacing: .07em;
    border: 1px solid transparent;
}}

.badge.success {{
    background: rgba(34,197,94,.13);
    color: #4ade80;
}}

.badge.warning {{
    background: rgba(245,158,11,.13);
    color: #fbbf24;
}}

.badge.danger {{
    background: rgba(239,68,68,.13);
    color: #f87171;
}}

.badge.neutral {{
    background: rgba(148,163,184,.13);
    color: #cbd5e1;
}}

.auth-grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 14px;
}}

.auth-item {{
    background: var(--panel-light);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 17px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}}

.auth-name {{
    font-size: 17px;
    font-weight: 700;
}}

.clean-list {{
    padding-left: 0;
    list-style: none;
    margin: 12px 0;
}}

.clean-list li {{
    background: var(--panel-light);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: 10px;
    padding: 12px 15px;
    margin: 9px 0;
}}

.empty {{
    color: var(--muted);
    background: rgba(148,163,184,.05);
    border: 1px dashed var(--border);
    border-radius: 12px;
    padding: 16px;
}}

.success-box {{
    border-left: 3px solid var(--green);
}}

.evidence-summary {{
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 14px;
    margin-bottom: 18px;
}}

.risk-panel {{
    position: relative;
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 28px 30px;
    border-radius: 20px;
    border: 1px solid var(--border);
    overflow: hidden;
}}

.risk-panel::after {{
    content: "";
    position: absolute;
    width: 220px;
    height: 220px;
    right: -90px;
    top: -100px;
    border-radius: 50%;
    background: rgba(255,255,255,.035);
}}

.risk-high {{
    background:
        linear-gradient(135deg, rgba(127,29,29,.48), rgba(69,10,10,.22));
    border-color: rgba(239,68,68,.52);
    box-shadow: 0 12px 34px rgba(127,29,29,.20);
}}

.risk-medium {{
    background:
        linear-gradient(135deg, rgba(120,53,15,.38), rgba(69,45,10,.18));
    border-color: rgba(245,158,11,.48);
}}

.risk-low {{
    background:
        linear-gradient(135deg, rgba(20,83,45,.32), rgba(10,55,34,.16));
    border-color: rgba(34,197,94,.42);
}}

.risk-label {{
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: .08em;
}}

.risk-score {{
    font-size: 54px;
    line-height: 1;
    font-weight: 900;
    letter-spacing: -.04em;
    text-shadow: 0 4px 18px rgba(0,0,0,.28);
}}

.risk-score span {{
    color: var(--muted);
    font-size: 17px;
}}

.severity-text {{
    font-size: 25px;
    font-weight: 800;
}}

.risk-bar {{
    height: 9px;
    background: #1e293b;
    border-radius: 999px;
    margin: 15px 0 25px;
    overflow: hidden;
}}

.risk-fill {{
    height: 100%;
    background: linear-gradient(90deg, #22c55e, #f59e0b, #ef4444);
    border-radius: inherit;
}}

.subsection {{
    margin-top: 22px;
}}

.footer {{
    text-align: center;
    color: #64748b;
    padding-top: 28px;
    font-size: 12px;
}}

.critical-banner {{
    display: flex;
    align-items: center;
    gap: 13px;
    padding: 15px 18px;
    margin: 0 0 20px;
    border: 1px solid rgba(239,68,68,.48);
    border-radius: 15px;
    background: linear-gradient(90deg, rgba(127,29,29,.50), rgba(69,10,10,.22));
    box-shadow: 0 10px 28px rgba(127,29,29,.16);
}}

.critical-banner strong {{
    display: block;
    color: #fca5a5;
    font-size: 12px;
    letter-spacing: .08em;
}}

.critical-banner span:not(.critical-dot) {{
    display: block;
    color: #fecaca;
    font-size: 12px;
    margin-top: 2px;
}}

.critical-dot {{
    width: 10px;
    height: 10px;
    flex: 0 0 10px;
    border-radius: 50%;
    background: #ef4444;
    box-shadow: 0 0 0 6px rgba(239,68,68,.12), 0 0 18px rgba(239,68,68,.65);
}}

@media (max-width: 700px) {{
    .hero-top {{
        flex-direction: column;
    }}

    .auth-grid,
    .evidence-summary {{
        grid-template-columns: 1fr;
    }}

    .risk-panel {{
        flex-direction: column;
        align-items: flex-start;
        gap: 18px;
    }}

    .container {{
        padding: 20px 13px 45px;
    }}

    .hero, section {{
        padding: 20px;
        border-radius: 17px;
    }}

    .critical-banner {{
        align-items: flex-start;
    }}

    th, td {{
        padding: 9px;
    }}
}}

@media print {{
    body {{
        background: white;
        color: #111827;
    }}

    body::before {{
        display: none;
    }}

    section, .hero {{
        box-shadow: none;
        break-inside: avoid;
    }}
}}
</style>
</head>

<body class="{body_class}">
<div class="container">

<header class="hero">
    <div class="hero-top">
        <div style="display:flex;gap:17px;align-items:flex-start;">
            <div class="logo">S</div>
            <div>
                <h1>SOC Phishing Email Investigation</h1>
                <p>Enterprise Email Security Investigation Report</p>
                <p>Generated: {_safe(generated_at)}</p>
            </div>
        </div>
        <div>
            {_badge(severity)}
        </div>
    </div>

    <div class="report-meta">
        <div class="meta">
            <div class="meta-label">Source File</div>
            <div class="meta-value">{_safe(file_name)}</div>
        </div>

        <div class="meta">
            <div class="meta-label">Subject</div>
            <div class="meta-value">{_safe(subject)}</div>
        </div>

        <div class="meta">
            <div class="meta-label">From</div>
            <div class="meta-value">{_safe(sender)}</div>
        </div>

        <div class="meta">
            <div class="meta-label">To</div>
            <div class="meta-value">{_safe(recipient)}</div>
        </div>
    </div>
</header>

{f'<div class="critical-banner"><span class="critical-dot"></span><div><strong>CRITICAL RISK DETECTED</strong><span>Automated investigation score is {score_number}/100. Review the evidence before taking response actions.</span></div></div>' if score_number >= 80 else ''}

<section>
    <div class="section-title">
        <div class="section-number">01</div>
        <h2>Investigation Overview</h2>
    </div>

    <div class="metrics">
        {_card("Risk Score", f"{score}/100", severity)}
        {_card("URLs", len(urls), "Extracted indicators")}
        {_card("Domains", len(domains), "Extracted indicators")}
        {_card("IP Addresses", len(ip_addresses), "Extracted indicators")}
        {_card("Email Addresses", len(email_addresses), "Extracted indicators")}
        {_card("Attachments", len(attachment_results or []), "Analyzed files")}
    </div>
</section>

<section>
    <div class="section-title">
        <div class="section-number">02</div>
        <h2>Header Analysis</h2>
    </div>

    {_render_header_analysis(header_results)}
</section>

<section>
    <div class="section-title">
        <div class="section-number">03</div>
        <h2>Email Authentication</h2>
    </div>

    {_render_authentication(authentication_results)}
</section>

<section>
    <div class="section-title">
        <div class="section-number">04</div>
        <h2>Indicators of Compromise</h2>
    </div>

    {_render_ioc_list("URLs", urls)}
    {_render_ioc_list("Domains", domains)}
    {_render_ioc_list("IP Addresses", ip_addresses)}
    {_render_ioc_list("Email Addresses", email_addresses)}

    {('<div class="empty">No IOCs were extracted.</div>'
      if not any([urls, domains, ip_addresses, email_addresses]) else '')}
</section>

<section>
    <div class="section-title">
        <div class="section-number">05</div>
        <h2>Attachment Analysis</h2>
    </div>

    {_render_attachments(attachment_results)}
</section>

<section>
    <div class="section-title">
        <div class="section-number">06</div>
        <h2>Threat Intelligence</h2>
    </div>

    <div class="subsection">
        <h3>VirusTotal</h3>
        {_render_threat_intelligence(virustotal_results, "VirusTotal")}
    </div>

    <div class="subsection">
        <h3>urlscan.io</h3>
        {_render_threat_intelligence(urlscan_results, "urlscan.io")}
    </div>
</section>

<section>
    <div class="section-title">
        <div class="section-number">07</div>
        <h2>Evidence Correlation</h2>
    </div>

    {_render_evidence(evidence_results)}
</section>

<section>
    <div class="section-title">
        <div class="section-number">08</div>
        <h2>Risk Assessment</h2>
    </div>

    {_render_risk(risk_results)}
</section>

<section>
    <div class="section-title">
        <div class="section-number">09</div>
        <h2>Analyst Notes</h2>
    </div>

    <div class="empty">
        This report contains automated investigation results.
        Final incident classification and response actions should be
        confirmed by a SOC analyst.
    </div>
</section>

<div class="footer">
    SOC Phishing Investigation Platform &bull;
    Automated Investigation Report
</div>

</div>
</body>
</html>
"""

    return html


def save_report(report):
    """Save the generated HTML report and return its path."""

    reports_dir = Path(__file__).resolve().parent.parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = reports_dir / f"phishing-investigation-{timestamp}.html"

    report_path.write_text(report, encoding="utf-8")

    return str(report_path)


if __name__ == "__main__":
    print("report_generator.py loaded successfully.")
    print("Output format: HTML")
