from html import escape

# ---------------------------------------------------------------------------
# Report Generator - HTML & CEF Export Formats
# Generates HTML reports for human review and CEF logs for SIEM ingestion.
# ---------------------------------------------------------------------------


def generate_html_report(report: dict, output_path: str = None) -> str:
    """
    Generate a styled HTML report from the analysis dict.
    If output_path is provided, writes to file. Otherwise returns HTML string.
    """
    risk_colors = {"CRITICAL": "#b71c1c", "HIGH": "#e65100", "MEDIUM": "#b8860b", "LOW": "#388e3c"}
    risk_color = risk_colors.get(report["risk_level"], "#757575")

    def html_escape(value: object) -> str:
        return escape(str(value), quote=True)

    def render_list(values: list[object]) -> str:
        return '<ul class="ioc-list">' + ''.join(
            f"<li>{html_escape(value)}</li>" for value in values
        ) + "</ul>"

    metadata = report["email_metadata"]
    iocs = report["iocs"]
    flags_html = ''.join(
        f'<div class="flag">{html_escape(flag)}</div>' for flag in report["flags"]
    ) or '<p class="no-data">No flags raised.</p>'
    findings_html = ''.join(
        '<div class="finding">'
        f'<strong>{html_escape(finding.get("message", ""))}</strong>'
        f'<div>Confidence: {html_escape(finding.get("confidence", "unknown"))} | '
        f'Weight: {html_escape(finding.get("weight", 0))} | '
        f'Score contribution: {html_escape(finding.get("score_contribution", finding.get("weight", 0)))} | '
        f'Evidence count: {html_escape(finding.get("evidence_count", 1))}</div>'
        f'<div><strong>Next:</strong> {html_escape(finding.get("recommended_action", ""))}</div>'
        f'<div><strong>Caveat:</strong> {html_escape(finding.get("false_positive_note", ""))}</div>'
        '</div>'
        for finding in report.get("findings", [])
    ) or '<p class="no-data">No detailed findings.</p>'
    urls_html = render_list(iocs["urls"]) if iocs["urls"] else '<p class="no-data">No URLs found.</p>'
    ips_html = render_list(iocs["ips"]) if iocs["ips"] else '<p class="no-data">No IPs found.</p>'
    attachments_html = ''.join(
        "<li>{name} ({content_type}, {size} bytes)</li>".format(
            name=html_escape(attachment.get("filename", "")),
            content_type=html_escape(attachment.get("content_type", "")),
            size=html_escape(attachment.get("size_bytes", 0)),
        )
        for attachment in iocs["attachments"]
    )
    if attachments_html:
        attachments_html = f'<ul class="ioc-list">{attachments_html}</ul>'
    else:
        attachments_html = '<p class="no-data">No attachments.</p>'

    threat_intel = report.get("threat_intel", {})
    ip_checks_html = ''.join(
        '<div class="threat-intel-item"><strong>IP {ip}:</strong> '
        'AbuseScore={score} | Reports={reports} | ISP={isp} | Tor={tor}</div>'.format(
            ip=html_escape(result.get("ip", result.get("indicator", ""))),
            score=html_escape(result.get("abuse_confidence_score", 0)),
            reports=html_escape(result.get("total_reports", 0)),
            isp=html_escape(result.get("isp", "N/A")),
            tor=html_escape(result.get("is_tor", False)),
        )
        for result in threat_intel.get("ip_checks", []) if not result.get("error")
    )
    url_checks_html = ''.join(
        '<div class="threat-intel-item"><strong>URL:</strong> {url} | '
        'Malicious={malicious} | Suspicious={suspicious}</div>'.format(
            url=html_escape(result.get("url", result.get("indicator", ""))),
            malicious=html_escape(result.get("malicious", 0)),
            suspicious=html_escape(result.get("suspicious", 0)),
        )
        for result in threat_intel.get("url_checks", []) if not result.get("error")
    )
    threat_intel_html = ip_checks_html + url_checks_html or '<p class="no-data">No threat intelligence results.</p>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishGuard Report - {html_escape(report['file'])}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{ margin-bottom: 10px; }}
        .header .version {{ opacity: 0.9; font-size: 14px; }}
        .risk-banner {{
            background: {risk_color};
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 24px;
            font-weight: bold;
        }}
        .section {{
            padding: 25px 30px;
            border-bottom: 1px solid #e0e0e0;
        }}
        .section:last-child {{ border-bottom: none; }}
        .section h2 {{
            color: #333;
            margin-bottom: 15px;
            font-size: 20px;
            border-left: 4px solid #667eea;
            padding-left: 12px;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 10px;
            font-size: 14px;
        }}
        .meta-label {{ font-weight: 600; color: #666; }}
        .meta-value {{ color: #333; word-break: break-all; }}
        .flag {{
            background: #fff3cd;
            border-left: 4px solid #f57c00;
            padding: 12px;
            margin: 8px 0;
            font-size: 14px;
            color: #333;
        }}
        .flag::before {{ content: "Warning: "; color: #f57c00; font-weight: bold; }}
        .finding {{
            background: #fff8e1;
            border-left: 4px solid #f9a825;
            padding: 12px;
            margin: 8px 0;
            font-size: 14px;
        }}
        .ioc-list {{ list-style: none; padding-left: 0; }}
        .ioc-list li {{
            background: #f5f5f5;
            padding: 8px 12px;
            margin: 5px 0;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            word-break: break-all;
        }}
        .threat-intel-item {{
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 12px;
            margin: 8px 0;
            font-size: 14px;
        }}
        .no-data {{ color: #999; font-style: italic; }}
        .footer {{
            background: #fafafa;
            padding: 15px 30px;
            text-align: center;
            font-size: 12px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PhishGuard Analysis Report</h1>
            <div class="version">v{html_escape(report['version'])} | {html_escape(report['analyzed_at'])}</div>
        </div>

        <div class="risk-banner">
            Risk Level: {html_escape(report['risk_level'])} (Score: {html_escape(report['risk_score'])})
        </div>

        <div class="section">
            <h2>Email Metadata</h2>
            <div class="meta-grid">
                <div class="meta-label">File:</div><div class="meta-value">{html_escape(report['file'])}</div>
                <div class="meta-label">Subject:</div><div class="meta-value">{html_escape(metadata['subject'])}</div>
                <div class="meta-label">From:</div><div class="meta-value">{html_escape(metadata['from'])}</div>
                <div class="meta-label">Reply-To:</div><div class="meta-value">{html_escape(metadata.get('reply_to', 'N/A'))}</div>
                <div class="meta-label">To:</div><div class="meta-value">{html_escape(metadata['to'])}</div>
                <div class="meta-label">Date:</div><div class="meta-value">{html_escape(metadata['date'])}</div>
                <div class="meta-label">Message-ID:</div><div class="meta-value">{html_escape(metadata['message_id'])}</div>
            </div>
        </div>

        <div class="section">
            <h2>Authentication Headers</h2>
            <div class="meta-grid">
                <div class="meta-label">SPF:</div><div class="meta-value">{html_escape(report['auth_headers']['spf'] or 'Not present')}</div>
                <div class="meta-label">DKIM:</div><div class="meta-value">{html_escape(report['auth_headers']['dkim'])}</div>
                <div class="meta-label">DMARC:</div><div class="meta-value">{html_escape(report['auth_headers']['dmarc'] or 'Not present')}</div>
            </div>
        </div>

        <div class="section">
            <h2>Flags Raised</h2>
            {flags_html}
        </div>

        <div class="section">
            <h2>Finding Details</h2>
            {findings_html}
        </div>

        <div class="section">
            <h2>Indicators of Compromise (IOCs)</h2>
            <h3 style="margin-top:15px;">URLs ({len(iocs['urls'])})</h3>
            {urls_html}

            <h3 style="margin-top:15px;">IP Addresses ({len(iocs['ips'])})</h3>
            {ips_html}

            <h3 style="margin-top:15px;">Attachments ({len(iocs['attachments'])})</h3>
            {attachments_html}
        </div>

        <div class="section">
            <h2>Threat Intelligence</h2>
            {threat_intel_html}
        </div>

        <div class="footer">
            Generated by PhishGuard v{html_escape(report['version'])} | Built for SOC Analysts
        </div>
    </div>
</body>
</html>"""

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        return output_path

    return html


def generate_cef_log(report: dict) -> str:
    """
    Generate a CEF (Common Event Format) log entry for SIEM ingestion.

    CEF Format:
    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

    Severity mapping: LOW=3, MEDIUM=6, HIGH=9
    """
    severity_map = {"CRITICAL": 10, "HIGH": 9, "MEDIUM": 6, "LOW": 3}
    severity = severity_map.get(report["risk_level"], 5)

    def escape_cef(value: object) -> str:
        return (
            str(value)
            .replace('\\', '\\\\')
            .replace('|', '\\|')
            .replace('=', '\\=')
            .replace('\r', ' ')
            .replace('\n', ' ')
        )

    subject = escape_cef(report['email_metadata']['subject'][:100])
    sender = escape_cef(report['email_metadata']['from'])

    extensions = []
    extensions.append(f"src={sender}")
    extensions.append(f"suser={sender}")
    extensions.append(f"msg={subject}")
    extensions.append(f"cs1Label=RiskScore cs1={report['risk_score']}")
    extensions.append(f"cs2Label=Flags cs2={escape_cef('; '.join(report['flags'][:3]) if report['flags'] else 'None')}")
    extensions.append(f"cnt={len(report['flags'])}")

    if report['iocs']['urls']:
        extensions.append(f"request={escape_cef(report['iocs']['urls'][0])}")
    if report['iocs']['ips']:
        extensions.append(f"dst={escape_cef(report['iocs']['ips'][0])}")

    extension_str = ' '.join(extensions)

    return f"CEF:0|PhishGuard|EmailAnalyzer|{report['version']}|PHISH_ANALYSIS|Phishing Email Analyzed|{severity}|{extension_str}"
