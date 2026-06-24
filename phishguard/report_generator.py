from datetime import datetime
import json

# ---------------------------------------------------------------------------
# Report Generator - HTML & CEF Export Formats
# Generates HTML reports for human review and CEF logs for SIEM ingestion.
# ---------------------------------------------------------------------------


def generate_html_report(report: dict, output_path: str = None) -> str:
    """
    Generate a styled HTML report from the analysis dict.
    If output_path is provided, writes to file. Otherwise returns HTML string.
    """
    risk_colors = {"HIGH": "#d32f2f", "MEDIUM": "#f57c00", "LOW": "#388e3c"}
    risk_color = risk_colors.get(report["risk_level"], "#757575")

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishGuard Report - {report['file']}</title>
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
        .flag::before {{ content: "⚠ "; color: #f57c00; font-weight: bold; }}
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
            <div class="version">v{report['version']} | {report['analyzed_at']}</div>
        </div>
        
        <div class="risk-banner">
            Risk Level: {report['risk_level']} (Score: {report['risk_score']})
        </div>
        
        <div class="section">
            <h2>Email Metadata</h2>
            <div class="meta-grid">
                <div class="meta-label">File:</div><div class="meta-value">{report['file']}</div>
                <div class="meta-label">Subject:</div><div class="meta-value">{report['email_metadata']['subject']}</div>
                <div class="meta-label">From:</div><div class="meta-value">{report['email_metadata']['from']}</div>
                <div class="meta-label">Reply-To:</div><div class="meta-value">{report['email_metadata'].get('reply_to', 'N/A')}</div>
                <div class="meta-label">To:</div><div class="meta-value">{report['email_metadata']['to']}</div>
                <div class="meta-label">Date:</div><div class="meta-value">{report['email_metadata']['date']}</div>
                <div class="meta-label">Message-ID:</div><div class="meta-value">{report['email_metadata']['message_id']}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Authentication Headers</h2>
            <div class="meta-grid">
                <div class="meta-label">SPF:</div><div class="meta-value">{report['auth_headers']['spf'] or 'Not present'}</div>
                <div class="meta-label">DKIM:</div><div class="meta-value">{report['auth_headers']['dkim']}</div>
                <div class="meta-label">DMARC:</div><div class="meta-value">{report['auth_headers']['dmarc'] or 'Not present'}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Flags Raised</h2>
            {''.join([f'<div class="flag">{flag}</div>' for flag in report['flags']]) if report['flags'] else '<p class="no-data">No flags raised.</p>'}
        </div>
        
        <div class="section">
            <h2>Indicators of Compromise (IOCs)</h2>
            <h3 style="margin-top:15px;">URLs ({len(report['iocs']['urls'])})</h3>
            {'<ul class="ioc-list">' + ''.join([f'<li>{url}</li>' for url in report['iocs']['urls']]) + '</ul>' if report['iocs']['urls'] else '<p class="no-data">No URLs found.</p>'}
            
            <h3 style="margin-top:15px;">IP Addresses ({len(report['iocs']['ips'])})</h3>
            {'<ul class="ioc-list">' + ''.join([f'<li>{ip}</li>' for ip in report['iocs']['ips']]) + '</ul>' if report['iocs']['ips'] else '<p class="no-data">No IPs found.</p>'}
            
            <h3 style="margin-top:15px;">Attachments ({len(report['iocs']['attachments'])})</h3>
            {'<ul class="ioc-list">' + ''.join([f'<li>{a["filename"]} ({a["content_type"]}, {a["size_bytes"]} bytes)</li>' for a in report['iocs']['attachments']]) + '</ul>' if report['iocs']['attachments'] else '<p class="no-data">No attachments.</p>'}
        </div>
        
        <div class="section">
            <h2>Threat Intelligence</h2>
            {''.join([f'<div class="threat-intel-item"><strong>IP {r["ip"]}:</strong> AbuseScore={r["abuse_confidence_score"]} | Reports={r["total_reports"]} | ISP={r.get("isp", "N/A")} | Tor={r.get("is_tor", False)}</div>' for r in report.get('threat_intel', {}).get('ip_checks', []) if not r.get('error')]) if report.get('threat_intel', {}).get('ip_checks') else ''}
            {''.join([f'<div class="threat-intel-item"><strong>URL:</strong> {r.get("url", r.get("indicator", ""))} | Malicious={r.get("malicious", 0)} | Suspicious={r.get("suspicious", 0)}</div>' for r in report.get('threat_intel', {}).get('url_checks', []) if not r.get('error')]) if report.get('threat_intel', {}).get('url_checks') else ''}
            {'<p class="no-data">No threat intelligence results.</p>' if not report.get('threat_intel', {}).get('ip_checks') and not report.get('threat_intel', {}).get('url_checks') else ''}
        </div>
        
        <div class="footer">
            Generated by PhishGuard v{report['version']} | Built for SOC Analysts
        </div>
    </div>
</body>
</html>
    """

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
    severity_map = {"LOW": 3, "MEDIUM": 6, "HIGH": 9}
    severity = severity_map.get(report["risk_level"], 5)
    
    # Escape pipe characters in fields
    def escape_cef(s):
        return str(s).replace('|', '\\|').replace('\\', '\\\\')
    
    subject = escape_cef(report['email_metadata']['subject'][:100])
    sender = escape_cef(report['email_metadata']['from'])
    
    # Build extension fields
    extensions = []
    extensions.append(f"src={report['email_metadata']['from']}")
    extensions.append(f"suser={sender}")
    extensions.append(f"msg={subject}")
    extensions.append(f"cs1Label=RiskScore cs1={report['risk_score']}")
    extensions.append(f"cs2Label=Flags cs2={'; '.join(report['flags'][:3]) if report['flags'] else 'None'}")
    extensions.append(f"cnt={len(report['flags'])}")
    
    if report['iocs']['urls']:
        extensions.append(f"request={report['iocs']['urls'][0]}")
    if report['iocs']['ips']:
        extensions.append(f"dst={report['iocs']['ips'][0]}")
    
    extension_str = ' '.join(extensions)
    
    cef_log = f"CEF:0|PhishGuard|EmailAnalyzer|{report['version']}|PHISH_ANALYSIS|Phishing Email Analyzed|{severity}|{extension_str}"
    
    return cef_log
