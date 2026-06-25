#!/usr/bin/env python3
"""
PhishGuard CLI
Handles argument parsing and output formatting only.
All analysis logic lives in phishguard/analyzer.py.
"""

import argparse
import json
import sys
import os

from phishguard.email_parser import parse_eml
from phishguard.analyzer import analyze
from phishguard.report_generator import generate_html_report, generate_cef_log


def print_text_report(report: dict):
    """Print a human-readable summary of the report."""
    sep = "=" * 60
    print(sep)
    print(f"  PhishGuard v{report['version']} - Analysis Report")
    print(f"  File       : {report['file']}")
    print(f"  Analyzed   : {report['analyzed_at']}")
    print(sep)
    print(f"  Risk Level : {report['risk_level']} (score: {report['risk_score']})")
    print(sep)
    print("  Email Metadata:")
    for k, v in report["email_metadata"].items():
        print(f"    {k:<12}: {v}")
    print(sep)
    print("  Auth Headers:")
    for k, v in report["auth_headers"].items():
        status = v if v else "not present"
        print(f"    {k.upper():<6}: {status[:80]}")
    print(sep)
    print("  DNS Validation:")
    for k, v in report["dns_validation"].items():
        if v:
            print(f"    {k.upper():<6}: {v.get('status', 'n/a')} - {v.get('record', '')[:70]}")
    print(sep)
    print("  Flags:")
    if report["flags"]:
        for flag in report["flags"]:
            print(f"    [!] {flag}")
    else:
        print("    [+] No flags raised.")
    print(sep)
    print("  IOCs:")
    print(f"    URLs        : {len(report['iocs']['urls'])} found")
    for url in report["iocs"]["urls"]:
        print(f"      - {url}")
    print(f"    IPs         : {report['iocs']['ips']}")
    print(f"    Attachments : {len(report['iocs']['attachments'])} found")
    for att in report["iocs"]["attachments"]:
        print(f"      - {att['filename']} ({att['content_type']}, {att['size_bytes']} bytes)")
    print(sep)
    print("  Threat Intel:")
    for r in report["threat_intel"]["ip_checks"]:
        if r.get("error"):
            print(f"    IP {r.get('indicator', r.get('ip', ''))}: {r['error']}")
        else:
            print(f"    IP {r['ip']}: AbuseScore={r['abuse_confidence_score']} | Reports={r['total_reports']} | ISP={r.get('isp', '')} | Tor={r.get('is_tor', False)}")
    for r in report["threat_intel"]["url_checks"]:
        if r.get("error"):
            print(f"    URL {r.get('indicator', r.get('url', ''))}: {r['error']}")
        else:
            url_short = r.get('url', r.get('indicator', ''))[:55]
            print(f"    URL {url_short}: malicious={r.get('malicious', 0)} | suspicious={r.get('suspicious', 0)}")
    if not report["threat_intel"]["ip_checks"] and not report["threat_intel"]["url_checks"]:
        print("    (no threat intel results)")
    print(sep)


def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard - Phishing Email Analyzer for SOC Analysts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -f email.eml                  # Basic analysis
  python main.py -f email.eml -o json          # JSON output
  python main.py -f email.eml -o html          # HTML report
  python main.py -f email.eml --no-intel       # Offline mode
  python main.py -f email.eml -o json | jq .  # Parse with jq
        """
    )
    parser.add_argument("-f", "--file", required=True, help="Path to the .eml file to analyze")
    parser.add_argument(
        "-o", "--output",
        choices=["json", "text", "html", "cef"],
        default="text",
        help="Output format: text (default), json, html, or cef"
    )
    parser.add_argument("--no-intel", action="store_true",
                        help="Skip AbuseIPDB / VirusTotal lookups (offline mode)")
    parser.add_argument("--html-out", default=None,
                        help="When using -o html, path to save the HTML file (default: print to stdout)")
    parser.add_argument("-v", "--version", action="version", version="PhishGuard 0.2.0")

    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[ERROR] File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing {args.file} ...", file=sys.stderr)
    parsed = parse_eml(args.file)
    report = analyze(parsed, args.file, run_intel=not args.no_intel)

    if args.output == "json":
        print(json.dumps(report, indent=2))
    elif args.output == "html":
        html = generate_html_report(report, output_path=args.html_out)
        if not args.html_out:
            print(html)
        else:
            print(f"[*] HTML report saved to: {args.html_out}", file=sys.stderr)
    elif args.output == "cef":
        print(generate_cef_log(report))
    else:
        print_text_report(report)


if __name__ == "__main__":
    main()