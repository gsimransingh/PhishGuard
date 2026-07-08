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
import csv
from datetime import datetime

from phishguard.email_parser import parse_eml # type: ignore
from phishguard.analyzer import analyze # type: ignore
from phishguard.url_analyzer import analyze_url # type: ignore
from phishguard.report_generator import generate_html_report, generate_cef_log # type: ignore


# ---------------------------------------------------------------------------
# Output Formatters
# ---------------------------------------------------------------------------

def print_text_report(report: dict, out=sys.stdout) -> str: # type: ignore
    """Print a human-readable summary of the report."""
    sep = "=" * 60
    lines = []
    lines.append(sep) # type: ignore
    lines.append(f"  PhishGuard v{report['version']} - Analysis Report") # type: ignore
    lines.append(f"  File       : {report['file']}") # type: ignore
    lines.append(f"  Analyzed   : {report['analyzed_at']}") # type: ignore
    lines.append(sep) # type: ignore
    lines.append(f"  Risk Level : {report['risk_level']} (score: {report['risk_score']})") # type: ignore
    lines.append(sep) # type: ignore
    lines.append("  Email Metadata:") # type: ignore
    for k, v in report["email_metadata"].items(): # type: ignore
        lines.append(f"    {k:<12}: {v}") # type: ignore
    lines.append(sep) # type: ignore
    lines.append("  Auth Headers:") # type: ignore
    for k, v in report["auth_headers"].items(): # type: ignore
        status = v if v else "not present" # type: ignore
        lines.append(f"    {k.upper():<6}: {status[:80]}") # type: ignore
    lines.append(sep) # type: ignore
    lines.append("  DNS Validation:") # type: ignore
    for k, v in report["dns_validation"].items(): # type: ignore
        if v:
            lines.append(f"    {k.upper():<6}: {v.get('status', 'n/a')} - {v.get('record', '')[:70]}") # type: ignore
    lines.append(sep) # type: ignore
    lines.append("  Flags:") # type: ignore
    if report["flags"]:
        for flag in report["flags"]: # type: ignore
            lines.append(f"    [!] {flag}") # type: ignore
    else:
        lines.append("    [+] No flags raised.") # type: ignore
    lines.append(sep) # type: ignore
    lines.append("  IOCs:") # type: ignore
    lines.append(f"    URLs        : {len(report['iocs']['urls'])} found") # type: ignore
    for url in report["iocs"]["urls"]: # type: ignore
        lines.append(f"      - {url}") # type: ignore
    lines.append(f"    IPs         : {report['iocs']['ips']}") # type: ignore
    lines.append(f"    Attachments : {len(report['iocs']['attachments'])} found") # type: ignore
    for att in report["iocs"]["attachments"]: # type: ignore
        lines.append(f"      - {att['filename']} ({att['content_type']}, {att['size_bytes']} bytes)") # type: ignore
    lines.append(sep) # type: ignore
    lines.append("  Threat Intel:") # type: ignore
    for r in report["threat_intel"]["ip_checks"]: # type: ignore
        if r.get("error"): # type: ignore
            lines.append(f"    IP {r.get('indicator', r.get('ip', ''))}: {r['error']}") # pyright: ignore[reportUnknownMemberType]
        else:
            lines.append(f"    IP {r['ip']}: AbuseScore={r['abuse_confidence_score']} | Reports={r['total_reports']} | ISP={r.get('isp', '')} | Tor={r.get('is_tor', False)}") # pyright: ignore[reportUnknownMemberType]
    for r in report["threat_intel"]["url_checks"]: # pyright: ignore[reportUnknownVariableType]
        if r.get("error"): # pyright: ignore[reportUnknownMemberType]
            lines.append(f"    URL {r.get('indicator', r.get('url', ''))}: {r['error']}") # type: ignore
        else:
            url_short = r.get('url', r.get('indicator', ''))[:55] # type: ignore
            lines.append(f"    URL {url_short}: malicious={r.get('malicious', 0)} | suspicious={r.get('suspicious', 0)}") # type: ignore
    if not report["threat_intel"]["ip_checks"] and not report["threat_intel"]["url_checks"]:
        lines.append("    (no threat intel results)") # type: ignore
    lines.append(sep) # type: ignore

    output = "\n".join(lines) # type: ignore
    print(output, file=out)
    return output


def print_url_report(report: dict, out=sys.stdout) -> str: # type: ignore
    """Print a human-readable summary of a standalone URL analysis."""
    sep = "=" * 60
    lines = []
    lines.append(sep) # type: ignore
    lines.append("  PhishGuard - URL Analysis Report") # type: ignore
    lines.append(f"  URL        : {report['url']}") # type: ignore
    lines.append(f"  Hostname   : {report['hostname']}") # type: ignore
    lines.append(sep) # type: ignore
    lines.append(f"  Risk Level : {report['risk_level']} (score: {report['risk_score']})") # type: ignore
    lines.append(sep) # type: ignore
    lines.append("  Findings:") # type: ignore
    if report["findings"]: # type: ignore
        for f in report["findings"]: # type: ignore
            lines.append(f"    [!] {f['finding']}") # type: ignore
            lines.append(f"        check={f['check']} weight={f['weight']} confidence={f['confidence']}") # type: ignore
            lines.append(f"        note: {f['false_positive_note']}") # type: ignore
    else:
        lines.append("    [+] No structural, brand, or age-based flags raised.") # type: ignore
    lines.append(sep) # type: ignore
    lines.append("  Domain Age:") # type: ignore
    age = report.get("domain_age") # type: ignore
    if age: # type: ignore
        lines.append(f"    status={age['status']} created={age.get('created')} age_days={age.get('age_days')}") # type: ignore
        if age.get("error"): # type: ignore
            lines.append(f"    note: {age['error']}") # type: ignore
    else:
        lines.append("    (skipped — offline mode or no hostname)") # type: ignore
    lines.append(sep) # type: ignore

    output = "\n".join(lines) # type: ignore
    print(output, file=out)
    return output



    """Print a summary table of batch analysis results."""
    sep = "=" * 70
    lines = []
    lines.append(sep) # type: ignore
    lines.append(f"  PhishGuard - Batch Analysis Summary") # type: ignore
    lines.append(f"  Analyzed   : {datetime.utcnow().isoformat()}Z") # type: ignore
    lines.append(f"  Total Files: {len(results)}") # type: ignore
    lines.append(sep) # type: ignore
    lines.append(f"  {'File':<35} {'Risk':<8} {'Score':<8} {'Flags'}") # type: ignore
    lines.append("-" * 70) # type: ignore
    for r in results: # type: ignore
        if r.get("error"): # type: ignore
            lines.append(f"  {r['file']:<35} {'ERROR':<8} {'N/A':<8} {r['error']}") # type: ignore
        else:
            fname = r['file'][:33] + '..' if len(r['file']) > 35 else r['file'] # type: ignore
            lines.append(f"  {fname:<35} {r['risk_level']:<8} {str(r['risk_score']):<8} {len(r['flags'])} flag(s)") # type: ignore
    lines.append(sep) # type: ignore

    high   = sum(1 for r in results if r.get("risk_level") == "HIGH") # type: ignore
    medium = sum(1 for r in results if r.get("risk_level") == "MEDIUM") # type: ignore
    low    = sum(1 for r in results if r.get("risk_level") == "LOW") # type: ignore
    errors = sum(1 for r in results if r.get("error")) # type: ignore
    lines.append(f"  HIGH: {high}  |  MEDIUM: {medium}  |  LOW: {low}  |  ERRORS: {errors}") # type: ignore
    lines.append(sep) # type: ignore

    output = "\n".join(lines) # type: ignore
    print(output, file=out)
    return output


# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------

def export_csv(results: list[dict], csv_path: str): # type: ignore
    """Export batch results to a CSV file."""
    fieldnames = ["file", "risk_level", "risk_score", "flags", "urls", "ips", "analyzed_at", "error"]
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results: # type: ignore
            if r.get("error"): # type: ignore
                writer.writerow({
                    "file": r["file"], "risk_level": "ERROR",
                    "risk_score": "", "flags": "", "urls": "",
                    "ips": "", "analyzed_at": "", "error": r["error"],
                })
            else:
                writer.writerow({
                    "file":        r["file"],
                    "risk_level":  r["risk_level"],
                    "risk_score":  r["risk_score"],
                    "flags":       " | ".join(r["flags"]), # type: ignore
                    "urls":        " | ".join(r["iocs"]["urls"]), # type: ignore
                    "ips":         " | ".join(r["iocs"]["ips"]), # type: ignore
                    "analyzed_at": r["analyzed_at"],
                    "error":       "",
                })
    print(f"[*] CSV saved to: {csv_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Single File Analysis
# ---------------------------------------------------------------------------

def run_single(args: argparse.Namespace):
    """Handle single file analysis."""
    if not os.path.isfile(args.file):
        print(f"[ERROR] File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing {args.file} ...", file=sys.stderr)
    parsed = parse_eml(args.file) # type: ignore
    report = analyze(parsed, args.file, run_intel=not args.no_intel) # type: ignore

    if args.output == "json":
        content = json.dumps(report, indent=2)
        print(content)
    elif args.output == "html":
        content = generate_html_report(report)
        print(content)
    elif args.output == "cef":
        content = generate_cef_log(report)
        print(content)
    else:
        content = print_text_report(report)

    if args.save_output:
        with open(args.save_output, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"[*] Output saved to: {args.save_output}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Standalone URL Analysis
# ---------------------------------------------------------------------------

def run_url(args: argparse.Namespace):
    """Handle standalone URL/domain analysis (no .eml file required)."""
    print(f"[*] Analyzing URL: {args.url} ...", file=sys.stderr)
    report = analyze_url(args.url, run_intel=not args.no_intel) # type: ignore

    if args.output == "json":
        content = json.dumps(report, indent=2)
        print(content)
    elif args.output in ("html", "cef"):
        print(f"[ERROR] Output format '{args.output}' is not yet supported for URL analysis (-u). Use text or json.", file=sys.stderr)
        sys.exit(1)
    else:
        content = print_url_report(report)

    if args.save_output:
        with open(args.save_output, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"[*] Output saved to: {args.save_output}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Batch Folder Analysis
# ---------------------------------------------------------------------------

def run_batch(args: argparse.Namespace):
    """Handle batch folder analysis."""
    folder = args.folder
    if not os.path.isdir(folder):
        print(f"[ERROR] Folder not found: {folder}", file=sys.stderr)
        sys.exit(1)

    eml_files = [f for f in os.listdir(folder) if f.lower().endswith('.eml')] # type: ignore
    if not eml_files:
        print(f"[ERROR] No .eml files found in: {folder}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Found {len(eml_files)} .eml file(s) in {folder}", file=sys.stderr) # type: ignore

    results = []
    for filename in sorted(eml_files): # type: ignore
        file_path = os.path.join(folder, filename) # type: ignore
        print(f"[*] Analyzing {filename} ...", file=sys.stderr)
        try:
            parsed = parse_eml(file_path) # type: ignore
            report = analyze(parsed, file_path, run_intel=not args.no_intel) # type: ignore
            results.append(report) # type: ignore

            # Print full report per file if verbose
            if args.verbose:
                print_text_report(report)

        except Exception as e:
            results.append({"file": filename, "error": str(e)}) # type: ignore

    # Always print summary
    summary = print_batch_summary(results)

    # Save summary to disk if -O specified
    if args.save_output:
        with open(args.save_output, 'w', encoding='utf-8') as f:
            f.write(summary)
        print(f"[*] Summary saved to: {args.save_output}", file=sys.stderr)

    # Export CSV if --csv specified
    if args.csv:
        export_csv(results, args.csv)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard - Phishing Email Analyzer for SOC Analysts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -f email.eml                          # Single file, text output
  python main.py -f email.eml -o json                  # JSON output
  python main.py -f email.eml -o html -O report.html   # Save HTML report
  python main.py -f email.eml -n                       # Offline mode
  python main.py -F samples/                           # Batch folder
  python main.py -F samples/ -n -V                     # Batch with full details
  python main.py -F samples/ -n --csv results.csv      # Batch with CSV export
  python main.py -F samples/ -n -O summary.txt         # Save batch summary
  python main.py -u paypa1-verify.com                  # Standalone URL/domain analysis
  python main.py -u http://evil.ru/login -n -o json    # Offline URL analysis, JSON output
        """
    )

    # Input — mutually exclusive: single file, folder, or standalone URL
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-f", "--file",   help="Path to a single .eml file to analyze")
    input_group.add_argument("-F", "--folder", help="Path to a folder of .eml files for batch analysis")
    input_group.add_argument("-u", "--url",    help="A single URL or bare domain to analyze (no .eml file needed)")

    # Output format (single file mode)
    parser.add_argument(
        "-o", "--output",
        choices=["text", "json", "html", "cef"],
        default="text",
        help="Output format: text (default), json, html, cef"
    )

    # Save output to disk
    parser.add_argument(
        "-O", "--save-output",
        metavar="PATH",
        default=None,
        help="Save output to disk (single: saves report, batch: saves summary)"
    )

    # Threat intel
    parser.add_argument(
        "-n", "--no-intel",
        action="store_true",
        help="Skip AbuseIPDB / VirusTotal lookups (offline mode)"
    )

    # Verbose (batch mode)
    parser.add_argument(
        "-V", "--verbose",
        action="store_true",
        help="(Batch mode) Print full report for each file, not just summary"
    )

    # CSV export (batch mode)
    parser.add_argument(
        "--csv",
        metavar="PATH",
        default=None,
        help="(Batch mode) Export results to a CSV file"
    )

    parser.add_argument("--version", action="version", version="PhishGuard 0.2.0")

    args = parser.parse_args()

    if args.url:
        run_url(args)
    elif args.folder:
        run_batch(args)
    else:
        run_single(args)


if __name__ == "__main__":
    main()