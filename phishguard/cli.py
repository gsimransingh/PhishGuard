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
import secrets
from datetime import datetime, timezone

from phishguard.email_parser import parse_eml # type: ignore
from phishguard.analyzer import analyze # type: ignore
from phishguard.url_analyzer import InvalidURLError, analyze_url # type: ignore
from phishguard.report_generator import generate_html_report, generate_cef_log # type: ignore
from phishguard import __version__
from phishguard.security import (
    EmailLimitError,
    MAX_BATCH_BYTES,
    MAX_BATCH_FILES,
    MAX_ENRICHED_BATCH_FILES,
)

_VERSION = __version__

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
_TAGLINES_PATH = os.path.join(_DATA_DIR, "taglines.txt")

_ANSI_RESET = "\033[0m"
_RISK_COLORS = {
    "LOW": "\033[32m",          # green
    "MEDIUM": "\033[38;5;220m", # soft gold
    "HIGH": "\033[38;5;208m",   # orange
    "CRITICAL": "\033[1;31m",   # bold red
}

# figlet "slant" font, generated offline and hardcoded — no pyfiglet
# dependency needed at runtime for one static string. Plain ASCII only
# (no Unicode box-drawing), so it renders correctly in plain cmd.exe and
# older locale settings, not just Windows Terminal/VS Code.
_ASCII_BANNER = r"""
    ____  __    _      __    ______                     __
   / __ \/ /_  (_)____/ /_  / ____/_  ______ __________/ /
  / /_/ / __ \/ / ___/ __ \/ / __/ / / / __ `/ ___/ __  / 
 / ____/ / / / (__  ) / / / /_/ / /_/ / /_/ / /  / /_/ /  
/_/   /_/ /_/_/____/_/ /_/\____/\__,_/\__,_/_/   \__,_/   
"""


def _load_tagline() -> str:
    """Pick a random tagline from data/taglines.txt. Falls back to a fixed
    line if the file is missing or empty, so a banner never crashes a run."""
    try:
        with open(_TAGLINES_PATH, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        if lines:
            return secrets.choice(lines)
    except FileNotFoundError:
        pass
    return "Phishing Email & URL Analysis for SOC Analysts"


def print_banner(): # type: ignore
    """
    Print the ASCII banner + version + a random tagline to STDERR — never
    stdout. This is the one rule that actually matters here: printing to
    stdout would corrupt piped JSON/CSV output for anyone scripting against
    this tool (e.g. `python main.py -f x.eml -o json | jq .`). Callers are
    also responsible for only calling this in text-output mode and skipping
    it entirely under --no-banner; this function itself doesn't check either
    condition, it just prints when called.
    """
    print(_ASCII_BANNER, file=sys.stderr) # type: ignore
    print(f"  Phishing Email & URL Analysis for SOC Analysts | v{_VERSION}", file=sys.stderr) # type: ignore
    print(f"  {_load_tagline()}", file=sys.stderr) # type: ignore
    print("", file=sys.stderr) # type: ignore


def _safe_terminal_text(value: object) -> str:
    """Render untrusted values without allowing terminal-control injection."""
    escaped: list[str] = []
    for character in str(value):
        if character == "\n":
            escaped.append("\\n")
        elif character == "\r":
            escaped.append("\\r")
        elif character == "\t":
            escaped.append("\\t")
        elif ord(character) < 32 or ord(character) == 127:
            escaped.append(f"\\x{ord(character):02x}")
        else:
            escaped.append(character)
    return "".join(escaped)


def _should_use_color(mode: str, stream: object) -> bool:
    """Enable ANSI color only for an explicitly requested or interactive terminal."""
    if mode == "never":
        return False
    if mode == "always":
        return True
    if os.environ.get("NO_COLOR") is not None:
        return False
    return bool(getattr(stream, "isatty", lambda: False)()) and os.environ.get("TERM") != "dumb"


def _colorize_risk(level: object, text: str, enabled: bool) -> str:
    """Apply the terminal color associated with a trusted risk-level value."""
    if not enabled:
        return text
    color = _RISK_COLORS.get(str(level).upper())
    return f"{color}{text}{_ANSI_RESET}" if color else text


# ---------------------------------------------------------------------------
# Output Formatters
# ---------------------------------------------------------------------------

def print_text_report(report: dict, out=sys.stdout, color: bool = False) -> str: # type: ignore
    """Print a human-readable summary of the report."""
    sep = "=" * 60
    lines = []
    lines.append(sep) # type: ignore
    lines.append(f"  PhishGuard v{_safe_terminal_text(report['version'])} - Analysis Report") # type: ignore
    lines.append(f"  File       : {_safe_terminal_text(report['file'])}") # type: ignore
    lines.append(f"  Analyzed   : {_safe_terminal_text(report['analyzed_at'])}") # type: ignore
    lines.append(sep) # type: ignore
    risk_line = f"  Risk Level : {_safe_terminal_text(report['risk_level'])} (score: {_safe_terminal_text(report['risk_score'])})" # type: ignore
    lines.append(_colorize_risk(report["risk_level"], risk_line, color)) # type: ignore
    lines.append(sep) # type: ignore
    lines.append("  Email Metadata:") # type: ignore
    for k, v in report["email_metadata"].items(): # type: ignore
        lines.append(f"    {k:<12}: {_safe_terminal_text(v)}") # type: ignore
    lines.append(sep) # type: ignore
    lines.append("  Auth Headers:") # type: ignore
    for k, v in report["auth_headers"].items(): # type: ignore
        status = v if v else "not present" # type: ignore
        lines.append(f"    {k.upper():<6}: {_safe_terminal_text(status[:80])}") # type: ignore
    lines.append(sep) # type: ignore
    lines.append("  DNS Validation:") # type: ignore
    for k, v in report["dns_validation"].items(): # type: ignore
        if v:
            lines.append(f"    {k.upper():<6}: {_safe_terminal_text(v.get('status', 'n/a'))} - {_safe_terminal_text(v.get('record', '')[:70])}") # type: ignore
    lines.append(sep) # type: ignore
    lines.append("  Flags:") # type: ignore
    if report["flags"]:
        for flag in report["flags"]: # type: ignore
            lines.append(f"    [!] {_safe_terminal_text(flag)}") # type: ignore
    else:
        lines.append("    [+] No flags raised.") # type: ignore
    lines.append(sep) # type: ignore
    lines.append("  IOCs:") # type: ignore
    lines.append(f"    URLs        : {len(report['iocs']['urls'])} found") # type: ignore
    for url in report["iocs"]["urls"]: # type: ignore
        lines.append(f"      - {_safe_terminal_text(url)}") # type: ignore
    lines.append(f"    IPs         : {_safe_terminal_text(report['iocs']['ips'])}") # type: ignore
    lines.append(f"    Attachments : {len(report['iocs']['attachments'])} found") # type: ignore
    for att in report["iocs"]["attachments"]: # type: ignore
        lines.append(f"      - {_safe_terminal_text(att['filename'])} ({_safe_terminal_text(att['content_type'])}, {_safe_terminal_text(att['size_bytes'])} bytes)") # type: ignore
    lines.append(sep) # type: ignore
    lines.append("  Threat Intel:") # type: ignore
    for r in report["threat_intel"]["ip_checks"]: # type: ignore
        if r.get("error"): # type: ignore
            lines.append(f"    IP {_safe_terminal_text(r.get('indicator', r.get('ip', '')))}: {_safe_terminal_text(r['error'])}") # pyright: ignore[reportUnknownMemberType]
        else:
            lines.append(f"    IP {_safe_terminal_text(r['ip'])}: AbuseScore={_safe_terminal_text(r['abuse_confidence_score'])} | Reports={_safe_terminal_text(r['total_reports'])} | ISP={_safe_terminal_text(r.get('isp', ''))} | Tor={_safe_terminal_text(r.get('is_tor', False))}") # pyright: ignore[reportUnknownMemberType]
    for r in report["threat_intel"]["url_checks"]: # pyright: ignore[reportUnknownVariableType]
        if r.get("error"): # pyright: ignore[reportUnknownMemberType]
            lines.append(f"    URL {_safe_terminal_text(r.get('indicator', r.get('url', '')))}: {_safe_terminal_text(r['error'])}") # type: ignore
        else:
            url_short = r.get('url', r.get('indicator', ''))[:55] # type: ignore
            lines.append(f"    URL {_safe_terminal_text(url_short)}: malicious={_safe_terminal_text(r.get('malicious', 0))} | suspicious={_safe_terminal_text(r.get('suspicious', 0))}") # type: ignore
    if not report["threat_intel"]["ip_checks"] and not report["threat_intel"]["url_checks"]:
        lines.append("    (no threat intel results)") # type: ignore
    lines.append(sep) # type: ignore

    display_output = "\n".join(lines) # type: ignore
    plain_output = _colorize_risk(report["risk_level"], risk_line, False) # type: ignore
    plain_lines = list(lines)
    plain_lines[5] = plain_output
    output = "\n".join(plain_lines) # type: ignore
    print(display_output, file=out)
    return output


def print_url_report(report: dict, out=sys.stdout, color: bool = False) -> str: # type: ignore
    """Print a human-readable summary of a standalone URL analysis."""
    sep = "=" * 60
    lines = []
    lines.append(sep) # type: ignore
    lines.append("  PhishGuard - URL Analysis Report") # type: ignore
    lines.append(f"  URL        : {_safe_terminal_text(report['url'])}") # type: ignore
    lines.append(f"  Hostname   : {_safe_terminal_text(report['hostname'])}") # type: ignore
    lines.append(sep) # type: ignore
    risk_line = f"  Risk Level : {_safe_terminal_text(report['risk_level'])} (score: {_safe_terminal_text(report['risk_score'])})" # type: ignore
    lines.append(_colorize_risk(report["risk_level"], risk_line, color)) # type: ignore
    lines.append(sep) # type: ignore
    lines.append("  Findings:") # type: ignore
    if report["findings"]: # type: ignore
        for f in report["findings"]: # type: ignore
            lines.append(f"    [!] {_safe_terminal_text(f['finding'])}") # type: ignore
            lines.append(f"        check={_safe_terminal_text(f['check'])} weight={_safe_terminal_text(f['weight'])} confidence={_safe_terminal_text(f['confidence'])}") # type: ignore
            lines.append(f"        note: {_safe_terminal_text(f['false_positive_note'])}") # type: ignore
    else:
        lines.append("    [+] No structural, brand, or age-based flags raised.") # type: ignore
    lines.append(sep) # type: ignore
    lines.append("  Domain Registration:") # type: ignore
    reg = report.get("domain_registration") # type: ignore
    if reg: # type: ignore
        lines.append(f"    status={_safe_terminal_text(reg['status'])} created={_safe_terminal_text(reg.get('created'))} expires={_safe_terminal_text(reg.get('expires'))}") # type: ignore
        lines.append(f"    age_days={_safe_terminal_text(reg.get('age_days'))} registration_period_days={_safe_terminal_text(reg.get('registration_period_days'))}") # type: ignore
        lines.append(f"    registrar={_safe_terminal_text(reg.get('registrar') or 'unknown')} (context only, not scored)") # type: ignore
        if reg.get("domain_status"): # type: ignore
            lines.append(f"    domain_status={_safe_terminal_text(reg['domain_status'])}") # type: ignore
        if reg.get("error"): # type: ignore
            lines.append(f"    note: {_safe_terminal_text(reg['error'])}") # type: ignore
    else:
        lines.append("    (skipped — offline mode or no hostname)") # type: ignore
    lines.append(sep) # type: ignore
    lines.append("  SSL/TLS Certificate:") # type: ignore
    tls = report.get("ssl_certificate") # type: ignore
    if tls: # type: ignore
        lines.append(f"    status={_safe_terminal_text(tls['status'])} issuer={_safe_terminal_text(tls.get('issuer') or 'unknown')}") # type: ignore
        if tls.get("not_before"): # type: ignore
            lines.append(f"    not_before={_safe_terminal_text(tls['not_before'])} days_since_issued={_safe_terminal_text(tls.get('days_since_issued'))}") # type: ignore
        if tls.get("error"): # type: ignore
            lines.append(f"    note: {_safe_terminal_text(tls['error'])}") # type: ignore
    else:
        lines.append("    (skipped — offline mode or no hostname)") # type: ignore
    lines.append(sep) # type: ignore

    display_output = "\n".join(lines) # type: ignore
    plain_lines = list(lines)
    plain_lines[5] = risk_line
    output = "\n".join(plain_lines) # type: ignore
    print(display_output, file=out)
    return output



def print_batch_summary(results: list[dict], out=sys.stdout, color: bool = False) -> str: # type: ignore
    """Print a summary table of batch analysis results."""
    sep = "=" * 70
    lines = []
    display_lines = []
    lines.append(sep) # type: ignore
    display_lines.append(sep) # type: ignore
    lines.append(f"  PhishGuard - Batch Analysis Summary") # type: ignore
    display_lines.append(f"  PhishGuard - Batch Analysis Summary") # type: ignore
    lines.append(f"  Analyzed   : {datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}") # type: ignore
    display_lines.append(lines[-1]) # type: ignore
    lines.append(f"  Total Files: {len(results)}") # type: ignore
    display_lines.append(lines[-1]) # type: ignore
    lines.append(sep) # type: ignore
    display_lines.append(sep) # type: ignore
    lines.append(f"  {'File':<35} {'Risk':<8} {'Score':<8} {'Flags'}") # type: ignore
    display_lines.append(lines[-1]) # type: ignore
    lines.append("-" * 70) # type: ignore
    display_lines.append("-" * 70) # type: ignore
    for r in results: # type: ignore
        if r.get("error"): # type: ignore
            row = f"  {_safe_terminal_text(r['file']):<35} {'ERROR':<8} {'N/A':<8} {_safe_terminal_text(r['error'])}" # type: ignore
            lines.append(row) # type: ignore
            display_lines.append(row) # type: ignore
        else:
            fname = _safe_terminal_text(r['file'][:33] + '..' if len(r['file']) > 35 else r['file']) # type: ignore
            risk_cell = f"{r['risk_level']:<8}" # type: ignore
            lines.append(f"  {fname:<35} {risk_cell} {str(r['risk_score']):<8} {len(r['flags'])} flag(s)") # type: ignore
            display_risk = _colorize_risk(r["risk_level"], risk_cell, color) # type: ignore
            display_lines.append(f"  {fname:<35} {display_risk} {str(r['risk_score']):<8} {len(r['flags'])} flag(s)") # type: ignore
    lines.append(sep) # type: ignore
    display_lines.append(sep) # type: ignore

    critical = sum(1 for r in results if r.get("risk_level") == "CRITICAL") # type: ignore
    high   = sum(1 for r in results if r.get("risk_level") == "HIGH") # type: ignore
    medium = sum(1 for r in results if r.get("risk_level") == "MEDIUM") # type: ignore
    low    = sum(1 for r in results if r.get("risk_level") == "LOW") # type: ignore
    errors = sum(1 for r in results if r.get("error")) # type: ignore
    lines.append(f"  CRITICAL: {critical}  |  HIGH: {high}  |  MEDIUM: {medium}  |  LOW: {low}  |  ERRORS: {errors}") # type: ignore
    display_lines.append(lines[-1]) # type: ignore
    lines.append(sep) # type: ignore
    display_lines.append(sep) # type: ignore

    output = "\n".join(lines) # type: ignore
    print("\n".join(display_lines), file=out) # type: ignore
    return output


# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------

def _safe_csv_cell(value: object) -> str:
    """Prevent spreadsheet software from interpreting untrusted cells as formulas."""
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def export_csv(results: list[dict], csv_path: str): # type: ignore
    """Export batch results to a CSV file."""
    fieldnames = ["file", "risk_level", "risk_score", "flags", "urls", "ips", "analyzed_at", "error"]
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results: # type: ignore
            if r.get("error"): # type: ignore
                row = {
                    "file": r["file"], "risk_level": "ERROR",
                    "risk_score": "", "flags": "", "urls": "",
                    "ips": "", "analyzed_at": "", "error": r["error"],
                }
            else:
                row = {
                    "file":        r["file"],
                    "risk_level":  r["risk_level"],
                    "risk_score":  r["risk_score"],
                    "flags":       " | ".join(r["flags"]), # type: ignore
                    "urls":        " | ".join(r["iocs"]["urls"]), # type: ignore
                    "ips":         " | ".join(r["iocs"]["ips"]), # type: ignore
                    "analyzed_at": r["analyzed_at"],
                    "error":       "",
                }
            writer.writerow({key: _safe_csv_cell(value) for key, value in row.items()})
    print(f"[*] CSV saved to: {csv_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Single File Analysis
# ---------------------------------------------------------------------------

def run_single(args: argparse.Namespace):
    """Handle single file analysis."""
    if not os.path.isfile(args.file):
        print(f"[ERROR] File not found: {_safe_terminal_text(args.file)}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing {_safe_terminal_text(args.file)} ...", file=sys.stderr)
    try:
        parsed = parse_eml(args.file) # type: ignore
        report = analyze(parsed, args.file, run_intel=args.enrich) # type: ignore
    except EmailLimitError as error:
        print(f"[ERROR] Input rejected: {error}", file=sys.stderr)
        sys.exit(2)

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
        content = print_text_report(report, color=_should_use_color(args.color, sys.stdout))

    if args.save_output:
        with open(args.save_output, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"[*] Output saved to: {args.save_output}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Standalone URL Analysis
# ---------------------------------------------------------------------------

def run_url(args: argparse.Namespace):
    """Handle standalone URL/domain analysis (no .eml file required)."""
    print(f"[*] Analyzing URL: {_safe_terminal_text(args.url)} ...", file=sys.stderr)
    try:
        report = analyze_url(args.url, run_intel=args.enrich) # type: ignore
    except InvalidURLError as error:
        print(f"[ERROR] Input rejected: {_safe_terminal_text(error)}", file=sys.stderr)
        sys.exit(2)

    if args.output == "json":
        content = json.dumps(report, indent=2)
        print(content)
    elif args.output in ("html", "cef"):
        print(f"[ERROR] Output format '{args.output}' is not yet supported for URL analysis (-u). Use text or json.", file=sys.stderr)
        sys.exit(1)
    else:
        content = print_url_report(report, color=_should_use_color(args.color, sys.stdout))

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
        print(f"[ERROR] Folder not found: {_safe_terminal_text(folder)}", file=sys.stderr)
        sys.exit(1)

    eml_files = sorted(f for f in os.listdir(folder) if f.lower().endswith('.eml')) # type: ignore
    if not eml_files:
        print(f"[ERROR] No .eml files found in: {_safe_terminal_text(folder)}", file=sys.stderr)
        sys.exit(1)
    if len(eml_files) > MAX_BATCH_FILES:
        print(f"[ERROR] Batch contains {len(eml_files)} files; the limit is {MAX_BATCH_FILES}.", file=sys.stderr)
        sys.exit(2)

    batch_bytes = sum(os.path.getsize(os.path.join(folder, filename)) for filename in eml_files)
    if batch_bytes > MAX_BATCH_BYTES:
        print(f"[ERROR] Batch is {batch_bytes} bytes; the limit is {MAX_BATCH_BYTES} bytes.", file=sys.stderr)
        sys.exit(2)
    if args.enrich and len(eml_files) > MAX_ENRICHED_BATCH_FILES:
        print(f"[ERROR] --enrich supports at most {MAX_ENRICHED_BATCH_FILES} files per batch.", file=sys.stderr)
        sys.exit(2)

    print(f"[*] Found {len(eml_files)} .eml file(s) in {_safe_terminal_text(folder)}", file=sys.stderr) # type: ignore

    results = []
    for filename in eml_files: # type: ignore
        file_path = os.path.join(folder, filename) # type: ignore
        print(f"[*] Analyzing {_safe_terminal_text(filename)} ...", file=sys.stderr)
        try:
            parsed = parse_eml(file_path) # type: ignore
            report = analyze(parsed, file_path, run_intel=args.enrich) # type: ignore
            results.append(report) # type: ignore

            # Print full report per file if verbose
            if args.verbose:
                print_text_report(report, color=_should_use_color(getattr(args, "color", "auto"), sys.stdout))

        except Exception as e:
            results.append({"file": filename, "error": str(e)}) # type: ignore

    # Always print summary
    summary = print_batch_summary(results, color=_should_use_color(getattr(args, "color", "auto"), sys.stdout))

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
  python main.py -f email.eml                          # Offline mode (default)
  python main.py -f email.eml --enrich                 # Allow external enrichment
  python main.py -F samples/                           # Batch folder
  python main.py -F samples/ -V                        # Batch with full details
  python main.py -F samples/ --csv results.csv          # Batch with CSV export
  python main.py -F samples/ -O summary.txt             # Save batch summary
  python main.py -u paypa1-verify.com                  # Standalone URL/domain analysis
  python main.py -u http://evil.ru/login -o json        # Offline URL analysis, JSON output
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

    # External enrichment is intentionally opt-in because it can send
    # potentially sensitive indicators to third parties.
    enrichment_group = parser.add_mutually_exclusive_group()
    enrichment_group.add_argument(
        "--enrich",
        action="store_true",
        help="Allow external DNS, reputation, RDAP, and TLS lookups"
    )
    enrichment_group.add_argument(
        "-n", "--no-intel",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    color_group = parser.add_mutually_exclusive_group()
    color_group.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Color text risk levels: auto (default), always, or never"
    )
    color_group.add_argument(
        "--no-color",
        dest="color",
        action="store_const",
        const="never",
        help="Disable terminal colors (same as --color never)"
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

    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress the startup banner (useful for cron/CI/scripted runs)")
    parser.add_argument("--version", action="version", version=f"PhishGuard {_VERSION}")

    args = parser.parse_args()

    # Banner only in human-readable text mode, and only to stderr — never
    # for json/html/cef, where it would corrupt piped/redirected output.
    if not args.no_banner and args.output == "text":
        print_banner()

    if args.url:
        run_url(args)
    elif args.folder:
        run_batch(args)
    else:
        run_single(args)


if __name__ == "__main__":
    main()
