#!/usr/bin/env python3
"""
PhishGuard - Phishing Email Analyzer
Usage: python main.py -f <path_to_email.eml> [-o json|text] [--no-intel]
"""

import argparse
import json
import sys
import os

from phishguard.email_parser import parse_eml
from phishguard.cli import build_report, print_text_report


def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard - Phishing Email Analyzer for SOC Analysts"
    )
    parser.add_argument("-f", "--file", required=True, help="Path to the .eml file to analyze")
    parser.add_argument("-o", "--output", choices=["json", "text"], default="text",
                        help="Output format: json or text (default: text)")
    parser.add_argument("--no-intel", action="store_true",
                        help="Skip AbuseIPDB / VirusTotal lookups (offline mode)")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[ERROR] File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsing {args.file} ...", file=sys.stderr)
    parsed = parse_eml(args.file)
    report = build_report(parsed, args.file, run_intel=not args.no_intel)

    if args.output == "json":
        print(json.dumps(report, indent=2))
    else:
        print_text_report(report)


if __name__ == "__main__":
    main()
