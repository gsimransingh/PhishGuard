#!/usr/bin/env python3
"""
PhishGuard - Phishing Email Analyzer
Entry point. All logic lives in the phishguard/ package.

Usage:
  python main.py -f <path_to_email.eml> [-o json|text|html|cef] [--no-intel]
"""

from phishguard.cli import main

if __name__ == "__main__":
    main()