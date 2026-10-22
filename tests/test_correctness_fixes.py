"""Regression tests for correctness bugs A1-A7 (code review 2026-10-22).

Each test was written to fail against the pre-fix code and pass after it.
"""

from phishguard.email_parser import _extract_urls


# --- A1: URLs keep trailing punctuation -------------------------------------

def test_a1_trailing_sentence_punctuation_is_not_part_of_url():
    text = "Log in (https://paypal.com/login). Or https://evil.example/x, today! See https://a.example/b;"
    assert _extract_urls(text) == [
        "https://paypal.com/login",
        "https://evil.example/x",
        "https://a.example/b",
    ]


def test_a1_balanced_parentheses_inside_url_are_kept():
    text = "Docs: https://en.wikipedia.org/wiki/Phishing_(security)."
    assert _extract_urls(text) == ["https://en.wikipedia.org/wiki/Phishing_(security)"]
