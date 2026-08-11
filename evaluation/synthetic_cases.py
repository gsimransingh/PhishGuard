"""Manifest entries for the generated synthetic .eml regression corpus."""

from pathlib import Path

from evaluation.generate_eml_corpus import SYNTHETIC_DEFINITIONS


def build_synthetic_cases() -> list[dict]:
    """Return labeled cases backed by actual generated .eml files."""
    cases = []
    for definition in SYNTHETIC_DEFINITIONS:
        cases.append({
            "id": definition["id"],
            "path": str(Path("samples") / "generated" / f"{definition['id']}.eml"),
            "category": definition["category"],
            "expected_disposition": definition["expected_disposition"],
            "auth_source": definition["auth_source"],
            "source_type": "synthetic_generated_eml",
        })
    return cases
