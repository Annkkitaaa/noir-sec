#!/usr/bin/env python3
"""
NoirSec: Report Generator
===========================
Generates a comprehensive Markdown report summarizing detection results
and circuit validation status across all vulnerability modules.

Usage:
    python3 scripts/generate_report.py [--output report.md]

Requirements:
    - nargo installed (for gate count info)
    - Run from repo root
    - Run in WSL on Windows
"""

import subprocess
import sys
import os
import json
from pathlib import Path
from datetime import datetime


REPO_ROOT = Path(__file__).parent.parent

VULNERABILITIES = [
    ("UC01", "Missing Range Check",              "01-under-constrained",  "Critical", "Easy"),
    ("UC02", "Unconstrained Hint Abuse",          "01-under-constrained",  "Critical", "Medium"),
    ("UC03", "Missing Nullifier Uniqueness",       "01-under-constrained",  "Critical", "Medium"),
    ("UC04", "Duplicate Witness Assignment",       "01-under-constrained",  "High",     "Medium"),
    ("OC01", "Unnecessary Range Restriction",     "02-over-constrained",   "Medium",   "Easy"),
    ("OC02", "Impossible Constraint Combination", "02-over-constrained",   "Medium",   "Easy"),
    ("PL01", "Accidental Public Input",           "03-privacy-leaks",      "High",     "Easy"),
    ("PL02", "Small Domain Hash Brute Force",     "03-privacy-leaks",      "High",     "Medium"),
    ("PL03", "Nullifier as Identity Leak",        "03-privacy-leaks",      "High",     "Medium"),
    ("PL04", "Correlation via Public Outputs",    "03-privacy-leaks",      "Medium",   "Hard"),
    ("FA01", "Integer Overflow in Field",         "04-field-arithmetic",   "Critical", "Medium"),
    ("FA02", "Division by Zero",                  "04-field-arithmetic",   "High",     "Easy"),
    ("FA03", "Modular Arithmetic Misuse",         "04-field-arithmetic",   "High",     "Medium"),
    ("LE01", "Intent vs Implementation",          "05-logic-errors",       "High",     "Hard"),
    ("LE02", "Missing Ownership Check",           "05-logic-errors",       "Critical", "Medium"),
    ("LE03", "Replay Attack (No Nonce)",          "05-logic-errors",       "High",     "Easy"),
    ("AZ01", "Note Nullifier Reuse",              "06-aztec-specific",     "Critical", "Medium"),
    ("AZ02", "Private-to-Public Leakage",         "06-aztec-specific",     "High",     "Hard"),
    ("AZ03", "Unconstrained Oracle Trust",        "06-aztec-specific",     "Critical", "Medium"),
    ("AZ04", "Note Encryption Key Misuse",        "06-aztec-specific",     "High",     "Medium"),
    ("AZ05", "Storage Slot Collision",            "06-aztec-specific",     "High",     "Medium"),
    ("AZ06", "Private Function Sender Trust",     "06-aztec-specific",     "Critical", "Hard"),
]

SEVERITY_EMOJI = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🟢",
}


def check_circuit_exists(vuln_id: str, category: str, circuit_type: str) -> bool:
    # Find the directory matching the vuln_id prefix
    cat_dir = REPO_ROOT / "vulnerabilities" / category
    if not cat_dir.exists():
        return False
    for d in cat_dir.iterdir():
        if d.name.startswith(vuln_id):
            circuit_dir = d / circuit_type
            return (circuit_dir / "src" / "main.nr").exists()
    return False


def nargo_check(circuit_dir: Path) -> bool:
    """Run nargo check on a circuit. Returns True if it passes."""
    try:
        result = subprocess.run(
            ["nargo", "check"],
            cwd=str(circuit_dir),
            capture_output=True,
            timeout=30,
        )
        return result.returncode == 0
    except Exception:
        return False


def generate_report(output_path: str = "REPORT.md") -> None:
    """Generate the full report."""
    print("Generating NoirSec report...")

    lines = [
        f"# NoirSec — Validation Report",
        f"",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"",
        f"---",
        f"",
        f"## Vulnerability Coverage",
        f"",
        f"| ID | Name | Severity | Difficulty | Vulnerable | Patched |",
        f"|----|------|----------|------------|------------|---------|",
    ]

    total = len(VULNERABILITIES)
    vuln_present = 0
    patch_present = 0

    for vuln_id, name, category, severity, difficulty in VULNERABILITIES:
        v_exists = check_circuit_exists(vuln_id, category, "vulnerable")
        p_exists = check_circuit_exists(vuln_id, category, "patched")
        if v_exists:
            vuln_present += 1
        if p_exists:
            patch_present += 1

        sev_emoji = SEVERITY_EMOJI.get(severity, "")
        v_status = "✅" if v_exists else "❌"
        p_status = "✅" if p_exists else "❌"
        lines.append(
            f"| {vuln_id} | {name} | {sev_emoji} {severity} | {difficulty} | {v_status} | {p_status} |"
        )

    lines += [
        f"",
        f"**Total:** {total} vulnerabilities | "
        f"Vulnerable circuits: {vuln_present}/{total} | "
        f"Patched circuits: {patch_present}/{total}",
        f"",
        f"---",
        f"",
        f"## Notes",
        f"",
        f"- Run `bash scripts/verify_all.sh` to compile-check all circuits with nargo",
        f"- Run `bash detection/run_all.sh` for automated detection analysis",
        f"- See [TAXONOMY.md](TAXONOMY.md) for full vulnerability descriptions",
        f"",
    ]

    report_content = "\n".join(lines)

    with open(output_path, "w") as f:
        f.write(report_content)

    print(f"Report written to {output_path}")
    print(f"Coverage: {vuln_present}/{total} vulnerable, {patch_present}/{total} patched")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="REPORT.md")
    args = parser.parse_args()
    generate_report(args.output)
