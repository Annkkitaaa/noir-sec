#!/usr/bin/env python3
"""
NoirSec: Constraint Counter
============================
Compares ACIR gate counts between vulnerable and patched circuit versions.

A significant gate count DECREASE in the patched version suggests the vulnerable
version was missing constraints (under-constrained). This is a quick sanity check
to verify that a security fix actually added constraints.

Conversely, a gate count INCREASE in the patched version (over-constrained fix)
is also informative for OC01/OC02 analysis.

Usage:
    python3 detection/constraint_counter.py <vulnerable_path> <patched_path>

Requirements:
    - nargo installed with `nargo info` command support
    - Run in WSL on Windows
"""

import subprocess
import sys
import os
import re
from typing import Optional


def get_gate_count(circuit_dir: str) -> Optional[int]:
    """Run nargo info and extract the ACIR gate count."""
    if not os.path.exists(os.path.join(circuit_dir, "Nargo.toml")):
        return None

    try:
        result = subprocess.run(
            ["nargo", "info"],
            cwd=circuit_dir,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            # Try compiling first
            subprocess.run(["nargo", "compile"], cwd=circuit_dir,
                         capture_output=True, timeout=60)
            result = subprocess.run(
                ["nargo", "info"],
                cwd=circuit_dir,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                return None

        output = result.stdout + result.stderr

        # Parse gate count from nargo info output
        # Common formats: "ACIR opcodes: 42", "Gates: 42", "circuit size: 42"
        patterns = [
            r'(?:ACIR\s+opcodes?|gates?|circuit\s+size)[:\s]+(\d+)',
            r'(\d+)\s+(?:ACIR\s+opcode|gate|constraint)',
            r'Opcodes\s*:\s*(\d+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return int(match.group(1))

        # Try to find any number that looks like a gate count
        numbers = re.findall(r'\b(\d{1,6})\b', output)
        if numbers:
            return int(numbers[0])

        return None

    except subprocess.TimeoutExpired:
        return None
    except FileNotFoundError:
        return None


def compare_circuits(vuln_dir: str, patch_dir: str) -> None:
    """Compare gate counts between vulnerable and patched circuits."""
    print(f"\nNoirSec Constraint Counter")
    print("=" * 60)

    # Check nargo
    result = subprocess.run(["nargo", "--version"], capture_output=True, text=True)
    if result.returncode != 0:
        print("ERROR: nargo not found. Install via scripts/setup.sh")
        sys.exit(1)

    print(f"Vulnerable: {vuln_dir}")
    print(f"Patched:    {patch_dir}")
    print()

    print("[1/2] Getting gate count for vulnerable circuit...")
    vuln_count = get_gate_count(vuln_dir)
    if vuln_count is None:
        print("  Could not determine gate count (compile error or nargo info not available)")
    else:
        print(f"  Vulnerable gates: {vuln_count}")

    print("[2/2] Getting gate count for patched circuit...")
    patch_count = get_gate_count(patch_dir)
    if patch_count is None:
        print("  Could not determine gate count")
    else:
        print(f"  Patched gates:    {patch_count}")

    print()
    print("=" * 60)

    if vuln_count is None or patch_count is None:
        print("Cannot compare — one or both counts unavailable.")
        return

    diff = patch_count - vuln_count
    pct = (diff / max(vuln_count, 1)) * 100

    if diff > 0:
        print(f"Patched has MORE constraints: +{diff} gates ({pct:+.1f}%)")
        print()
        print("Interpretation:")
        print("  The patched version added constraints — consistent with fixing an")
        print("  under-constrained vulnerability (UC01-UC04, FA01-FA03, LE01-LE03).")
        if pct > 20:
            print(f"  Significant increase ({pct:.0f}%) — major fix applied.")
        else:
            print(f"  Minor increase ({pct:.0f}%) — small fix or type change.")

    elif diff < 0:
        print(f"Patched has FEWER constraints: {diff} gates ({pct:+.1f}%)")
        print()
        print("Interpretation:")
        print("  The patched version removed constraints — consistent with fixing an")
        print("  over-constrained vulnerability (OC01, OC02).")

    else:
        print(f"Gate count UNCHANGED: {vuln_count} gates in both versions")
        print()
        print("Interpretation:")
        print("  No change in constraint count. The fix may be:")
        print("  - A type change (u32 -> u64) that doesn't add ACIR gates")
        print("  - A semantic change to existing constraints")
        print("  - A privacy fix (PL01: removing pub keyword doesn't add gates)")
        print("  Manual review is recommended to confirm the fix is correct.")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 constraint_counter.py <vulnerable_dir> <patched_dir>")
        sys.exit(1)

    compare_circuits(sys.argv[1], sys.argv[2])
