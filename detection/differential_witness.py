#!/usr/bin/env python3
"""
NoirSec: Differential Witness Tester
=====================================
Tests whether a Noir circuit is potentially under-constrained by attempting
to generate multiple different witnesses that produce the same public outputs.

If two different private inputs yield the same public outputs (or the circuit
accepts witness values in unexpected ranges), the circuit may be under-constrained.

Usage:
    python3 detection/differential_witness.py <circuit_path>
    python3 detection/differential_witness.py vulnerabilities/01-under-constrained/UC01-missing-range-check/vulnerable

Requirements:
    - nargo installed and in PATH
    - The circuit directory must contain Nargo.toml and src/main.nr
    - Run in WSL on Windows

Limitations:
    - Cannot detect UC02 (unconstrained hint abuse) — requires source analysis
    - Cannot guarantee completeness — only tests specific patterns
    - Best used as a first-pass triage, not a definitive security assessment
"""

import subprocess
import sys
import os
import json
import tomllib
from pathlib import Path
from typing import Optional


BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617
BN254_PRIME_MINUS_1 = BN254_PRIME - 1


def run_nargo(circuit_dir: str, prover_toml_content: str) -> tuple[bool, str]:
    """Run nargo execute with given Prover.toml content. Returns (success, output)."""
    prover_path = os.path.join(circuit_dir, "Prover.toml")

    # Back up original Prover.toml
    original_content = None
    if os.path.exists(prover_path):
        with open(prover_path, "r") as f:
            original_content = f.read()

    try:
        with open(prover_path, "w") as f:
            f.write(prover_toml_content)

        result = subprocess.run(
            ["nargo", "execute"],
            cwd=circuit_dir,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except FileNotFoundError:
        return False, "nargo not found — install via scripts/setup.sh"
    finally:
        # Restore original Prover.toml
        if original_content is not None:
            with open(prover_path, "w") as f:
                f.write(original_content)


def read_prover_toml(circuit_dir: str) -> dict:
    """Read the existing Prover.toml as a dictionary."""
    prover_path = os.path.join(circuit_dir, "Prover.toml")
    if not os.path.exists(prover_path):
        return {}
    try:
        with open(prover_path, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return {}


def test_field_overflow(circuit_dir: str, original_inputs: dict) -> list[dict]:
    """
    Test UC01-type vulnerability: try field elements outside normal integer range.
    For each Field-type input, substitute p-1 and see if the circuit still passes.
    """
    findings = []

    for key, value in original_inputs.items():
        # Skip pub inputs (we want to keep those fixed) — heuristic: assume
        # inputs with common "public" names are public
        if any(pub in key for pub in ["hash", "commitment", "root", "nullifier",
                                       "recipient", "amount", "threshold"]):
            continue

        # Build a test input with this field set to p-1
        test_inputs = dict(original_inputs)
        test_inputs[key] = str(BN254_PRIME_MINUS_1)

        # Write as TOML
        toml_content = "\n".join(f'{k} = "{v}"' for k, v in test_inputs.items())
        success, output = run_nargo(circuit_dir, toml_content)

        if success:
            findings.append({
                "type": "FIELD_RANGE_BYPASS",
                "parameter": key,
                "test_value": f"p-1 ({BN254_PRIME_MINUS_1})",
                "original_value": value,
                "description": (
                    f"Circuit accepts {key}=p-1 (field prime - 1). "
                    f"If {key} should be a bounded value (e.g., age, index), "
                    f"this is likely UC01 - Missing Range Check."
                ),
            })

    return findings


def test_zero_inputs(circuit_dir: str, original_inputs: dict) -> list[dict]:
    """
    Test FA02-type vulnerability: try divisor/denominator inputs set to zero.
    """
    findings = []

    for key, value in original_inputs.items():
        if any(div in key for div in ["capital", "divisor", "denominator", "shards", "n_"]):
            test_inputs = dict(original_inputs)
            test_inputs[key] = "0"
            toml_content = "\n".join(f'{k} = "{v}"' for k, v in test_inputs.items())
            success, output = run_nargo(circuit_dir, toml_content)

            if success:
                findings.append({
                    "type": "ZERO_INPUT_BYPASS",
                    "parameter": key,
                    "description": (
                        f"Circuit accepts {key}=0. If {key} is used as a divisor or "
                        f"denominator, this is likely FA02 - Division by Zero."
                    ),
                })

    return findings


def test_duplicate_witnesses(circuit_dir: str, original_inputs: dict) -> list[dict]:
    """
    Test UC04-type vulnerability: try setting pairs of inputs to the same value.
    """
    findings = []
    keys = list(original_inputs.keys())

    # Find pairs of similar-named keys (credential_a/credential_b, etc.)
    for i, key_a in enumerate(keys):
        for key_b in keys[i + 1:]:
            # Only test pairs that look like they should be independent
            similar = (
                (key_a.endswith("_a") and key_b.endswith("_b")) or
                (key_a.endswith("1") and key_b.endswith("2")) or
                ("credential" in key_a and "credential" in key_b)
            )
            if not similar:
                continue

            test_inputs = dict(original_inputs)
            test_inputs[key_b] = test_inputs[key_a]
            toml_content = "\n".join(f'{k} = "{v}"' for k, v in test_inputs.items())
            success, output = run_nargo(circuit_dir, toml_content)

            if success:
                findings.append({
                    "type": "DUPLICATE_WITNESS",
                    "parameters": [key_a, key_b],
                    "description": (
                        f"Circuit accepts {key_a} == {key_b}. "
                        f"If these should be independent, this is UC04."
                    ),
                })

    return findings


def analyze_circuit(circuit_dir: str) -> None:
    """Run all differential witness tests on a circuit directory."""
    print(f"\nNoirSec Differential Witness Tester")
    print(f"Circuit: {circuit_dir}")
    print("=" * 60)

    if not os.path.exists(os.path.join(circuit_dir, "Nargo.toml")):
        print(f"ERROR: No Nargo.toml found in {circuit_dir}")
        sys.exit(1)

    # Check nargo is available
    result = subprocess.run(["nargo", "--version"], capture_output=True, text=True)
    if result.returncode != 0:
        print("ERROR: nargo not found. Install via scripts/setup.sh (requires WSL on Windows)")
        sys.exit(1)

    # Read original inputs
    original_inputs = read_prover_toml(circuit_dir)
    if not original_inputs:
        print("WARNING: No Prover.toml found or it is empty. Tests may be incomplete.")
        original_inputs = {}

    print(f"\nLoaded {len(original_inputs)} inputs from Prover.toml")
    print(f"Running differential witness tests...\n")

    all_findings = []

    # Test 1: Field overflow
    print("[Test 1] Field range bypass (UC01 pattern)...")
    findings = test_field_overflow(circuit_dir, original_inputs)
    all_findings.extend(findings)
    print(f"         {len(findings)} finding(s)")

    # Test 2: Zero inputs
    print("[Test 2] Zero denominator (FA02 pattern)...")
    findings = test_zero_inputs(circuit_dir, original_inputs)
    all_findings.extend(findings)
    print(f"         {len(findings)} finding(s)")

    # Test 3: Duplicate witnesses
    print("[Test 3] Duplicate witness assignment (UC04 pattern)...")
    findings = test_duplicate_witnesses(circuit_dir, original_inputs)
    all_findings.extend(findings)
    print(f"         {len(findings)} finding(s)")

    # Report
    print("\n" + "=" * 60)
    if all_findings:
        print(f"FINDINGS: {len(all_findings)} potential issue(s) detected\n")
        for i, finding in enumerate(all_findings, 1):
            print(f"[{i}] Type: {finding['type']}")
            print(f"    {finding['description']}")
            print()
    else:
        print("No automatic findings. This does NOT mean the circuit is secure.")
        print("Manual review is required, especially for:")
        print("  - UC02 (Unconstrained Hint Abuse)")
        print("  - LE01 (Dead variables)")
        print("  - LE02 (Missing ownership binding)")
        print("  - All privacy leak categories")

    print("\nLimitation: This tool is a first-pass triage, not a security guarantee.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 differential_witness.py <circuit_directory>")
        sys.exit(1)

    analyze_circuit(sys.argv[1])
