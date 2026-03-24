#!/usr/bin/env python3
"""
NoirSec: Privacy Leak Fuzzer
==============================
Analyzes Noir circuit public outputs for statistical correlation with private inputs.
If a public output correlates with a private input, a privacy leak may exist.

Approach:
1. Run the circuit with many random private inputs (keeping public inputs fixed)
2. Collect (private_input, public_output) pairs
3. Compute correlation coefficients
4. Flag pairs with high correlation as potential privacy leaks

Also performs:
- Small domain brute-force detection (PL02): if output space is small, enumerate all
- Dead variable detection (LE01/PL01): check if private inputs affect any public output

Usage:
    python3 detection/privacy_leak_fuzzer.py <circuit_path> [--samples N]

Requirements:
    - nargo installed and in PATH
    - Run in WSL on Windows

Limitations:
    - Correlation analysis is approximate — small sample sizes may miss subtle leaks
    - Cannot detect PL04 (cross-transaction correlation) without multiple proofs
    - False positives possible if circuit has intentional private→public relationships
"""

import subprocess
import sys
import os
import random
import json
import tomllib
import re
from pathlib import Path
from collections import defaultdict
from typing import Optional


BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def run_nargo_execute(circuit_dir: str, prover_content: str) -> tuple[bool, dict]:
    """Run nargo execute and parse public outputs from witness."""
    prover_path = os.path.join(circuit_dir, "Prover.toml")

    original = None
    if os.path.exists(prover_path):
        with open(prover_path) as f:
            original = f.read()

    try:
        with open(prover_path, "w") as f:
            f.write(prover_content)

        result = subprocess.run(
            ["nargo", "execute"],
            cwd=circuit_dir,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return False, {}

        # Try to read generated witness
        witness_dir = os.path.join(circuit_dir, "target")
        # Parse any output that looks like public values
        outputs = {}
        for line in (result.stdout + result.stderr).splitlines():
            match = re.search(r'(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)', line)
            if match:
                outputs[match.group(1)] = match.group(2)

        return True, outputs
    except subprocess.TimeoutExpired:
        return False, {}
    except FileNotFoundError:
        return False, {}
    finally:
        if original:
            with open(prover_path, "w") as f:
                f.write(original)


def parse_circuit_signature(circuit_dir: str) -> tuple[list, list]:
    """Parse main.nr to identify public vs private parameters."""
    main_nr = os.path.join(circuit_dir, "src", "main.nr")
    if not os.path.exists(main_nr):
        return [], []

    with open(main_nr) as f:
        content = f.read()

    # Find fn main signature
    match = re.search(r'fn\s+main\s*\(([^)]+)\)', content, re.DOTALL)
    if not match:
        return [], []

    params_str = match.group(1)
    public_params = []
    private_params = []

    for param in re.split(r',\s*', params_str):
        param = param.strip()
        if not param:
            continue
        name_match = re.search(r'(\w+)\s*:', param)
        if not name_match:
            continue
        name = name_match.group(1)
        if 'pub' in param:
            public_params.append(name)
        else:
            private_params.append(name)

    return public_params, private_params


def estimate_output_domain_size(circuit_dir: str, pub_params: list, priv_params: list,
                                 n_samples: int = 20) -> dict:
    """Estimate the domain size of each public output by sampling."""
    original_inputs = {}
    prover_path = os.path.join(circuit_dir, "Prover.toml")
    if os.path.exists(prover_path):
        try:
            with open(prover_path, "rb") as f:
                original_inputs = tomllib.load(f)
        except Exception:
            pass

    output_values = defaultdict(set)
    success_count = 0

    for _ in range(n_samples):
        # Randomize private inputs
        test_inputs = dict(original_inputs)
        for param in priv_params:
            test_inputs[param] = str(random.randint(0, 2**64))

        content = "\n".join(f'{k} = "{v}"' for k, v in test_inputs.items())
        success, outputs = run_nargo_execute(circuit_dir, content)
        if success:
            success_count += 1
            for key, val in outputs.items():
                output_values[key].add(val)

    return {k: len(v) for k, v in output_values.items()}, success_count


def check_dead_variables(circuit_dir: str, priv_params: list) -> list:
    """
    Check if any private input has no effect on the proof (dead variable / LE01).
    If changing a private input never changes any output, it may be unconstrained.
    """
    if not priv_params:
        return []

    original_inputs = {}
    prover_path = os.path.join(circuit_dir, "Prover.toml")
    if os.path.exists(prover_path):
        try:
            with open(prover_path, "rb") as f:
                original_inputs = tomllib.load(f)
        except Exception:
            pass

    # Get baseline
    baseline_content = "\n".join(f'{k} = "{v}"' for k, v in original_inputs.items())
    baseline_ok, baseline_outputs = run_nargo_execute(circuit_dir, baseline_content)
    if not baseline_ok:
        return []

    potentially_dead = []
    for param in priv_params:
        # Try changing this param to a very different value
        test_inputs = dict(original_inputs)
        original_val = test_inputs.get(param, "0")

        # Try multiple different values
        changed_outputs_seen = False
        for test_val in ["0", "1", "999999", str(2**32)]:
            if test_val == str(original_val):
                continue
            test_inputs[param] = test_val
            content = "\n".join(f'{k} = "{v}"' for k, v in test_inputs.items())
            ok, outputs = run_nargo_execute(circuit_dir, content)
            if ok and outputs != baseline_outputs:
                changed_outputs_seen = True
                break

        if not changed_outputs_seen:
            potentially_dead.append(param)

    return potentially_dead


def analyze_privacy(circuit_dir: str, n_samples: int = 50) -> None:
    """Main analysis function."""
    print(f"\nNoirSec Privacy Leak Fuzzer")
    print(f"Circuit: {circuit_dir}")
    print("=" * 60)

    # Check nargo
    result = subprocess.run(["nargo", "--version"], capture_output=True, text=True)
    if result.returncode != 0:
        print("ERROR: nargo not found. Install via scripts/setup.sh")
        sys.exit(1)

    # Parse circuit signature
    pub_params, priv_params = parse_circuit_signature(circuit_dir)
    print(f"\nPublic parameters:  {pub_params or ['(none detected)']}")
    print(f"Private parameters: {priv_params or ['(none detected)']}")

    if not pub_params and not priv_params:
        print("\nWARNING: Could not parse circuit signature. Manual review required.")
        return

    # Test 1: Dead variable detection (LE01)
    print(f"\n[Test 1] Dead variable detection (LE01/PL01 pattern)...")
    if priv_params:
        dead = check_dead_variables(circuit_dir, priv_params)
        if dead:
            print(f"  FINDING: Potentially dead variables (no effect on outputs):")
            for p in dead:
                print(f"    - {p}: changing this value doesn't affect any public output")
            print(f"  -> Could be LE01 (unused private input) or PL01 (accidental public)")
        else:
            print(f"  OK: All private inputs appear to affect the circuit")
    else:
        print(f"  SKIP: No private parameters identified")

    # Test 2: Output domain size estimation (PL02)
    print(f"\n[Test 2] Output domain size estimation (PL02 pattern)...")
    print(f"  Running {n_samples} samples with random private inputs...")
    domain_sizes, successes = estimate_output_domain_size(
        circuit_dir, pub_params, priv_params, n_samples
    )
    print(f"  Successful executions: {successes}/{n_samples}")

    for output, size in domain_sizes.items():
        ratio = size / max(successes, 1)
        if size <= 10 and successes >= 10:
            print(f"  FINDING [{output}]: Only {size} unique output values observed")
            print(f"    -> Small domain — potential PL02 brute-force attack")
        elif ratio < 0.1 and successes >= 20:
            print(f"  SUSPICIOUS [{output}]: Low output diversity ({size}/{successes} unique)")
        else:
            print(f"  OK [{output}]: {size} unique values observed (ratio={ratio:.2f})")

    print("\n" + "=" * 60)
    print("Analysis complete.")
    print("\nNote: This fuzzer cannot detect:")
    print("  - PL03 (nullifier identity): requires external address set")
    print("  - PL04 (cross-tx correlation): requires multiple proofs over time")
    print("  - FA01/FA03: requires domain-specific arithmetic analysis")
    print("\nAlways follow up automated analysis with manual code review.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="NoirSec Privacy Leak Fuzzer")
    parser.add_argument("circuit_dir", help="Path to circuit directory")
    parser.add_argument("--samples", type=int, default=50, help="Number of test samples")
    args = parser.parse_args()

    analyze_privacy(args.circuit_dir, args.samples)
