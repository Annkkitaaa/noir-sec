# NoirSec Detection Scripts

Lightweight automated detection scripts for Noir circuit vulnerabilities.
These scripts are NOT a replacement for manual auditing — they are a first-pass
triage tool to flag potential issues for deeper investigation.

---

## Scripts

| Script | Targets | Detects |
|--------|---------|---------|
| `noir_diff_test.py` | All categories | **Differential testing**: runs vuln/patched pairs against same inputs; flags divergence |
| `differential_witness.py` | Under-constrained (UC01–UC04) | Multiple witnesses for same public inputs |
| `privacy_leak_fuzzer.py` | Privacy leaks (PL01–PL04) | Statistical correlation between public/private inputs |
| `constraint_counter.py` | UC, FA (all categories) | Suspicious gate count differences between vulnerable/patched |
| `run_all.sh` | All categories | Runs all scripts, produces summary table |

---

## Requirements

- Python 3.10+
- `nargo` installed and in PATH ([installation guide](../scripts/setup.sh))
- On Windows: run inside WSL

---

## Usage

```bash
# Differential testing: compare a single vulnerable/patched pair
python3 detection/noir_diff_test.py \
    --vulnerable vulnerabilities/01-under-constrained/UC01-missing-range-check/vulnerable \
    --patched    vulnerabilities/01-under-constrained/UC01-missing-range-check/patched \
    --iterations 50

# Differential testing: batch scan all pairs
python3 detection/noir_diff_test.py --scan-all vulnerabilities/

# Run a specific detector on a specific circuit
python3 detection/differential_witness.py vulnerabilities/01-under-constrained/UC01-missing-range-check/vulnerable

# Run all detectors against all challenges
bash detection/run_all.sh

# Compare constraint counts between vulnerable and patched
python3 detection/constraint_counter.py \
    vulnerabilities/01-under-constrained/UC01-missing-range-check/vulnerable \
    vulnerabilities/01-under-constrained/UC01-missing-range-check/patched
```

---

## Detection Limitations

**Honest assessment — be aware of what these scripts CANNOT do:**

| Vulnerability | Auto-Detectable? | Notes |
|--------------|-----------------|-------|
| UC01 Missing Range Check | Partial | Detects if witness succeeds with large field elements |
| UC02 Unconstrained Hint Abuse | Hard | Requires modifying hint — manual review essential |
| UC03 Nullifier Uniqueness | Partial | Detects collision if two witnesses have same public outputs |
| UC04 Duplicate Witness | Partial | Detects if same secret satisfies both slots |
| OC01/OC02 Over-constrained | Yes | nargo execute fails for all inputs |
| PL01 Accidental Public | Yes | Static grep for `pub` on sensitive parameters |
| PL02 Small Domain Hash | Yes | Precompute all possible hashes, match |
| PL03 Nullifier Identity | Partial | Detects if nullifier computation omits per-note entropy |
| PL04 Correlation | Hard | Statistical analysis; needs multiple samples |
| FA01 Field Overflow | Partial | Test balance > withdrawal with field arithmetic |
| FA02 Division by Zero | Yes | Test with divisor=0 |
| FA03 Modular Misuse | Hard | Requires domain knowledge of expected behavior |
| LE01 Dead Variable | Partial | Static analysis: check private inputs appear in asserts |
| LE02 Missing Ownership | Hard | Manual review: check identity binding |
| LE03 Replay Attack | Hard | Manual review: check for nonce parameter |
| AZ01/AZ02/AZ03 Aztec | Partial | Simulated patterns only |

**Key insight for auditors:** The majority of ZK circuit vulnerabilities require **manual review**. Automated tools are a useful complement but cannot replace a skilled human auditor reading the circuit against its specification.

---

## Methodology

### noir_diff_test.py
**Differential witness testing** — the most effective automated technique for detecting
under-constrained and over-constrained circuits. Runs both circuit versions against
identical inputs and reports divergence:

- **Under-constrained signal**: vulnerable PASSES, patched FAILS
  → the patch added a missing constraint that the vulnerable version lacked
- **Over-constrained signal**: vulnerable FAILS, patched PASSES
  → the patch relaxed a constraint that was too restrictive

Uses two input strategies:
1. **Adversarial boundary inputs**: zero, one, max_u8, max_u32, max_u64, field prime ±1, 2^128, etc.
2. **Random inputs**: seeded random generation respecting field type hints from Prover.toml

Also compares ACIR gate counts: a significant gate delta is a strong signal of constraint change.

Validated results on the NoirSec suite:
- UC01: 12 divergent inputs detected (under-constrained)
- UC02: 3 divergent inputs detected (adversarial boundary)
- FA01: 20 UC + 5 OC signals detected
- Patched vs patched sanity check: 0 divergence (correct)

### differential_witness.py
Tests whether different private inputs can satisfy the same public inputs.
If two witnesses produce identical public outputs, the circuit may be under-constrained
(the prover has freedom to choose witness values that shouldn't be equivalent).

### privacy_leak_fuzzer.py
Runs the circuit with many random private inputs and analyzes public outputs.
If public outputs show statistical correlation with private inputs, a privacy leak exists.
Uses correlation coefficient analysis across the input/output space.

### constraint_counter.py
Uses `nargo info` to count ACIR gates in both vulnerable and patched versions.
A significant gate count decrease in the patched version suggests missing constraints.
Useful as a quick sanity check after patching.
