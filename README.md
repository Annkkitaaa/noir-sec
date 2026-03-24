# NoirSec

![NoirSec CI](https://github.com/Annkkitaaa/noir-sec/actions/workflows/verify.yml/badge.svg)

**The first open-source vulnerability test suite for Noir ZK circuits.**

NoirSec is a hands-on security training corpus for auditors, developers, and researchers working with [Noir](https://noir-lang.org/) — Aztec's domain-specific language for zero-knowledge proof circuits. It contains 19 intentionally vulnerable circuits, each paired with a patched version, an exploit demonstration, and educational commentary.

---

## Motivation

ZK circuit security is fundamentally different from traditional software security. A circuit bug doesn't crash your program — it silently breaks the soundness or privacy guarantees of the proof system. The Noir ecosystem lacked a structured, hands-on corpus for learning these failure modes.

NoirSec fills that gap by providing:

- **22 vulnerable + patched circuit pairs** — see exactly what the bug looks like and what the fix is
- **Exploit scripts** — prove the vulnerability is real and exploitable
- **Differential testing framework** — automatically detect constraint divergence across vuln/patched pairs
- **Automated detection tooling** — first-pass triage scripts for common vulnerability patterns
- **Formal taxonomy** — a structured classification of Noir-specific vulnerability classes
- **Aztec-specific scenarios** — nullifier reuse, oracle trust, storage slot collisions, sender trust
- **Real-world postmortem mappings** — links every vulnerability class to documented production incidents
- **Compiler bug reproductions** — three documented Noir compiler bugs that affect circuit security
- **Near-miss examples** — circuits that look fixed but still have subtle vulnerabilities
- **CTF challenges** — 22 gamified challenges with point scoring for self-assessment

---

## Quick Start

### Prerequisites

- **nargo** (Noir compiler) — see [scripts/setup.sh](scripts/setup.sh)
- **Python 3.10+** — for detection scripts and exploits
- **WSL** — required on Windows (nargo has no native Windows binary)

### Install nargo

```bash
# On Linux/macOS or WSL:
bash scripts/setup.sh
```

### Run all circuits through the compiler

```bash
bash scripts/verify_all.sh
```

### Run automated detection

```bash
bash detection/run_all.sh
```

### Generate coverage report

```bash
python3 scripts/generate_report.py
cat REPORT.md
```

---

## Vulnerability Table

| ID | Name | Category | Severity | Difficulty |
|----|------|----------|----------|------------|
| UC01 | Missing Range Check | Under-Constrained | Critical | Easy |
| UC02 | Unconstrained Hint Abuse | Under-Constrained | Critical | Medium |
| UC03 | Missing Nullifier Uniqueness | Under-Constrained | Critical | Medium |
| UC04 | Duplicate Witness Assignment | Under-Constrained | High | Medium |
| OC01 | Unnecessary Range Restriction | Over-Constrained | Medium | Easy |
| OC02 | Impossible Constraint Combination | Over-Constrained | Medium | Easy |
| PL01 | Accidental Public Input | Privacy Leaks | High | Easy |
| PL02 | Small Domain Hash Brute Force | Privacy Leaks | High | Medium |
| PL03 | Nullifier as Identity Leak | Privacy Leaks | High | Medium |
| PL04 | Correlation via Public Outputs | Privacy Leaks | Medium | Hard |
| FA01 | Integer Overflow in Field | Field Arithmetic | Critical | Medium |
| FA02 | Division by Zero | Field Arithmetic | High | Easy |
| FA03 | Modular Arithmetic Misuse | Field Arithmetic | High | Medium |
| LE01 | Intent vs Implementation | Logic Errors | High | Hard |
| LE02 | Missing Ownership Check | Logic Errors | Critical | Medium |
| LE03 | Replay Attack (No Nonce) | Logic Errors | High | Easy |
| AZ01 | Note Nullifier Reuse | Aztec-Specific | Critical | Medium |
| AZ02 | Private-to-Public Leakage | Aztec-Specific | High | Hard |
| AZ03 | Unconstrained Oracle Trust | Aztec-Specific | Critical | Medium |
| AZ04 | Note Encryption Key Misuse | Aztec-Specific | High | Medium |
| AZ05 | Storage Slot Collision | Aztec-Specific | High | Medium |
| AZ06 | Private Function Sender Trust | Aztec-Specific | Critical | Hard |

Severity: Critical | High | Medium | Low

---

## Repository Structure

```
noir-sec/
├── vulnerabilities/
│   ├── 01-under-constrained/
│   │   ├── UC01-missing-range-check/
│   │   │   ├── vulnerable/          # Buggy circuit (compiles, unsound)
│   │   │   │   ├── src/main.nr
│   │   │   │   ├── Nargo.toml
│   │   │   │   └── Prover.toml
│   │   │   ├── patched/             # Fixed circuit
│   │   │   │   ├── src/main.nr
│   │   │   │   ├── Nargo.toml
│   │   │   │   └── Prover.toml
│   │   │   ├── exploit/             # Proof-of-concept exploit
│   │   │   │   └── exploit.sh
│   │   │   └── README.md            # Challenge description + hints
│   │   └── ... (UC02-UC04)
│   ├── 02-over-constrained/         # OC01-OC02
│   ├── 03-privacy-leaks/            # PL01-PL04
│   ├── 04-field-arithmetic/         # FA01-FA03
│   ├── 05-logic-errors/             # LE01-LE03
│   └── 06-aztec-specific/           # AZ01-AZ06
├── detection/
│   ├── noir_diff_test.py            # Differential witness testing (NEW)
│   ├── differential_witness.py      # Tests for under-constrained patterns
│   ├── privacy_leak_fuzzer.py       # Tests for privacy leaks
│   ├── constraint_counter.py        # Compares ACIR gate counts
│   ├── run_all.sh                   # Runs all detectors
│   ├── requirements.txt
│   └── README.md                    # Detection limitations table
├── compiler-bugs/                   # Documented Noir compiler bugs (NEW)
│   ├── CB01-unconstrained-struct-constraints/
│   ├── CB02-constraint-simplification-loop/
│   └── CB03-u128-shift-field-overflow/
├── ctf/                             # CTF challenge wrapper (NEW)
│   ├── challenges.toml              # 22 challenge definitions
│   ├── check_solution.sh            # Verify your exploit
│   ├── progress.md                  # Score tracker
│   └── README.md
├── scripts/
│   ├── setup.sh                     # Install nargo via noirup
│   ├── verify_all.sh                # nargo check on all circuits
│   └── generate_report.py           # Generate REPORT.md coverage summary
├── resources/
│   ├── POSTMORTEMS.md               # Real-world incident mappings (NEW)
│   ├── NOIR_SECURITY_CHECKLIST.md   # Auditor checklist
│   └── REFERENCES.md                # Citations and further reading
├── TAXONOMY.md                      # Full vulnerability taxonomy
└── Nargo.toml                       # Workspace (47 members)
```

---

## How to Use

### For learning

1. Open a vulnerability's `README.md` — read the scenario and challenge
2. Read `vulnerable/src/main.nr` — identify the bug
3. Read `exploit/exploit.sh` — understand how it's exploited
4. Read `patched/src/main.nr` — see the fix and understand *why* it works

### For auditing practice

Work through categories in order of severity:
- Start with **UC01** (easiest, Field type pitfall)
- Progress to **UC02** (the signature Noir vulnerability — unconstrained hint abuse)
- Study **AZ01** (Aztec Connect double-spend pattern)
- Finish with **LE01** / **PL04** (hardest — require semantic understanding)

### For automated detection

```bash
# Differential testing: compare a single pair
python3 detection/noir_diff_test.py \
    --vulnerable vulnerabilities/01-under-constrained/UC01-missing-range-check/vulnerable \
    --patched    vulnerabilities/01-under-constrained/UC01-missing-range-check/patched

# Differential testing: batch scan all pairs
python3 detection/noir_diff_test.py --scan-all vulnerabilities/

# Test a specific circuit for under-constrained patterns
python3 detection/differential_witness.py vulnerabilities/01-under-constrained/UC01-missing-range-check/vulnerable

# Compare gate counts between vulnerable and patched
python3 detection/constraint_counter.py \
    vulnerabilities/01-under-constrained/UC01-missing-range-check/vulnerable \
    vulnerabilities/01-under-constrained/UC01-missing-range-check/patched

# Fuzz for privacy leaks
python3 detection/privacy_leak_fuzzer.py vulnerabilities/03-privacy-leaks/PL01-accidental-public-input/vulnerable
```

### For CTF-style learning

```bash
# See all challenges
cat ctf/challenges.toml

# Check your solution
bash ctf/check_solution.sh CTF-01
```

### For integration into CI

```bash
# Add to your audit pipeline:
bash scripts/verify_all.sh        # All circuits compile
bash detection/run_all.sh          # Run automated detectors
python3 scripts/generate_report.py # Generate summary
```

---

## Complementary Tools

NoirSec is a training corpus, not a production scanner. For production auditing, consider pairing with:

| Tool | Focus | Link |
|------|-------|------|
| **NAVe** | Noir Automated Vulnerability scanner (academic) | Nethermind Research |
| **QED2** | Constraint system equivalence checker | Veridise |
| **zkFuzz** | ZK circuit fuzzer | Academic |
| **Picus** | Symbolic under-constraint detection | Trail of Bits |
| **aztec-lint** | Aztec-specific static analysis | Aztec Labs |
| **nargo check** | Compilation correctness | Built-in |

See [resources/REFERENCES.md](resources/REFERENCES.md) for links and citations.

---

## Real-World Precedents

Every vulnerability class in NoirSec has a documented real-world counterpart. See [resources/POSTMORTEMS.md](resources/POSTMORTEMS.md) for detailed mappings to production incidents including:

- **Aztec Connect** (2021) — tree index range bug (UC01) and BigField CRT overflow (FA01)
- **Zcash Sapling** (2019) — silent counterfeiting vulnerability (UC category)
- **circomlib** (2023) — eight under-constrained bugs found by QED-It/Picus
- **RISC Zero V2** (2024) — multiple UC bugs including ExpandU32 and DoDiv
- **Noir compiler** (2023-2024) — three compiler bugs that affected circuit security (see `compiler-bugs/`)

---

## Near-Miss Examples

Each circuit in NoirSec has a `near-miss/` variant demonstrating a common incorrect fix that still leaves the vulnerability exploitable:

- **UC01 near-miss**: `age as u8` truncates but doesn't constrain the Field witness
- **UC02 near-miss**: `!= 0` check allows trivial `(1, n)` factorization
- **AZ01 near-miss**: Nullifier includes nonce but not note content — enables double-spend

---

## Detection Limitations

Automated detection has significant limits in ZK security. Many vulnerability classes require human judgment:

| Vulnerability | Auto-Detectable? | Why? |
|---------------|-----------------|------|
| UC01 (Missing Range Check) | Partial | Field overflow test works; semantic intent unclear |
| UC02 (Unconstrained Hint Abuse) | No | Requires source analysis of unconstrained functions |
| LE02 (Missing Ownership Check) | No | Requires understanding of semantic binding intent |
| PL04 (Cross-tx Correlation) | No | Requires multiple proofs over time |
| AZ02 (Private-to-Public Leakage) | No | Requires understanding of Aztec storage model |

**A skilled human auditor is essential for complete coverage.**

See [detection/README.md](detection/README.md) for the full detection limitations table.

---

## Contributing

Contributions welcome:

- **New vulnerability patterns** — open an issue with a description and proposed circuit
- **Detection script improvements** — PRs welcome (keep to false-positive-conscious heuristics)
- **Real-world examples** — if a public postmortem maps to a taxonomy class, add a reference
- **Aztec contract patterns** — as aztec-nr matures, circuits can be upgraded to full contracts

Please follow the circuit implementation guidelines in [TAXONOMY.md](TAXONOMY.md).

---

## Author

Built as part of research into ZK circuit security tooling for the Noir/Aztec ecosystem.

See [resources/REFERENCES.md](resources/REFERENCES.md) for background literature.

---

## License

MIT
