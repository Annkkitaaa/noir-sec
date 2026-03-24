# NoirSec CTF

**22 challenges. 4400 total points. All in Noir ZK circuits.**

NoirSec is a self-contained CTF covering every major Noir ZK vulnerability class:
under-constrained circuits, over-constrained circuits, privacy leaks, field arithmetic
bugs, logic errors, and Aztec-specific attack patterns.

---

## Getting Started

### Requirements
- [nargo](https://noir-lang.org/docs/getting_started/quick_start) v1.0.0-beta.19+
- Python 3.10+ (for Python exploit challenges)
- On Windows: run inside WSL

```bash
# Quick setup check
nargo --version
python3 --version
```

### Pick a Challenge

Open [challenges.toml](challenges.toml) or the [progress tracker](progress.md) and pick
a challenge that matches your experience level.

Each challenge gives you:
- A short description of the scenario
- A hint pointing at the vulnerability class
- A path to the vulnerable circuit

### Solve It

1. Read the vulnerable circuit's source code (`path/src/main.nr`)
2. Identify the vulnerability
3. Craft an exploit — either modify `Prover.toml` or write a script
4. Verify your exploit works with nargo: `cd path && nargo execute`

### Check Your Solution

```bash
bash ctf/check_solution.sh CTF-01   # replace with your challenge ID
```

A successful exploit exits with code 0. Mark the challenge solved in [progress.md](progress.md).

---

## Challenge Overview

| Difficulty | Points | Challenges |
|------------|--------|------------|
| Easy (1) | 100 | CTF-01, CTF-06, CTF-08, CTF-13 |
| Medium (2) | 200 | CTF-02, CTF-03, CTF-04, CTF-05, CTF-09, CTF-10, CTF-12, CTF-14, CTF-15, CTF-16, CTF-18, CTF-20, CTF-21 |
| Hard (3) | 300 | CTF-07, CTF-11, CTF-17, CTF-19, CTF-22 |

**Recommended path for beginners:** CTF-01 → CTF-06 → CTF-08 → CTF-13 → CTF-02

---

## Categories

| Category | Challenges | Key Lesson |
|----------|------------|------------|
| Under-Constrained | CTF-01 to CTF-04 | Missing constraints allow invalid witnesses |
| Field Arithmetic | CTF-05 to CTF-07 | Field math != integer math |
| Privacy Leaks | CTF-08 to CTF-11 | Public inputs can reveal secrets |
| Over-Constrained | CTF-12 to CTF-13 | Too many constraints break valid proofs |
| Logic Errors | CTF-14 to CTF-16 | Correct constraints, wrong semantics |
| Aztec-Specific | CTF-17 to CTF-22 | UTXO model, sequencer trust, oracle calls |

---

## Solutions

Reference solutions are in each challenge's `exploit/` directory. Try to solve challenges
yourself before consulting the reference solution — the learning value is in the attempt.

```
vulnerabilities/<category>/<VULN-ID>/exploit/exploit.sh   # bash exploit
vulnerabilities/<category>/<VULN-ID>/exploit/exploit.py   # Python exploit
```

---

## Tips

- **Read the spec comments**: Every vulnerable circuit has a `// Spec:` comment explaining
  what the circuit is supposed to prove. The vulnerability is the gap between spec and implementation.

- **Check Prover.toml**: The field names and their types are your attack surface. What values
  can you set them to?

- **Field vs integer**: Remember that `Field` inputs have NO range constraint. Values like
  `p-1` (the field prime minus 1) are always valid Field inputs.

- **unconstrained fn**: Any value returned from an `unconstrained fn` is prover-controlled
  unless the return value is verified by subsequent assertions.

- **`pub` keyword**: Public inputs are visible to the verifier. Private inputs are not.
  Privacy challenges exploit the gap between what the spec promises and what stays private.
