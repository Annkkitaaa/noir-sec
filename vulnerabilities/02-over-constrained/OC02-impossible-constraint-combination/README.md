# OC02 — Impossible Constraint Combination

| Property | Value |
|----------|-------|
| **Difficulty** | Easy |
| **Category** | Over-Constrained (OC) |
| **Severity** | Medium |
| **Root Cause** | Two constraints contradict each other — no valid witness exists |

## Scenario
A reward eligibility circuit requires `50 <= score <= 100`. A copy-paste error during refactoring added `assert(score <= 49)`, which contradicts `assert(score >= 50)`. No score satisfies both — the circuit is permanently broken.

**Bug:** `assert(score >= 50)` + `assert(score <= 49)` = unsatisfiable for any input.

**Fix:** Remove the erroneous `assert(score <= 49)`.


---

## Impact Assessment

**Severity: Medium**

**Justification:** Mutually exclusive constraints (`score >= 50` AND `score <= 49`) make the circuit permanently unsatisfiable -- no valid witness exists for any input. Every proof attempt fails. In a credit scoring or eligibility system, all users are denied access permanently. If the system depends on these proofs for operational decisions (loans, access control, governance), the entire system becomes non-functional on deployment.

**Attack Complexity:** N/A -- the circuit never works for any input; no attacker needed

**Prerequisites:** None -- automatic failure for all inputs

**Affected Components:** Any circuit with constraints that conflict; discovered at circuit design time or on first deployment

---

## Running the Exploit
```bash
bash vulnerabilities/02-over-constrained/OC02-impossible-constraint-combination/exploit/exploit.sh
```
