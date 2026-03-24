# FA02 — Division by Zero Non-Constraint

| Property | Value |
|----------|-------|
| **Difficulty** | Easy |
| **Category** | Field Arithmetic (FA) |
| **Severity** | High |
| **Root Cause** | Missing `assert(divisor != 0)` — any value satisfies `x * 0 == 0` |

## Scenario
An interest rate proof circuit verifies `claimed_rate * capital == earnings`. When `capital = 0` and `earnings = 0`, any `claimed_rate` satisfies `0 == 0`. An attacker claims an arbitrary rate for a zero-capital position.

**Bug:** Missing `assert(capital != 0)`.

**Fix:** Add `assert(capital != 0)` before the multiplication check.


---

## Impact Assessment

**Severity: High**

**Justification:** Field arithmetic does not raise an error on division by zero; it returns 0 (undefined behavior). A circuit dividing by an unconstrained input without asserting non-zero accepts `capital = 0` and treats the result as a valid computation. In a DeFi lending circuit, this allows borrowing at any specified rate with zero collateral. The bug is silent -- no runtime error occurs, and the circuit executes normally with a mathematically undefined result that passes all assertions.

**Attack Complexity:** Low -- simply pass 0 as the divisor; no cryptographic analysis required

**Prerequisites:** None -- the attacker sets the capital input to 0 and asserts any desired outcome

**Affected Components:** Rate calculation circuits, interest computations, any circuit performing field division on user-supplied inputs

---

## Running the Exploit
```bash
bash vulnerabilities/04-field-arithmetic/FA02-division-by-zero-no-constraint/exploit/exploit.sh
```
