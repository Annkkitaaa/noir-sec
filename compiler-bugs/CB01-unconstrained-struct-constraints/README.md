# CB01 -- Unconstrained Function Generating Hidden Constraints

**Category:** Compiler Bug Reproduction
**Noir Issue:** [#4442](https://github.com/noir-lang/noir/issues/4442)
**Severity:** High
**Status:** Fixed in Noir v0.28+
**NoirSec Mapping:** [UC02 -- Unconstrained Hint Abuse](../../vulnerabilities/01-under-constrained/UC02-unconstrained-hint-abuse/)
**Real-World Precedent:** [PM-06 in POSTMORTEMS.md](../../resources/POSTMORTEMS.md#pm-06-noir-compiler----unconstrained-function-generating-constraints-issue-4442)

---

## The Bug

When a `struct` containing arrays was passed **by value** into an `unconstrained` function
and iterated over, the Noir compiler (pre-v0.28) inadvertently generated **ACIR constraints**
for code that was meant to execute only in Brillig (unconstrained/native execution mode).

```noir
struct Balances { values: [u64; 4] }

unconstrained fn compute_sum(balances: Balances) -> u64 {
    let mut total: u64 = 0;
    for i in 0..4 {
        total += balances.values[i];  // BUG: leaked into ACIR in affected compilers
    }
    total
}
```

### Why This Is Dangerous

The constrained/unconstrained boundary is a **security boundary** in Noir:
- Code in `fn main` (ACIR mode) generates proof constraints
- Code in `unconstrained fn` (Brillig mode) is hint-only; the prover controls the output

When unconstrained code accidentally generates constraints, two problems arise:

1. **Hidden constraints**: The circuit's actual constraint set differs from what source review
   would suggest. A security auditor reading the code would miss constraints contributed by
   the "unconstrained" function.

2. **Unexpected proof dependencies**: The proof now depends on intermediate values from what
   the developer believed was unconstrained execution. Circuit behavior becomes unpredictable.

---

## Reproduction

The `reproduction/` directory contains a circuit demonstrating the bug pattern.

```bash
cd compiler-bugs/CB01-unconstrained-struct-constraints/reproduction
nargo execute
```

**Expected (fixed compiler):** Circuit executes normally; `compute_sum` runs in Brillig only.
**Affected compiler:** Circuit generates unexpected ACIR constraints from the loop body.

The reproduction uses `nargo info` to inspect gate counts. In affected compilers, the gate
count will be higher than expected because the Brillig loop body contributed constraints.

---

## Detection

There is no simple automated way to detect this bug class. Manual detection requires:

1. **Static review**: Enumerate all `unconstrained fn` functions that accept struct-with-array
   arguments and compare expected vs. actual ACIR gate counts.

2. **Gate count analysis**: Using `nargo info`, compare gate counts between:
   - The circuit as written
   - A version where the unconstrained function body is replaced with a constant return value

   If the gate count differs, the unconstrained function is leaking constraints.

3. **ACIR inspection**: Inspect the compiled `.acir` artifact to verify that the unconstrained
   function's internal operations do not appear in the constraint system.

---

## Fix

**Upgrade to Noir v0.28+.** The fix ensures that Brillig operations are never promoted to
ACIR constraints during compilation, regardless of argument types.

**Defense in depth**: Even after the fix, treat the `unsafe` keyword as a security-critical
annotation. Every `unconstrained fn` call should be explicitly reviewed:
- Does the return value get fully constrained by subsequent assertions?
- Are there intermediate operations in the unconstrained function that must stay unconstrained?

---

## Key Lesson for Auditors

> **The constrained/unconstrained boundary is a security boundary.** Any bug that blurs
> this boundary — whether leaking Brillig into ACIR (this bug) or failing to constrain
> ACIR hints (UC02) — can break the soundness of the proof system.

When auditing Noir circuits, **explicitly enumerate all `unconstrained fn` calls** and verify
that the constraint contribution of each function matches developer intent. Compare gate counts
before and after removing unconstrained functions to detect leaks.
