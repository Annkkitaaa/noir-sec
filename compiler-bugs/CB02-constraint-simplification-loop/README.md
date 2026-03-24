# CB02 -- Constraint Simplification Removing Loop Assertions

**Category:** Compiler Bug Reproduction
**Noir Issues:** [#9806](https://github.com/noir-lang/noir/blob/master/CHANGELOG.md) ("Do not simplify constraints with induction variable"), [#9857](https://github.com/noir-lang/noir/blob/master/CHANGELOG.md) ("Check for signed division overflow")
**Severity:** High
**Status:** Fixed in Noir v1.x (post-fix release)
**NoirSec Mapping:** General UC category -- optimizer-mediated under-constrained vulnerability
**Real-World Precedent:** [PM-07 in POSTMORTEMS.md](../../resources/POSTMORTEMS.md#pm-07-noir-compiler----constraint-simplification-over-optimization)

---

## The Bug

The Noir compiler's **SSA optimization pass** could simplify away assertions that involved
loop induction variables. If the optimizer determined an assertion was "provably true" based
on the loop bounds, it removed the constraint from the compiled ACIR output.

```noir
fn main(values: [u64; 4], max_value: pub u64) {
    for i in 0..4 {
        assert(values[i] <= max_value);  // BUG: may be removed by SSA optimizer
    }
}
```

The optimizer's reasoning (incorrect): "The loop index `i` is bounded to [0, 4), and the
array access `values[i]` is always valid, therefore the assertion is always satisfiable
and can be removed."

The optimizer's error: The assertion is NOT about `i` — it's about the relationship between
`values[i]` and `max_value`, which is a runtime constraint that must be enforced.

### Why This Is Dangerous

This is a **compiler-mediated under-constrained vulnerability**: the source code is correct,
but the compiled circuit is weaker than the source implies. From an auditor's perspective,
this is more dangerous than a developer mistake:

- **Source review passes**: The code correctly specifies the range check for every element.
- **Deployed circuit fails**: The actual ACIR artifact does not enforce the constraint.
- **Detection requires ACIR audit**: Only comparing source to compiled artifact reveals the gap.

---

## Reproduction

The `reproduction/` directory demonstrates the vulnerable pattern.

```bash
cd compiler-bugs/CB02-constraint-simplification-loop/reproduction
nargo execute
```

**Expected (fixed compiler):** Circuit executes with 4 assertion constraints (one per element).
**Affected compiler:** Some or all loop assertions may be missing from ACIR.

To verify constraint presence, use `nargo info` and count gates. A correct implementation
of 4 range checks should generate noticeably more gates than a circuit with no assertions.

---

## Companion Bug: Signed Division Overflow (#9857)

Issue #9857 ("Check for signed division overflow") is a related optimization bug where
signed integer division could silently overflow without detection. The optimizer did not
generate an overflow check for `i8` / `i16` / `i32` / `i64` division results, meaning
circuits using signed division could accept inputs that produced incorrect (overflowed)
quotients.

Pattern:
```noir
fn main(a: i32, b: i32, expected: pub i32) {
    let result = a / b;  // BUG: overflow not checked in affected compilers
    assert(result == expected);
}
```

---

## Detection

Unlike developer-introduced vulnerabilities, compiler bugs require **artifact-level auditing**:

1. **ACIR inspection**: Decompile the compiled `.acir` file and count assertion opcodes.
   Compare to the number of assertions in the source. Any discrepancy is a red flag.

2. **Gate count baseline**: For a circuit with N range checks, the gate count should be
   approximately N × (gates per range check). Significantly fewer gates suggests constraints
   were removed.

3. **Compiler changelog review**: Before auditing a circuit, check the Noir CHANGELOG for
   the compiler version used. Known optimizer bugs that affect the codebase's patterns should
   trigger artifact-level review.

---

## Fix

**Upgrade to Noir v1.x** (post-fix version). The fix adds a rule to the SSA optimizer:
never simplify constraints that contain loop induction variables as sub-expressions.

**Defense in depth**: For production deployments, always:
- Pin the compiler version in `Nargo.toml`
- Audit at the ACIR level in addition to the source level
- Check the Noir CHANGELOG for optimizer bugs affecting your patterns before deployment

---

## Key Lesson for Auditors

> **The compiler is part of the trusted computing base.** Source code review is necessary
> but not sufficient for production ZK circuits. For security-critical assertions inside
> loops, verify their presence in the compiled ACIR artifact.

See CHANGELOG for issues #9806 and #9857: `https://github.com/noir-lang/noir/blob/master/CHANGELOG.md`
