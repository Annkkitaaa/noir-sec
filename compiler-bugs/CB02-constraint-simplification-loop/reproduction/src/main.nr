// CB02: Constraint Simplification Removing Loop Assertions (Noir Issue #9806)
// ===========================================================================
// Bug: The Noir SSA optimizer (pre-fix) simplified away constraints that
// involved loop induction variables, potentially removing security-critical
// assertions inside loops.
//
// Pattern: A loop that asserts a range constraint on each element of an array.
// Bug: The optimizer determined the assertion was "provably true" for constant
// loop bounds, then removed the constraint from ACIR. Any circuit relying on
// per-element assertions inside loops could be silently weakened.
//
// Status: FIXED in Noir v1.x (issue #9806: "Do not simplify constraints with
//         induction variable")
// Affected versions: Noir v1.x prior to fix

// The vulnerability pattern: asserting a constraint inside a loop.
// In affected compilers, the SSA optimizer could eliminate these assertions
// when it determined the induction variable's value was "bounded" by the loop.
fn main(
    values: [u64; 4],
    max_value: pub u64,
) {
    // INTENDED: every element must be <= max_value (e.g., a range check on scores)
    // BUG: In affected compilers, the optimizer might simplify this loop body
    // if it could prove the loop index i is in range [0,4), concluding the
    // assertion is "always satisfied" and removing it from the constraint system.
    for i in 0..4 {
        // This assertion should generate a constraint for each iteration.
        // Bug: the constraint was removed by the optimizer in some cases.
        assert(values[i] <= max_value);
    }
}
