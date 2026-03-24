// CB01: Unconstrained Function Generating Constraints (Noir Issue #4442)
// =====================================================================
// Bug: When a struct containing arrays was passed by value into an
// `unconstrained` function and iterated over, the Noir compiler (pre-v0.28)
// generated ACIR constraints for code that should only run in Brillig.
//
// Pattern: Developer intends "compute_sum" to be hint-only (no constraints).
// Bug: The array iteration inside unconstrained fn generated hidden constraints,
// making the proof depend on values the developer thought were unconstrained.
//
// Status: FIXED in Noir v0.28+ (issue #4442)
// Affected versions: Noir v0.x prior to fix

struct Balances {
    values: [u64; 4],
}

// BUGGY PATTERN (pre-fix): This unconstrained fn was intended to run only
// in Brillig (outside the proof), but the struct array iteration generated
// ACIR constraints in affected compiler versions.
unconstrained fn compute_sum(balances: Balances) -> u64 {
    let mut total: u64 = 0;
    for i in 0..4 {
        // In affected compilers: this loop body leaked into ACIR.
        // A developer reviewing the constrained code would not see this.
        total += balances.values[i];
    }
    total
}

fn main(
    balances: [u64; 4],
    expected_sum: pub u64,
) {
    let b = Balances { values: balances };

    // Developer believes: compute_sum runs unconstrained (Brillig only),
    // no constraints generated on intermediate addition.
    // Bug: In affected compilers, intermediate values from the loop body
    // silently became part of the ACIR constraint system.
    let hint_sum = unsafe { compute_sum(b) };

    // This assert was intended to be the ONLY constraint on the sum.
    // Bug made additional hidden constraints appear from compute_sum.
    assert(hint_sum == expected_sum);
}
