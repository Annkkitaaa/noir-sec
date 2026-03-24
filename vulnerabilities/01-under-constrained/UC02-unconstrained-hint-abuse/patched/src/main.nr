// UC02 -- Unconstrained Hint Abuse (PATCHED)
// ============================================================
// Fix applied: Verify the unconstrained hint against the original input.
//
// Root cause:
//   The unconstrained fn factorize() returns a hint that the prover
//   controls. Without verifying that factors[0] * factors[1] == n,
//   the prover can supply any two values > 1 and claim any number
//   is composite -- including primes.
//
// Fix:
//   Add the critical constraint: assert(factors[0] * factors[1] == n).
//
//   This is the fundamental rule for unconstrained hints in Noir:
//   "Every resulting value from an unconstrained function must be involved
//   in a later constraint against the arguments of the call or a constant."
//   -- Noir documentation

unconstrained fn factorize(n: u64) -> [u64; 2] {
    // Same hint computation as before.
    // The difference is that the CONSTRAINED circuit now verifies the hint.
    let mut f0: u64 = 2;
    let mut f1: u64 = n / 2;
    if n == 15 { f0 = 3; f1 = 5; }
    if n == 21 { f0 = 3; f1 = 7; }
    [f0, f1]
}

fn main(n: pub u64) {
    // Safety: factors are verified to be non-trivial AND to multiply to n.
    let factors = unsafe { factorize(n) };

    // Verify factors are non-trivial.
    assert(factors[0] > 1);
    assert(factors[1] > 1);

    // FIXED: Verify that the hint actually factors n.
    // Without this, the prover can lie about the factors.
    assert(factors[0] * factors[1] == n);

    // Now a prover must provide REAL factors. The prime 7 cannot be
    // factored into two values > 1, so any proof for n=7 will fail.
}
