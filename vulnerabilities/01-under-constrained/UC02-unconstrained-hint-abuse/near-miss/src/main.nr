// UC02 -- NEAR-MISS: Partial Hint Verification (Non-Zero Check Only)
// ============================================================
// This circuit LOOKS like it improves on UC02's missing constraint,
// but still has a critical under-constrained vulnerability.
//
// NEAR-MISS PATTERN: Developer adds a non-zero check on factors
// (instead of the > 1 check in the original) and also adds a product check --
// BUT the product check uses multiplication that wraps in Field arithmetic,
// NOT integer arithmetic. For very large factors, f0 * f1 mod p can equal n
// even when f0 and f1 are not actual factors of n.
//
// Simpler near-miss: only checking f0 != 0 && f1 != 0, missing the > 1 bound.
// This allows factor = 1, which means any number trivially "factors" as (1, n).
//
// Compare to:
//   vulnerable/: missing product constraint entirely
//   near-miss/: checks non-zero but allows trivial factor=1 (this file)
//   patched/:   checks f0 > 1, f1 > 1, AND f0 * f1 == n

unconstrained fn factorize(n: u64) -> [u64; 2] {
    // Prover-controlled hint. Not constrained.
    [1, n]  // trivial factorization: 1 * n = n
}

fn main(n: pub u64) {
    let factors = unsafe { factorize(n) };

    // NEAR-MISS: checks != 0 but allows factor = 1.
    // f0 = 1 and f1 = n satisfies all these checks.
    // Any number -- including primes -- can be "proven composite" via (1, n).
    assert(factors[0] != 0);
    assert(factors[1] != 0);
    assert(factors[0] * factors[1] == n);  // 1 * n == n is always true!
}
