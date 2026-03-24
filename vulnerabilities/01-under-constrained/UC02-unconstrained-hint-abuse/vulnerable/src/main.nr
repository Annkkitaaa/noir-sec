// UC02 -- Unconstrained Hint Abuse
// ============================================================
// Vulnerability ID : UC02
// Category         : Under-Constrained
// Severity         : Critical
// Difficulty       : Medium
// Hint Level       : 2
// ============================================================
//
// Scenario:
//   A ZK membership system proves that a number is COMPOSITE (not prime)
//   by providing its prime factors. Useful for: proving a modulus N=p*q
//   has two large factors (RSA-like), excluding primes from an asset pool,
//   or verifying factorization in a ZK game.
//
// Spec:
//   Prove that n has factors [f0, f1] where:
//     1. f0 > 1
//     2. f1 > 1
//     3. f0 * f1 == n   (the factors actually multiply to n)
//
// How it works:
//   The developer uses an unconstrained function to COMPUTE the factors
//   outside the circuit (as a "hint"), then verifies the hint inside.
//
// Your challenge:
//   Can you prove that the PRIME number 7 is "composite" using this circuit?
//   Can you prove ANY number is composite?

// Computes integer factors of n natively (outside the circuit).
// This runs in Brillig (native Noir execution) -- NOT in the ZK proof.
// The prover controls what this function returns.
unconstrained fn factorize(n: u64) -> [u64; 2] {
    // Native hint computation -- no constraints applied here.
    // In a real implementation this would find actual prime factors.
    // The return value is just a WITNESS HINT.
    let mut f0: u64 = 2;
    let mut f1: u64 = n / 2;
    // Simplified factor search (not important -- the prover controls this)
    if n == 15 { f0 = 3; f1 = 5; }
    if n == 21 { f0 = 3; f1 = 7; }
    [f0, f1]
}

fn main(n: pub u64) {
    // Safety: factors verified to be non-trivial below.
    let factors = unsafe { factorize(n) };

    // Verify factors are non-trivial (> 1).
    assert(factors[0] > 1);
    assert(factors[1] > 1);

    // !!BUG: The factors are never verified to MULTIPLY to n!!
    // The constraint `factors[0] * factors[1] == n` is MISSING.
    //
    // A malicious prover can make factorize() return [2, 3] for ANY input n.
    // Since factors[0]=2 > 1 and factors[1]=3 > 1, both asserts pass.
    // The prime 7 is "proven" composite by providing factors [2, 3].
}
