// FA01 -- Integer Overflow in Field
// ============================================================
// Vulnerability ID : FA01
// Category         : Field Arithmetic
// Severity         : Critical
// Difficulty       : Medium
// Hint Level       : 2
// ============================================================
//
// Scenario:
//   A ZK token contract. A user proves they have sufficient balance to
//   cover a withdrawal. The circuit verifies: withdrawal <= balance.
//   If verified, the contract allows the withdrawal on-chain.
//
// Spec:
//   Prove that: withdrawal <= balance  (no overdraft)
//
// Your challenge:
//   You have a balance of 100 tokens. Can you prove a withdrawal of 1000?
//   (In a real system this would allow you to steal tokens from the contract.)

fn main(
    balance: Field,        // Private: user's current token balance
    withdrawal: pub Field  // Public:  amount being withdrawn
) {
    // The developer wants to verify: balance >= withdrawal
    // (i.e., the user has enough balance to cover the withdrawal)
    //
    // VULNERABLE: Field subtraction NEVER underflows.
    // In a prime field, (a - b) mod p is ALWAYS in [0, p-1].
    // If balance=100 and withdrawal=1000:
    //   remaining = 100 - 1000 = p - 900  (a huge positive number!)
    // This is NOT zero, so the assert passes -- even though the user is overdrawn.
    //
    // The developer mistakenly believes:
    //   "If remaining is non-zero, the balance is positive after withdrawal."
    // But in a prime field there is NO negative number -- subtraction wraps.
    let remaining = balance - withdrawal;
    assert(remaining != 0);

    // ALSO MISSING: there is no upper-bound check on withdrawal amount.
    // A prover could also claim withdrawal = p-1 (field prime - 1 tokens).
}
