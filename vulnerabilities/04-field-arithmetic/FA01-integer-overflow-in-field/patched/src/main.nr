// FA01 -- Integer Overflow in Field (PATCHED)
// ============================================================
// Fix applied: Use bounded integer type (u64) for token balances.
//
// Root cause:
//   Field subtraction wraps modulo the prime p. There is no "underflow"
//   in a prime field -- (a - b) is always a valid field element in [0, p-1].
//   An attacker with balance=100 can withdraw 1000 because:
//     remaining = 100 - 1000 = p - 900 (huge, non-zero) -> assert passes.
//
// Fix:
//   Use u64 for balances and withdrawals. u64 arithmetic correctly detects
//   when withdrawal > balance (it would panic or produce a carry bit).
//   The direct comparison assert(withdrawal <= balance) with u64 types
//   uses integer comparison, not field comparison.
//
// Alternative fix (if Field must be used):
//   assert(withdrawal as u64 <= balance as u64);  // cast to u64 first

fn main(
    balance: u64,        // FIXED: u64 uses integer arithmetic, no field wrap
    withdrawal: pub u64  // FIXED: u64 for withdrawal amount
) {
    // With u64, this comparison is correct integer arithmetic.
    // If balance=100 and withdrawal=1000, this assert FAILS as intended.
    assert(withdrawal <= balance);
}
