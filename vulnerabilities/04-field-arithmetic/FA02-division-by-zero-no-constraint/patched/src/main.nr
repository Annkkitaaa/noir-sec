// FA02 -- Division by Zero Non-Constraint (PATCHED)
// ============================================================
// Fix: Assert capital != 0 before verifying the rate.
//
// Root cause:
//   claimed_rate * 0 == 0 is satisfied by any claimed_rate when capital=0.
//   A prover can claim any rate for a zero-capital position.
//
// Fix:
//   assert(capital != 0) ensures the division is well-defined.
//   The multiplication check then correctly verifies the rate.

fn main(
    earnings: pub Field,
    capital: pub Field,
    claimed_rate: Field
) {
    // FIXED: Ensure capital is non-zero before verifying division.
    assert(capital != 0);

    // Now the multiplication check is meaningful -- any claimed_rate * capital
    // must equal earnings, and capital != 0 prevents the trivial bypass.
    assert(claimed_rate * capital == earnings);
}
