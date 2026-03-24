// FA02 -- Division by Zero Non-Constraint
// ============================================================
// Vulnerability ID : FA02
// Category         : Field Arithmetic
// Severity         : High
// Difficulty       : Easy
// Hint Level       : 1
// ============================================================
//
// Scenario:
//   A DeFi interest rate circuit. Given earnings and capital, prove that
//   the claimed interest rate is correct: rate = earnings / capital.
//
//   The circuit verifies: claimed_rate * capital == earnings
//   (rearranged form of rate = earnings / capital)
//
// Spec:
//   Prove: claimed_rate * capital == earnings
//          AND capital != 0  (division is defined)
//
// Bug:
//   When capital = 0 and earnings = 0:
//     claimed_rate * 0 == 0  =>  0 == 0  =>  TRUE for ANY claimed_rate!
//   A prover can claim ANY interest rate for a zero-capital position.

fn main(
    earnings: pub Field,      // Public:  total earnings
    capital: pub Field,       // Public:  invested capital
    claimed_rate: Field       // Private: claimed interest rate (earnings / capital)
) {
    // Verify: claimed_rate * capital == earnings
    // This is the "correct" way to verify division without field division.
    assert(claimed_rate * capital == earnings);

    // !!BUG: No check that capital != 0!!
    //
    // When capital = 0:
    //   claimed_rate * 0 = 0
    //   If earnings = 0 too, then 0 == 0 is TRUE for ALL claimed_rate values.
    //
    // An attacker with zero capital can claim an arbitrarily high interest rate:
    //   earnings = 0, capital = 0, claimed_rate = 999999
    //   999999 * 0 = 0 == earnings  => VALID PROOF
    //
    // In a lending protocol, this could allow borrowing against a "high-rate"
    // position that has zero actual capital.
    //
    // MISSING: assert(capital != 0);
}
