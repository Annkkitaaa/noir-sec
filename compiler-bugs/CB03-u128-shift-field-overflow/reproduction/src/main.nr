// CB03: u128 Left Bit Shift Field Overflow (Noir Issue #9723)
// ============================================================
// Bug: Left bit shifts on `u128` values could overflow the BN254 scalar field
// modulus (p ~ 2^254), producing field elements that were arithmetically
// incorrect as 128-bit integers.
//
// The BN254 prime: p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
// This is less than 2^254. A u128 shift by 64 positions: 1 << 64 = 2^64, which
// is safe. But 1 << 127 = 2^127 > p on some platforms, causing field reduction
// to wrap to a small value that passes circuit assertions but is arithmetically wrong.
//
// Pattern: A circuit uses u128 for large cryptographic values (e.g., key material,
// bit manipulation in hash functions). Shift operations near the upper range of
// u128 silently produce wrong values.
//
// Status: FIXED in Noir v1.x (issue #9723: "Left bit shift u128 would overflow Field")
// Affected versions: Noir v1.x prior to fix

fn main(
    base: u128,
    shift_amount: u128,
    expected_result: pub u128,
) {
    // INTENDED: standard left bit shift on u128
    // BUG: In affected compilers, if base << shift_amount overflows field p,
    // the result is field-reduced instead of wrapping as 2^128. Any downstream
    // assertion comparing to expected_result would silently accept a wrong value.
    // Note: Noir requires same type for both shift operands.
    let result = base << shift_amount;

    // This assertion was intended to verify correct shift arithmetic.
    // Bug: In affected compilers, a prover could satisfy this with an incorrect
    // shift result that happened to match after field reduction.
    assert(result == expected_result);
}
