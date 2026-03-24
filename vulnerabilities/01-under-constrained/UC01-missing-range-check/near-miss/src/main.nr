// UC01 -- NEAR-MISS: Range Check on Cast, Not on Witness
// ============================================================
// This circuit LOOKS like it fixes UC01 but still has a subtle vulnerability.
//
// The developer saw the bug (age is Field, no range check) and attempted to fix it
// by casting age to u8 before comparing. This looks plausible at code review,
// but it is still vulnerable.
//
// NEAR-MISS PATTERN: Casting a Field to u8 truncates the value but does NOT
// constrain the original Field witness 'age'. The cast `age as u8` computes
// the lowest 8 bits of 'age' -- it does NOT prove that age is in [0, 255].
//
// Attack: Set age = 256 + 5 = 261 in Field.
//   age as u8 = 5 (lowest 8 bits of 261)
//   assert(5 >= 18) -> FAILS? No -- try age = 256 + 30 = 286
//   age as u8 = 30
//   assert(30 >= 18) -> PASSES!
//   But the actual age value (286) far exceeds any human age.
//
// Compare to:
//   vulnerable/: no cast, no comparison at all
//   near-miss/: cast truncates instead of constraining (this file)
//   patched/:   'age' declared as u8 -- the type itself enforces the range proof

fn main(
    age: Field,       // Private: the user's actual age
    min_age: pub u8   // Public:  minimum age requirement (e.g., 18)
) {
    // NEAR-MISS: Developer attempts to fix UC01 by casting Field to u8 before comparing.
    // This looks like it adds the range check, but it does NOT constrain 'age'.
    //
    // The cast `age as u8` is computed in the circuit as: (age mod 256) as u8.
    // A prover can set age = (256 * k) + valid_looking_age for any k,
    // and age_u8 will equal valid_looking_age while the actual Field value is much larger.
    //
    // The constraint system only sees: age_u8 >= min_age.
    // It does NOT see: age is a valid 8-bit integer.
    let age_u8: u8 = age as u8;

    // This assertion is satisfied by age=286 (age_u8=30) just as well as age=30.
    assert(age_u8 >= min_age);
}
