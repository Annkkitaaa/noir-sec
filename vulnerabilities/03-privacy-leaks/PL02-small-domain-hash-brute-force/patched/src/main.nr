// PL02 -- Small Domain Hash Brute Force (PATCHED)
// ============================================================
// Fix applied: Include a user-specific secret salt in the hash.
//
// Root cause:
//   hash(bracket) where bracket in {0,1,2,3} has only 4 possible outputs.
//   An attacker can precompute hash(0), hash(1), hash(2), hash(3) and
//   instantly determine any voter's bracket from the public output.
//
// Fix:
//   Include a secret salt (known only to the voter) in the hash:
//     bracket_hash = hash(bracket, salt)
//   Now an attacker needs to find (bracket, salt) pairs, which is
//   infeasible if salt has sufficient entropy (>= 128 bits).
//
// Note:
//   The salt must be kept private and ideally derived from a secret key
//   to prevent correlation across multiple proofs by the same voter.

fn main(
    age: u8,                    // Private: the voter's actual age
    salt: Field,                // Private: random salt (>=128 bits of entropy)
    bracket_hash: pub Field     // Public:  hash(bracket, salt)
) {
    let bracket: u8 = if age < 18 {
        0
    } else if age <= 30 {
        1
    } else if age <= 50 {
        2
    } else {
        3
    };

    assert(bracket >= 1);

    // FIXED: Include secret salt in the hash.
    // Brute-forcing now requires finding (bracket, salt) -- infeasible for large salt.
    let computed_hash = std::hash::pedersen_hash([bracket as Field, salt]);
    assert(computed_hash == bracket_hash);
}
