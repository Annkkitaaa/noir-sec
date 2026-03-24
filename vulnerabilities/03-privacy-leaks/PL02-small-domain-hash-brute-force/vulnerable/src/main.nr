// PL02 -- Small Domain Hash Brute Force
// ============================================================
// Vulnerability ID : PL02
// Category         : Privacy Leak
// Severity         : High
// Difficulty       : Medium
// Hint Level       : 2
// ============================================================
//
// Scenario:
//   An anonymous election system. Voters prove their age bracket qualifies
//   them to vote (e.g., must be 18+), WITHOUT revealing their exact age.
//   The system publishes a hash of each voter's age bracket as a
//   "privacy-preserving" public output.
//
//   Age brackets:
//     0 = Under 18   (not eligible)
//     1 = 18--30
//     2 = 31--50
//     3 = 51+
//
// Spec:
//   Prove the voter's age bracket is >= 1 (eligible), without revealing age.
//   The bracket hash is published publicly.
//
// Your challenge:
//   Given a published bracket_hash, can you determine the voter's age bracket?
//   (Hint: you don't need the voter's age -- only the hash output.)

fn main(
    age: u8,                    // Private: the voter's actual age
    bracket_hash: pub Field     // Public:  published hash of age bracket
) {
    // Compute age bracket from age.
    let bracket: u8 = if age < 18 {
        0  // Under 18 -- not eligible
    } else if age <= 30 {
        1  // Young adult
    } else if age <= 50 {
        2  // Adult
    } else {
        3  // Senior
    };

    // Voter must be in an eligible bracket (>= 1).
    assert(bracket >= 1);

    // Publish a hash of the bracket as "anonymous" proof of eligibility.
    // VULNERABLE: bracket has only 4 possible values (0, 1, 2, 3).
    // An observer can hash all 4 values and match against bracket_hash!
    let computed_hash = std::hash::pedersen_hash([bracket as Field]);
    assert(computed_hash == bracket_hash);
}
