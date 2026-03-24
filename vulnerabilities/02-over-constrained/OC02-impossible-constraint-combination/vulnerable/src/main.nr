// OC02 -- Impossible Constraint Combination
// ============================================================
// Vulnerability ID : OC02
// Category         : Over-Constrained
// Severity         : Medium
// Difficulty       : Easy
// Hint Level       : 1
// ============================================================
//
// Scenario:
//   A reward eligibility circuit. Users prove they are eligible for a reward
//   based on their score. The developer intended to accept scores in [50, 100].
//   During a refactor, a conflicting constraint was accidentally introduced.
//
// Spec:
//   Accept scores where: 50 <= score <= 100
//
// Bug:
//   The circuit contains contradictory constraints -- it can NEVER be satisfied.
//   The reward system is completely broken: NO valid proof can be generated.
//
// Your challenge:
//   Find the two constraints that contradict each other.

fn main(
    score: u8,           // Private: user's score
    user_id: pub Field   // Public:  user identity
) {
    // Constraint 1: score must be at least 50 (minimum to qualify)
    assert(score >= 50);

    // Constraint 2: score must be at most 100 (maximum possible score)
    assert(score <= 100);

    // !!BUG: This constraint was added during a copy-paste refactor mistake!!
    // Constraint 3: score must be at most 49
    assert(score <= 49);  // Contradicts Constraint 1! No score satisfies both.

    // Constraints 1 and 3 together require: 50 <= score AND score <= 49
    // This is impossible -- no value of score can satisfy both.
    // The circuit is permanently broken. All reward claims fail.

    assert(user_id != 0);
}
