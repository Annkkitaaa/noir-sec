// OC02 -- Impossible Constraint Combination (PATCHED)
// ============================================================
// Fix: Remove the contradictory constraint (score <= 49).
//
// The circuit now correctly accepts scores in [50, 100].

fn main(
    score: u8,
    user_id: pub Field
) {
    assert(score >= 50);  // Minimum qualifying score
    assert(score <= 100); // Maximum valid score
    // REMOVED: assert(score <= 49) -- was contradicting score >= 50

    assert(user_id != 0);
}
