// UC03 -- Missing Nullifier Uniqueness
// ============================================================
// Vulnerability ID : UC03
// Category         : Under-Constrained
// Severity         : Critical
// Difficulty       : Medium
// Hint Level       : 2
// ============================================================
//
// Scenario:
//   A private payment system where users prove they are spending a specific note.
//   Each note is defined by (value, salt) -- two notes may have the same value
//   but different salts (they are distinct notes).
//
//   The nullifier should be unique per note -- different notes must have
//   different nullifiers, regardless of whether they have the same value.
//
// Spec:
//   nullifier = pedersen_hash([owner_secret, note_value, note_salt])
//   (includes all unique note components)
//
// Your challenge:
//   Show that two different notes (same value, different salt) produce the
//   SAME nullifier in the vulnerable circuit.

fn main(
    note_value: Field,       // Private: value stored in this note
    note_salt: Field,        // Private: random salt making note unique
    owner_secret: Field,     // Private: owner's secret key
    note_hash: pub Field,    // Public:  commitment to the note
    nullifier: pub Field     // Public:  published nullifier
) {
    // Verify note_hash commits to all note contents.
    let computed_note_hash = std::hash::pedersen_hash([note_value, note_salt, owner_secret]);
    assert(computed_note_hash == note_hash);

    // !!BUG: nullifier depends on note_value but NOT on note_salt!!
    //
    // Two different notes with the SAME value but DIFFERENT salts:
    //   Note A: (value=100, salt=42)  -> nullifier = hash(owner, 100)
    //   Note B: (value=100, salt=99)  -> nullifier = hash(owner, 100) [SAME!]
    //
    // Consequence: spending Note A prevents spending Note B (DoS),
    // or a double-spend may be possible if nullifier checking is loose.
    let computed_nullifier = std::hash::pedersen_hash([owner_secret, note_value]);
    assert(computed_nullifier == nullifier);

    // MISSING: note_salt must be included in the nullifier hash.
    // Correct: pedersen_hash([owner_secret, note_value, note_salt])
}
