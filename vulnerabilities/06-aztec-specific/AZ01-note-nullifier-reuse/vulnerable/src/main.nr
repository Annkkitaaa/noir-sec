// AZ01 -- Note Nullifier Reuse
// ============================================================
// Vulnerability ID : AZ01
// Category         : Aztec-Specific
// Severity         : Critical
// Difficulty       : Medium
// Hint Level       : 2
// ============================================================
//
// Aztec Network context:
//   In Aztec's private UTXO model, assets are stored as encrypted "notes."
//   To spend a note, the owner publishes a "nullifier" to the global nullifier tree.
//   The nullifier tree prevents double-spending: if nullifier(N) is already in
//   the tree, note N cannot be spent again.
//
//   This circuit simulates a note spending proof in vanilla Noir.
//   In a real Aztec contract, this uses aztec-nr primitives (NoteInterface,
//   context.push_nullifier, etc.). The core vulnerability is identical.
//
// Spec:
//   Spend note with (note_hash, owner_secret), publishing nullifier:
//     nullifier = pedersen_hash([owner_secret, note_hash])
//   The nullifier must be unique per note -- different notes = different nullifiers.
//
// Your challenge:
//   Alice owns two notes with the same value but different salts (they ARE different notes).
//   Show that both notes produce the SAME nullifier in the vulnerable circuit.
//   This means spending one note effectively "burns" the other (DoS),
//   or both can be spent in the same transaction (double-spend).

fn main(
    note_value: Field,       // Private: token amount in this note
    note_salt: Field,        // Private: random salt making each note unique
    owner_secret: Field,     // Private: the note owner's secret key
    note_hash: pub Field,    // Public:  commitment to the note (hash of all note fields)
    nullifier: pub Field,    // Public:  published to the nullifier tree
    recipient: pub Field     // Public:  who receives the transferred value
) {
    // Verify note_hash is a valid commitment to the note contents.
    let computed_note_hash = std::hash::pedersen_hash([note_value, note_salt, owner_secret]);
    assert(computed_note_hash == note_hash);

    // Compute the nullifier to publish.
    // !!BUG: nullifier only depends on owner_secret, NOT on note_hash!!
    //
    // Any two notes owned by the same person produce the SAME nullifier.
    // Spending note A automatically "spends" note B (same nullifier).
    // This enables:
    //   1. Denial of service: spending one note blocks all your other notes
    //   2. Double-spend if the nullifier check is done incorrectly
    let computed_nullifier = std::hash::pedersen_hash([owner_secret]);
    assert(computed_nullifier == nullifier);

    // Verify the recipient is specified.
    assert(recipient != 0);

    // MISSING: nullifier should be:
    //   pedersen_hash([owner_secret, note_hash])
    // This binds the nullifier to the SPECIFIC note being spent.
}
