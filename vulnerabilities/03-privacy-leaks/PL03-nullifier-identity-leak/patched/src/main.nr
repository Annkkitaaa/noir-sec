// PL03 -- Nullifier as Identity Leak (PATCHED)
// ============================================================
// Fix: Include a note-specific secret salt in the nullifier.
//
// Root cause:
//   nullifier = hash(sender_address) is deterministic per sender.
//   An observer can match nullifiers to addresses with O(n) work.
//
// Fix:
//   nullifier = hash(sender_address, note_secret)
//   where note_secret is a unique random value per transaction.
//   Now nullifiers are unlinkable to sender_address without knowing note_secret.

fn main(
    sender_address: Field,  // Private: sender's address
    note_secret: Field,     // Private: unique per-transaction random value
    recipient: pub Field,
    amount: pub u64,
    nullifier: pub Field
) {
    assert(amount > 0);
    assert(recipient != 0);

    // FIXED: Include note_secret -- breaks deterministic link to sender_address.
    // Even knowing sender_address, an observer cannot compute the nullifier
    // without also knowing note_secret (which is private).
    let computed_nullifier = std::hash::pedersen_hash([sender_address, note_secret]);
    assert(computed_nullifier == nullifier);
}
