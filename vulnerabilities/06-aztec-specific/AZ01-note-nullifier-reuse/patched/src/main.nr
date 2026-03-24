// AZ01 -- Note Nullifier Reuse (PATCHED)
// ============================================================
// Fix applied: Include note_hash in nullifier derivation.
//
// Root cause:
//   nullifier = hash(owner_secret) is the same for ALL notes owned by
//   a single owner. Two notes with the same owner produce identical nullifiers.
//
// Fix:
//   nullifier = hash(owner_secret, note_hash)
//   This binds the nullifier to the SPECIFIC note being spent.
//   Two different notes (different note_hash values) produce different nullifiers.
//
// Real Aztec connection:
//   This mirrors the Aztec Connect double-spending vulnerability.
//   The fix in production Aztec circuits includes the full note preimage
//   (or at minimum the note's unique commitment) in nullifier derivation.
//   See: https://hackmd.io/@aztec-network/disclosure-of-recent-vulnerabilities

fn main(
    note_value: Field,
    note_salt: Field,
    owner_secret: Field,
    note_hash: pub Field,
    nullifier: pub Field,
    recipient: pub Field
) {
    // Verify note commitment.
    let computed_note_hash = std::hash::pedersen_hash([note_value, note_salt, owner_secret]);
    assert(computed_note_hash == note_hash);

    // FIXED: nullifier includes note_hash -- unique per note.
    // Different notes (different note_hash) produce different nullifiers.
    // Two notes by the same owner cannot collide in the nullifier tree.
    let computed_nullifier = std::hash::pedersen_hash([owner_secret, note_hash]);
    assert(computed_nullifier == nullifier);

    assert(recipient != 0);
}
