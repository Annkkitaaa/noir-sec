// UC03 -- Missing Nullifier Uniqueness (PATCHED)
// ============================================================
// Fix applied: Include note_salt in nullifier derivation.
//
// Root cause:
//   nullifier = hash(owner_secret, note_value) ignores note_salt.
//   Two notes with the same value but different salts produce identical nullifiers.
//
// Fix:
//   Include ALL unique note components in the nullifier:
//   nullifier = hash(owner_secret, note_value, note_salt)
//   Since each note has a unique (value, salt) combination, nullifiers are unique.

fn main(
    note_value: Field,
    note_salt: Field,
    owner_secret: Field,
    note_hash: pub Field,
    nullifier: pub Field
) {
    let computed_note_hash = std::hash::pedersen_hash([note_value, note_salt, owner_secret]);
    assert(computed_note_hash == note_hash);

    // FIXED: Include note_salt in nullifier -- uniqueness guaranteed per note.
    let computed_nullifier = std::hash::pedersen_hash([owner_secret, note_value, note_salt]);
    assert(computed_nullifier == nullifier);
}
