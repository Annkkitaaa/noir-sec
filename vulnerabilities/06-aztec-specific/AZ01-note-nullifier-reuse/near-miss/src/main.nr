// AZ01 -- NEAR-MISS: Nullifier Includes Nonce But Not Note Content
// ============================================================
// This circuit LOOKS like it fixes AZ01 (nullifier depends on more than just
// owner_secret), but has a subtle remaining vulnerability.
//
// NEAR-MISS PATTERN: Developer adds a "nonce" to the nullifier computation to
// make nullifiers look unique. But the nonce is derived from a per-transaction
// value that the prover controls, NOT from the specific note being spent.
//
// Specifically: nullifier = pedersen_hash([owner_secret, spend_nonce])
// where spend_nonce is any Field the prover provides.
//
// Attack: The prover can use the SAME note_hash twice with DIFFERENT nonces.
// Each spend produces a different nullifier, so the nullifier tree check passes.
// This enables double-spending of the same note.
//
// The correct fix (patched): nullifier = pedersen_hash([owner_secret, note_hash])
// This binds the nullifier to the specific note -- a note can only produce ONE
// nullifier regardless of what spend_nonce the prover provides.
//
// Compare to:
//   vulnerable/: nullifier = hash(owner_secret) -- same for ALL notes of one owner
//   near-miss/: nullifier = hash(owner_secret, spend_nonce) -- same note, different nonce = different nullifier
//   patched/:   nullifier = hash(owner_secret, note_hash) -- bound to specific note

fn main(
    note_value: Field,
    note_salt: Field,
    owner_secret: Field,
    spend_nonce: Field,          // NEAR-MISS: prover-controlled nonce, not note-bound
    note_hash: pub Field,
    nullifier: pub Field,
    recipient: pub Field
) {
    // Verify note_hash is a valid commitment.
    let computed_note_hash = std::hash::pedersen_hash([note_value, note_salt, owner_secret]);
    assert(computed_note_hash == note_hash);

    // NEAR-MISS: nullifier includes spend_nonce (looks unique) but spend_nonce
    // is NOT bound to the specific note. The same note can be spent multiple times
    // with different nonces, each producing a unique nullifier that passes
    // the nullifier tree check.
    let computed_nullifier = std::hash::pedersen_hash([owner_secret, spend_nonce]);
    assert(computed_nullifier == nullifier);

    assert(recipient != 0);
}
