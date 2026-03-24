// LE01 -- Intent vs Implementation Mismatch (PATCHED)
// ============================================================
// Fix: Actually verify owner_key against owner_commitment.
//
// Root cause:
//   owner_key appeared as a parameter but was never constrained.
//   The circuit only verified public metadata, not private ownership.
//
// Fix:
//   assert(pedersen_hash([owner_key, token_id]) == owner_commitment)
//   This binds owner_key to the specific token and the on-chain commitment.
//   Only the true owner (who knows owner_key) can generate a valid proof.

fn main(
    token_id: pub Field,
    owner_commitment: pub Field, // On-chain: hash([owner_key, token_id])
    owner_key: Field             // Private: owner's secret key
) {
    // FIXED: Actually verify the owner_key against the on-chain commitment.
    // This proves: prover knows owner_key such that hash([owner_key, token_id]) == commitment
    // Only the true owner knows the correct owner_key for this token.
    let computed_commitment = std::hash::pedersen_hash([owner_key, token_id]);
    assert(computed_commitment == owner_commitment);

    // Note: metadata_hash removed -- it was public and not useful for ownership proof.
}
