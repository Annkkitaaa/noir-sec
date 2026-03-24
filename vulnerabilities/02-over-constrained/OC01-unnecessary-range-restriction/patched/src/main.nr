// OC01 -- Unnecessary Range Restriction (PATCHED)
// ============================================================
// Fix: Use u64 instead of u32 for token_id.
//
// This accommodates all valid NFT token IDs in [0, 2^64-1].
// The range check is now appropriate for the actual domain.

fn main(
    secret_key: Field,
    token_id: u64,               // FIXED: u64 supports token IDs up to 2^64-1
    ownership_commitment: pub Field
) {
    let commitment = std::hash::pedersen_hash([secret_key, token_id as Field]);
    assert(commitment == ownership_commitment);
}
