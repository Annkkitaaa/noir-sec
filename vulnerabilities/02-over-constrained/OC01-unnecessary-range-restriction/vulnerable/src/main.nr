// OC01 -- Unnecessary Range Restriction
// ============================================================
// Vulnerability ID : OC01
// Category         : Over-Constrained
// Severity         : Medium
// Difficulty       : Easy
// Hint Level       : 1
// ============================================================
//
// Scenario:
//   An NFT ownership proof. The application layer assigns 64-bit token IDs
//   (any value in [0, 2^64-1]). The circuit proves ownership of a specific
//   token_id without revealing the owner's secret key.
//
// Spec:
//   Prove: pedersen_hash([secret_key, token_id]) == ownership_commitment
//   Valid for all token_ids in [0, 2^64-1].
//
// Bug:
//   The developer chose u32 for token_id, which only covers [0, 2^32-1].
//   NFTs with token_id >= 2^32 (e.g., 4294967296) produce proofs that
//   FAIL at the range check, even though they are valid NFTs.
//
//   This is an over-constrained bug: valid inputs are rejected.

fn main(
    secret_key: Field,            // Private: owner's secret key
    token_id: u32,                // BUG: u32 rejects valid token_ids >= 2^32
    ownership_commitment: pub Field  // Public: pedersen_hash([secret_key, token_id])
) {
    let commitment = std::hash::pedersen_hash([secret_key, token_id as Field]);
    assert(commitment == ownership_commitment);

    // The circuit compiles and the proof logic is correct, but
    // any token_id >= 4294967296 (2^32) will fail the implicit u32 range check.
    // The NFT contract supports u64 token IDs but the circuit rejects half of them.
}
