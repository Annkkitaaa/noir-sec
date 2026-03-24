// PL01 -- Accidental Public Input
// ============================================================
// Vulnerability ID : PL01
// Category         : Privacy Leak
// Severity         : High
// Difficulty       : Easy
// Hint Level       : 1
// ============================================================
//
// Scenario:
//   A private identity commitment system. Users register by providing:
//     - user_id: their public identifier (shown to verifiers)
//     - secret: their private secret (must NEVER be revealed)
//   The commitment = pedersen_hash([user_id, secret]) is stored on-chain.
//
//   When verifying, users prove knowledge of secret WITHOUT revealing it.
//
// Spec:
//   user_id -- PUBLIC (verifier may know this)
//   secret  -- PRIVATE (must stay hidden)
//   commitment -- PUBLIC (stored on-chain)
//
// Your challenge:
//   The verifier can see `secret` directly from the proof transcript.
//   Why? Find the accidental `pub` keyword.

fn main(
    user_id: pub Field,    // Intentionally public: verifier knows the user's ID
    secret: pub Field,     // !!BUG!! Should be private -- `pub` added by mistake!
    commitment: pub Field  // Intentionally public: stored on-chain commitment
) {
    // The circuit logic is correct -- the commitment is properly verified.
    // But `secret` is marked `pub`, so it appears in the proof's public inputs.
    // Any verifier (or observer) can read `secret` directly from the proof.
    let computed = std::hash::pedersen_hash([user_id, secret]);
    assert(computed == commitment);
}
