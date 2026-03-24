// PL01 -- Accidental Public Input (PATCHED)
// ============================================================
// Fix: Remove `pub` from `secret` parameter.
//
// In Noir, parameters without `pub` are private by default.
// The secret will no longer appear in the proof's public inputs.

fn main(
    user_id: pub Field,    // Public: intended
    secret: Field,         // FIXED: private (no `pub` keyword)
    commitment: pub Field  // Public: intended
) {
    let computed = std::hash::pedersen_hash([user_id, secret]);
    assert(computed == commitment);
    // `secret` is now a private witness -- only the prover knows it.
    // The verifier only sees (user_id, commitment) and the proof.
}
