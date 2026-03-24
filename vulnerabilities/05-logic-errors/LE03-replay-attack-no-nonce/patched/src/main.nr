// LE03 -- Replay Attack (PATCHED)
// ============================================================
// Fix: Include a public nonce in the authentication hash.
//
// Root cause:
//   Without a nonce, the proof is identical for every session.
//   An intercepted proof can be reused indefinitely.
//
// Fix:
//   Include a per-session nonce (provided by the verifier/application).
//   The auth_hash now covers (secret_key, user_id, nonce).
//   Each session produces a different proof because the nonce changes.
//   The application tracks used nonces to prevent reuse.

fn main(
    secret_key: Field,      // Private: user's authentication secret
    user_id: pub Field,     // Public:  user's identity
    nonce: pub Field,       // ADDED: per-session challenge from the verifier
    auth_hash: pub Field    // Public:  registered hash(secret_key, user_id, nonce)
) {
    // Verify knowledge of secret_key, bound to this specific session (nonce).
    // Each session generates a DIFFERENT auth_hash because nonce changes.
    let computed = std::hash::pedersen_hash([secret_key, user_id, nonce]);
    assert(computed == auth_hash);

    // The application must:
    // 1. Issue a fresh nonce for each authentication request
    // 2. Track used nonces to prevent resubmission of old proofs
    // 3. Store auth_hash = hash(user_secret, user_id, nonce) per session
}
