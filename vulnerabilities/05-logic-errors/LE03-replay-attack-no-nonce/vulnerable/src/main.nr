// LE03 -- Replay Attack (No Nonce)
// ============================================================
// Vulnerability ID : LE03
// Category         : Logic Error
// Severity         : High
// Difficulty       : Easy
// Hint Level       : 1
// ============================================================
//
// Scenario:
//   A one-time authentication system. A user generates a ZK proof
//   to authenticate for a session. The proof is supposed to be
//   single-use -- submitting the same proof twice should be rejected.
//
// Spec:
//   Proof must include a nonce or challenge that binds it to a specific
//   session/request, making it impossible to reuse.
//
// Bug:
//   The proof contains no nonce. It is valid forever.
//   An attacker who observes a valid proof can resubmit it at any time
//   to impersonate the user.

fn main(
    secret_key: Field,      // Private: user's authentication secret
    user_id: pub Field,     // Public:  user's identity
    auth_hash: pub Field    // Public:  registered hash(secret_key, user_id)
) {
    // Verify knowledge of secret_key for this user_id.
    let computed = std::hash::pedersen_hash([secret_key, user_id]);
    assert(computed == auth_hash);

    // !!BUG: No nonce, timestamp, or challenge included!!
    //
    // This proof is IDENTICAL for every authentication attempt.
    // If an attacker intercepts proof P at time T, they can resubmit P
    // at time T+1, T+2, ... T+inf and it will always be valid.
    //
    // The application layer must implement nonce tracking, but the circuit
    // provides no mechanism for the application to tie the proof to a
    // specific session -- making correct application-layer protection harder.
    //
    // MISSING: nonce: pub Field -- a challenge that changes per session
    //          assert(pedersen_hash([secret_key, user_id, nonce]) == auth_hash)
}
