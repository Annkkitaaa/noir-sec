// LE02 -- Missing Ownership Check
// ============================================================
// Vulnerability ID : LE02
// Category         : Logic Error
// Severity         : Critical
// Difficulty       : Medium
// Hint Level       : 2
// ============================================================
//
// Scenario:
//   A decentralized access control system. Users prove they are authorized
//   to perform an action on behalf of a specific user_id. Authorization
//   is granted to anyone who knows the secret key sk associated with
//   the registered auth_hash = pedersen_hash([sk]).
//
// Spec:
//   Prove that:
//     1. You know sk such that pedersen_hash([sk]) == auth_hash
//     2. You are acting on behalf of user_id
//     3. user_id is BOUND to sk (the key authorizes THIS user, not any user)
//
// Your challenge:
//   Alice has user_id=1 and auth_hash=hash(sk_alice).
//   Bob knows his own sk_bob and has auth_hash_bob=hash(sk_bob).
//   Can Bob generate a proof that acts on behalf of Alice's user_id?

fn main(
    sk: Field,              // Private: the secret key of the authenticating party
    user_id: pub Field,     // Public:  the user_id being acted on behalf of
    auth_hash: pub Field    // Public:  registered hash -- hash(sk) for authorized user
) {
    // Verifies: the caller knows sk such that hash(sk) == auth_hash.
    let computed_hash = std::hash::pedersen_hash([sk]);
    assert(computed_hash == auth_hash);

    // !!BUG: user_id is NEVER constrained to be related to sk!!
    //
    // The circuit only proves "you know SOME key that hashes to auth_hash."
    // It does NOT prove "your key authorizes THIS specific user_id."
    //
    // An attacker (Bob) can:
    //   - Use their own sk_bob and their own auth_hash_bob
    //   - Set user_id = alice_id (Alice's account)
    //   - Generate a valid proof acting on behalf of Alice
    //
    // Bob has a valid (sk, auth_hash) pair -- the hash check passes.
    // But Bob is acting on Alice's user_id, which should be impossible.
    //
    // MISSING: assert(user_id == pedersen_hash([sk, DOMAIN_SEPARATOR]));
    // OR: user_id must be derived from sk to bind the key to the identity.
}
