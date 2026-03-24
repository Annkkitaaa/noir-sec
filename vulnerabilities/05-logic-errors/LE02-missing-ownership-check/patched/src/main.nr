// LE02 -- Missing Ownership Check (PATCHED)
// ============================================================
// Fix applied: Constrain user_id to be derived from sk.
//
// Root cause:
//   The circuit proved "I know a key matching auth_hash" but did NOT
//   prove "this key is linked to this user_id." Any valid (sk, auth_hash)
//   pair could authorize any user_id.
//
// Fix:
//   user_id must be deterministically derived from sk. This creates a
//   binding: only the holder of sk can act on behalf of the user_id
//   that was derived from sk at registration time.
//
//   user_id = pedersen_hash([sk])
//   (Registration stores user_id on-chain; auth_hash = hash([sk]) is checked at auth time)
//
// Note on auth_hash:
//   In this patched version, auth_hash is redundant because user_id = hash([sk])
//   already proves knowledge of sk. We keep it for backward compatibility;
//   a cleaner design might just use user_id as the commitment.

fn main(
    sk: Field,           // Private: the secret key
    user_id: pub Field,  // Public:  user_id = pedersen_hash([sk]) -- enforced below
    auth_hash: pub Field // Public:  auth_hash = pedersen_hash([sk]) (same as user_id here)
) {
    // Verify knowledge of sk.
    let sk_hash = std::hash::pedersen_hash([sk]);
    assert(sk_hash == auth_hash);

    // FIXED: Verify that user_id was derived from this sk.
    // Only the holder of sk can generate a valid proof for this user_id.
    // An attacker using sk_bob cannot produce a proof for alice's user_id
    // because pedersen_hash([sk_bob]) != alice_user_id.
    assert(sk_hash == user_id);

    // Result: user_id is cryptographically bound to sk.
    // Bob cannot use his own sk_bob to authorize Alice's user_id.
}
