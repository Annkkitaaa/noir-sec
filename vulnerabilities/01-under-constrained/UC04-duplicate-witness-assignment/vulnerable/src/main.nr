// UC04 -- Duplicate Witness Assignment
// ============================================================
// Vulnerability ID : UC04
// Category         : Under-Constrained
// Severity         : High
// Difficulty       : Medium
// Hint Level       : 2
// ============================================================
//
// Scenario:
//   A 2-of-2 multi-credential system. To perform a sensitive action,
//   a user must demonstrate knowledge of TWO INDEPENDENT secrets:
//     credential_a: their primary authentication secret
//     credential_b: their secondary authorization secret (e.g., 2FA)
//   Both must hash to their registered commitment hashes.
//
// Spec:
//   hash(credential_a) == hash_a  AND  hash(credential_b) == hash_b
//   credential_a != credential_b  (they must be DIFFERENT secrets)
//
// Your challenge:
//   Can you satisfy the 2-of-2 requirement using only ONE secret?

fn main(
    credential_a: Field,    // Private: first credential (e.g., password)
    credential_b: Field,    // Private: second credential (e.g., 2FA code)
    hash_a: pub Field,      // Public:  registered hash of credential_a
    hash_b: pub Field       // Public:  registered hash of credential_b
) {
    // Verify both credentials are known.
    let computed_hash_a = std::hash::pedersen_hash([credential_a]);
    let computed_hash_b = std::hash::pedersen_hash([credential_b]);

    assert(computed_hash_a == hash_a);
    assert(computed_hash_b == hash_b);

    // !!BUG: No constraint prevents credential_a == credential_b!!
    //
    // If hash_a == hash_b (same registered commitment), then a user can
    // provide credential_a == credential_b and satisfy BOTH checks with
    // a single secret.
    //
    // This breaks the "2 independent secrets" requirement.
    // A user who only knows one credential can bypass the 2-of-2 check
    // if the application registers the same hash for both slots.
    //
    // MISSING: assert(credential_a != credential_b);
}
