// AZ02 -- Private-to-Public State Leakage
// ============================================================
// Vulnerability ID : AZ02
// Category         : Aztec-Specific
// Severity         : High
// Difficulty       : Hard
// Hint Level       : 3
// ============================================================
//
// Aztec Network context:
//   In Aztec, tokens can be "shielded" (moved to private state) and
//   "unshielded" (moved back to public state). The unshielding operation
//   publishes a commitment that hides the user's identity.
//
//   This circuit simulates the unshielding commitment in vanilla Noir.
//
// Spec:
//   user_commitment must NOT reveal which user is unshielding.
//   Across multiple transactions by the same user, commitments should be
//   unlinkable to each other and to the user's address.
//
// Bug:
//   user_commitment = hash(private_balance) -- deterministic per balance.
//   As the user's balance changes (100 -> 90 -> 80), each commitment is
//   predictable. An observer can correlate commitments over time to
//   reconstruct the user's transaction history and identity.

fn main(
    sender_address: Field,       // Private: sender (must stay anonymous)
    private_balance: u64,        // Private: user's private balance
    withdrawal_amount: pub u64,   // Public:  amount being unshielded
    user_commitment: pub Field   // Public:  "anonymous" proof of sender
) {
    // Verify sufficient balance.
    assert(withdrawal_amount <= private_balance);
    assert(withdrawal_amount > 0);

    // !!BUG: user_commitment only hashes private_balance -- not sender_address!!
    //
    // 1. Balance is predictable: balance decreases by withdrawal_amount each time.
    //    hash(1000), hash(900), hash(800)... forms a traceable sequence.
    //
    // 2. sender_address is not included -- different users with the same balance
    //    produce identical commitments (false anonymity set).
    //
    // 3. No per-transaction randomness -- deterministic and linkable.
    let computed_commitment = std::hash::pedersen_hash([private_balance as Field]);
    assert(computed_commitment == user_commitment);

    // MISSING:
    //   - Include sender_address in commitment
    //   - Include a fresh random salt per transaction
    //   - Use: hash(sender_address, private_balance, fresh_salt)
}
