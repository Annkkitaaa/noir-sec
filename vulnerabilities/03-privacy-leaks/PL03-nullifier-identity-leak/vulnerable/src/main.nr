// PL03 -- Nullifier as Identity Leak
// ============================================================
// Vulnerability ID : PL03
// Category         : Privacy Leak
// Severity         : High
// Difficulty       : Medium
// Hint Level       : 2
// ============================================================
//
// Scenario:
//   An anonymous private transfer circuit. Users send tokens privately.
//   A nullifier is published to prevent double-spending.
//
//   The system promises sender anonymity: verifiers cannot learn WHO sent
//   a transaction -- only that it was valid.
//
// Spec:
//   nullifier must prevent replay but NOT reveal the sender's identity.
//
// Bug:
//   nullifier = hash(sender_address) -- deterministic per sender.
//   Anyone with a list of known addresses can compute hash(address) for each
//   and match against published nullifiers to identify the sender.

fn main(
    sender_address: Field,   // Private: sender's address (must stay anonymous!)
    recipient: pub Field,    // Public:  recipient
    amount: pub u64,        // Public:  transfer amount
    nullifier: pub Field     // Public:  anti-replay nullifier
) {
    // Basic transfer validity
    assert(amount > 0);
    assert(recipient != 0);

    // !!BUG: nullifier = hash(sender_address) -- leaks sender identity!!
    //
    // The nullifier is deterministic and unique per sender_address.
    // If an observer knows a list of candidate addresses (common in a small
    // community or known participant set), they can compute:
    //   hash(alice) = ? -> does it match the published nullifier?
    //   hash(bob)   = ? -> does it match?
    //   ...
    //
    // This is a brute-force attack on the sender set -- O(n) hash computations.
    // All transactions by the same sender share the same nullifier pattern.
    let computed_nullifier = std::hash::pedersen_hash([sender_address]);
    assert(computed_nullifier == nullifier);

    // MISSING: Include a note-specific salt in the nullifier
    // to break the deterministic link to sender_address.
}
