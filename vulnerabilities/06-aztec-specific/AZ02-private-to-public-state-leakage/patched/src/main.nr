// AZ02 -- Private-to-Public State Leakage (PATCHED)
// ============================================================
// Fix: Include sender_address and a fresh random salt in the commitment.
//
// Root cause:
//   hash(private_balance) is predictable and linkable across transactions.
//   The balance changes in a predictable pattern; the commitment leaks history.
//
// Fix:
//   user_commitment = hash(sender_address, private_balance, tx_salt)
//   where tx_salt is a fresh random value generated per transaction.
//   This makes each commitment unpredictable and unlinkable.

fn main(
    sender_address: Field,
    private_balance: u64,
    tx_salt: Field,              // ADDED: fresh random per-transaction salt
    withdrawal_amount: pub u64,
    user_commitment: pub Field
) {
    assert(withdrawal_amount <= private_balance);
    assert(withdrawal_amount > 0);

    // FIXED: Include sender_address AND tx_salt.
    // Each transaction produces a unique, unlinkable commitment.
    let computed_commitment = std::hash::pedersen_hash([sender_address, private_balance as Field, tx_salt]);
    assert(computed_commitment == user_commitment);
}
