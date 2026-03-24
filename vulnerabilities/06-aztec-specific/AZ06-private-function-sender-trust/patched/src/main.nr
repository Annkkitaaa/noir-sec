// AZ06 -- Private Function msg.sender Trust (PATCHED)
// Fix: Constrain oracle-provided sender against authorized sender.
//
// Option A (simplest): Make the caller prove knowledge of authorized_sender's secret key.
// Option B (stronger): Use a cryptographic auth_commitment that binds sender identity.
//
// We implement Option B: auth_commitment = pedersen_hash([authorized_sender, caller_secret])
// The caller must know caller_secret to produce a valid proof.

fn main(
    authorized_sender: pub Field,  // Public:  who is allowed to call
    action_amount: pub u64,        // Public:  action amount
    auth_commitment: pub Field,    // Public:  commitment = hash(authorized_sender, caller_secret)
    caller_secret: Field           // Private: caller's secret key (proves identity)
) {
    // FIXED: Verify the caller knows the secret bound to authorized_sender.
    // A malicious sequencer cannot forge this -- they do not know caller_secret.
    let computed_commitment = std::hash::pedersen_hash([authorized_sender, caller_secret]);
    assert(computed_commitment == auth_commitment);

    // Now we know the caller is who they claim to be.
    assert(action_amount > 0);
}
