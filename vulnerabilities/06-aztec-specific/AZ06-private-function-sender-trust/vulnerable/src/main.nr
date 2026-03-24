// AZ06 -- Private Function msg.sender Trust
// ============================================================
// Vulnerability ID : AZ06
// Category         : Aztec-Specific
// Severity         : Critical
// Difficulty       : Medium
// ============================================================
//
// Scenario:
//   In Aztec's private execution model, msg.sender is obtained via an
//   oracle call. The sequencer (prover) controls oracle return values.
//   A private function that trusts the oracle-provided sender without
//   verifying it against a cryptographic proof can be spoofed.
//
// Bug:
//   claimed_sender is obtained from an unconstrained oracle and used
//   without any verification against the authorized sender or a
//   cryptographic commitment to the actual caller's identity.

unconstrained fn oracle_get_sender() -> Field {
    // In Aztec: this would be an oracle call returning msg.sender.
    // The sequencer (prover) controls what this returns.
    // For demo: returns the "authorized" sender -- but malicious sequencer
    // can return ANY address here, including one they do not own.
    12345
}

fn main(
    authorized_sender: pub Field,  // Public:  who should be allowed to call
    action_amount: pub u64,        // Public:  amount to transfer/action to take
    auth_commitment: pub Field     // Public:  commitment binding authorization
) {
    // Get the caller's address from oracle (unconstrained -- prover-controlled)
    let claimed_sender = unsafe { oracle_get_sender() };

    // !!BUG: claimed_sender is NEVER constrained!!
    // The circuit never asserts: claimed_sender == authorized_sender
    // A malicious sequencer can set claimed_sender to any address,
    // impersonating any user for any private function call.
    //
    // MISSING: assert(claimed_sender == authorized_sender);
    // OR: verify claimed_sender against auth_commitment

    let _ = claimed_sender; // acknowledged but unconstrained
    let _ = authorized_sender;

    // The action proceeds regardless of who actually called
    assert(action_amount > 0);
    assert(auth_commitment != 0);
}
