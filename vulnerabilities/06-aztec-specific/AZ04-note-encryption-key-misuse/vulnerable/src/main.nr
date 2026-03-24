// AZ04 -- Note Encryption Key Misuse
// ============================================================
// Vulnerability ID : AZ04
// Category         : Aztec-Specific
// Severity         : High
// Difficulty       : Medium
// ============================================================
//
// Scenario:
//   An Aztec private note is "encrypted" by hashing the secret with a key.
//   The recipient can decrypt only if they know the key used.
//
// Bug:
//   The vulnerable circuit encrypts with the SENDER's key instead of the
//   RECIPIENT's key. The sender can always "decrypt" (recompute the hash)
//   but the intended recipient cannot.
//
// Spec:
//   encrypted_note = pedersen_hash([secret_note, recipient_pubkey])
//   Only the recipient (who knows recipient_pubkey) can verify the note.

fn main(
    secret_note: Field,          // Private: the note content
    sender_key: Field,           // Private: sender's key (WRONG -- should use recipient's)
    recipient_pubkey: pub Field, // Public:  intended recipient's key
    encrypted_note: pub Field    // Public:  the "encrypted" commitment
) {
    // !!BUG: Uses sender_key instead of recipient_pubkey for encryption!!
    // The sender can always decrypt their own note.
    // The recipient (who only knows recipient_pubkey) cannot verify it.
    let computed = std::hash::pedersen_hash([secret_note, sender_key]);
    assert(computed == encrypted_note);

    // MISSING: assert(pedersen_hash([secret_note, recipient_pubkey]) == encrypted_note)
    // This would ensure only the recipient can verify/decrypt the note.
}
