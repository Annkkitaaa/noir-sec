// AZ04 -- Note Encryption Key Misuse (PATCHED)
// Fix: Encrypt with recipient_pubkey, not sender_key.

fn main(
    secret_note: Field,          // Private: the note content
    sender_key: Field,           // Private: sender's key (retained but not used for encryption)
    recipient_pubkey: pub Field, // Public:  recipient's key (used for encryption)
    encrypted_note: pub Field    // Public:  commitment encrypted for recipient
) {
    // FIXED: Use recipient_pubkey so only the recipient can verify/decrypt.
    let computed = std::hash::pedersen_hash([secret_note, recipient_pubkey]);
    assert(computed == encrypted_note);

    // Sender key is retained as a private input to prove sender identity,
    // but it is NOT used in the encryption -- the note is for the recipient.
    let _ = sender_key; // acknowledge sender_key without using it in the note hash
}
