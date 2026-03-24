# AZ04 -- Note Encryption Key Misuse

| Field | Value |
|-------|-------|
| **Vulnerability ID** | AZ04 |
| **Category** | Aztec-Specific |
| **Severity** | High |
| **Difficulty** | Medium |
| **Hint Level** | 2 |

## Scenario

An Aztec private note is "encrypted" by hashing the note's secret content with a key. The intended
recipient can only verify (decrypt) the note if they know the key that was used during encryption.
A circuit implementing this pattern must hash the secret with the **recipient's** public key, not
the sender's, so that only the intended recipient can verify the commitment.

## The Bug

The vulnerable circuit computes:

```
encrypted_note = pedersen_hash([secret_note, sender_key])
```

It uses the **sender's** key instead of the recipient's public key. As a result:

- The **sender** can always recompute and verify the note (they know `sender_key`).
- The **recipient** cannot verify the note even though they are the intended recipient, because
  the note was never encrypted with their key.
- `recipient_pubkey` is present as a public input but is completely unused in the hash, making
  its presence misleading and ineffective.

## The Fix

The patched circuit computes:

```
encrypted_note = pedersen_hash([secret_note, recipient_pubkey])
```

It uses the **recipient's** public key so that only the recipient can verify the note. The
`sender_key` is retained as a private input (for sender identity proofs) but is not used in
the note encryption hash, correctly separating the concerns.

## Impact Assessment

**Severity: High**

**Justification:** A note system with this bug provides no confidentiality guarantees for the
recipient. The sender retains full read access to every note they send, while recipients are
locked out. In a financial application (e.g., private token transfers on Aztec), this means
the sender could monitor all outgoing notes and recipients would be unable to spend received
notes without external coordination.

**Attack Complexity:** Low -- the sender needs no special knowledge beyond what they already
possess (`sender_key`) to bypass the intended access control.

**Prerequisites:** The attacker must be the original sender of the note. No additional
privileges or chain access are required.

**Affected Components:** Note encryption, private state management, recipient-gated decryption,
Aztec note commitment schemes.

## Running the Exploit

```bash
bash vulnerabilities/06-aztec-specific/AZ04-note-encryption-key-misuse/exploit/exploit.sh
```

## References

- [Aztec Network Private Execution Model](https://docs.aztec.network/concepts/accounts/keys)
- [Aztec Notes and Nullifiers](https://docs.aztec.network/concepts/notes/notes)
- [Pedersen Hash in Noir](https://noir-lang.org/docs/reference/standard_library/cryptographic_primitives/hashes)
