# AZ06 -- Private Function msg.sender Trust

| Field | Value |
|-------|-------|
| **Vulnerability ID** | AZ06 |
| **Category** | Aztec-Specific |
| **Severity** | Critical |
| **Difficulty** | Medium |
| **Hint Level** | 2 |

## Scenario

In Aztec's private execution model, `msg.sender` is not a natively-constrained value. Instead,
it is obtained through an oracle call during private function execution. The sequencer (who also
acts as the prover) controls what the oracle returns. A private function that trusts the oracle's
claim about the caller's identity without cryptographic verification can be trivially spoofed by
any sequencer or prover.

## The Bug

The vulnerable circuit calls `oracle_get_sender()` -- an unconstrained function -- to obtain the
caller's address:

```noir
unconstrained fn oracle_get_sender() -> Field { 12345 }

fn main(authorized_sender: pub Field, action_amount: pub u64, auth_commitment: pub Field) {
    let claimed_sender = unsafe { oracle_get_sender() };
    let _ = claimed_sender;       // BUG: never constrained!
    let _ = authorized_sender;    // never checked against claimed_sender
    assert(action_amount > 0);
    assert(auth_commitment != 0);
}
```

The `claimed_sender` is read from the oracle but never asserted to equal `authorized_sender`.
The circuit does not contain the constraint `claimed_sender == authorized_sender`, so the proof
is valid regardless of who actually calls the function. A malicious sequencer can pass any address
as the oracle return value and successfully generate a proof impersonating any user.

## The Fix

The patched circuit eliminates reliance on the unconstrained oracle for identity verification.
Instead, it requires the caller to prove knowledge of a `caller_secret` that is cryptographically
bound to `authorized_sender` via a public commitment:

```noir
fn main(
    authorized_sender: pub Field,
    action_amount: pub u64,
    auth_commitment: pub Field,   // = pedersen_hash([authorized_sender, caller_secret])
    caller_secret: Field          // Private: only the real caller knows this
) {
    let computed_commitment = pedersen_hash([authorized_sender, caller_secret]);
    assert(computed_commitment == auth_commitment);
    assert(action_amount > 0);
}
```

A malicious sequencer cannot forge `caller_secret` without breaking the hash preimage, so only
the legitimate caller (who knows `caller_secret`) can generate a valid proof.

## Impact Assessment

**Severity: Critical**

**Justification:** Any private function protected only by an unconstrained oracle sender check
provides no access control whatsoever. A malicious sequencer or any party generating the proof
can impersonate any user, enabling unauthorized token transfers, governance votes, administrative
actions, or any other privileged operation gated behind "only msg.sender can call this."

**Attack Complexity:** Low -- a sequencer needs only to run `nargo execute` with arbitrary public
inputs; no cryptographic breaking is required.

**Prerequisites:** The attacker must be able to act as the sequencer or control proof generation.
In Aztec's current architecture, the sequencer has this capability by design, making this a
fundamental design-level vulnerability in any contract that trusts unverified oracle sender values.

**Affected Components:** All private functions using oracle-provided `msg.sender` for access
control, private token contracts, private governance systems, private multi-sig schemes.

## Running the Exploit

```bash
bash vulnerabilities/06-aztec-specific/AZ06-private-function-sender-trust/exploit/exploit.sh
```

## Notes on the Patched Prover.toml

The patched `Prover.toml` uses a placeholder for `auth_commitment`. The correct value is
`pedersen_hash([12345, 4660])`. Compute it by running `nargo execute` in the patched directory
after updating the Prover.toml, or use a Noir REPL to compute the hash directly.

## References

- [Aztec Network Private Execution Model](https://docs.aztec.network/concepts/accounts/keys)
- [Aztec Oracles and Unconstrained Functions](https://noir-lang.org/docs/how_to/how-to-oracles)
- [Aztec msg.sender in Private Functions](https://docs.aztec.network/concepts/calls/public_private_calls)
