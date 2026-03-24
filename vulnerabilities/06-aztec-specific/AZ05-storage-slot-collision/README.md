# AZ05 -- Storage Slot Collision

| Field | Value |
|-------|-------|
| **Vulnerability ID** | AZ05 |
| **Category** | Aztec-Specific |
| **Severity** | High |
| **Difficulty** | Hard |
| **Hint Level** | 3 |

## Scenario

An Aztec contract manages two distinct state variables -- `balance` and `allowance` -- by deriving
unique storage slots for each via `pedersen_hash([contract_address, variable_index])`. This pattern
is standard in Aztec's private state model: each variable must occupy a distinct, deterministic slot
so reads and writes are routed correctly. The contract is analogous to an ERC20 token contract
handling private balances and spending approvals.

## The Bug

The vulnerable circuit uses `variable_index = 0` for **both** variables:

```noir
let computed_balance_slot   = pedersen_hash([contract_address, 0]); // index 0
let computed_allowance_slot = pedersen_hash([contract_address, 0]); // BUG: also index 0
```

Because both slots resolve to the same hash, `balance_slot == allowance_slot`. Any write to the
balance slot silently overwrites the allowance slot and vice versa. The circuit accepts the
proof without complaint -- the state corruption is invisible at the constraint level.

## The Fix

The patched circuit uses **distinct** indices for each variable:

```noir
let computed_balance_slot   = pedersen_hash([contract_address, 0]); // index 0 for balance
let computed_allowance_slot = pedersen_hash([contract_address, 1]); // index 1 for allowance
```

This is standard domain separation: by varying the index, the two hashes are guaranteed to differ
for any `contract_address`. Each state variable now occupies an independent storage slot.

## Impact Assessment

**Severity: High**

**Justification:** Storage slot collisions silently corrupt contract state. In an ERC20-like
contract, writing a balance value also overwrites the allowance, and vice versa. An attacker
who controls the `allowance` slot can manipulate the effective balance of any account, enabling
unauthorized transfers or draining of funds.

**Attack Complexity:** Medium -- exploiting the collision requires understanding how slot
derivation works and crafting transactions that target the aliased slot.

**Prerequisites:** The attacker must be able to interact with the contract's private functions
(e.g., `approve`, `transfer`). No special privileges beyond a standard user account are needed.

**Affected Components:** Private state storage, ERC20-like token contracts, any Aztec contract
using indexed slot derivation without proper domain separation.

## Running the Exploit

```bash
bash vulnerabilities/06-aztec-specific/AZ05-storage-slot-collision/exploit/exploit.sh
```

## References

- [Aztec Storage Slots](https://docs.aztec.network/concepts/storage/storage_slots)
- [Aztec Private State](https://docs.aztec.network/concepts/state_model/private_state)
- [Domain Separation in Hash Functions](https://en.wikipedia.org/wiki/Domain_separation)
