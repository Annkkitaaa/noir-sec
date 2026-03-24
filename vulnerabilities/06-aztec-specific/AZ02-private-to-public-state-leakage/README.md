# AZ02 — Private-to-Public State Leakage

| Property | Value |
|----------|-------|
| **Difficulty** | Hard |
| **Category** | Aztec-Specific (AZ) |
| **Severity** | High |
| **Root Cause** | Public commitment deterministically derived from predictable private state |

## Scenario
An Aztec unshielding circuit (simulated in vanilla Noir). Users move tokens from private to public state. The public `user_commitment = hash(private_balance)` is deterministic — balance changes predictably, creating a traceable commitment chain that de-anonymizes the user.

**Bug:** `user_commitment = hash(private_balance)` — no randomness, no sender binding.

**Fix:** `user_commitment = hash(sender_address, private_balance, tx_salt)` — fresh salt per transaction breaks linkability.


---

## Impact Assessment

**Severity: High**

**Justification:** The commitment `hash(balance)` is deterministic and changes predictably with each withdrawal. An on-chain observer tracks commitment transitions: if commitment_N = hash(1000) and commitment_{N+1} = hash(900), they know the user withdrew 100 tokens. Observing the full sequence reconstructs the user's complete balance history. Users with the same balance produce identical commitments, collapsing the anonymity set for unique balances to a single identity. This defeats shielded transaction privacy without any cryptographic attack -- only on-chain observation.

**Attack Complexity:** Low -- only requires on-chain observation; all inference is deterministic from public data

**Prerequisites:** Ability to observe on-chain commitment values (completely public blockchain data)

**Affected Components:** Private balance proofs, shielded transfer circuits, any protocol using balance-derived commitments without per-transaction randomness

---

## Running the Exploit
```bash
python3 vulnerabilities/06-aztec-specific/AZ02-private-to-public-state-leakage/exploit/exploit.py
```
