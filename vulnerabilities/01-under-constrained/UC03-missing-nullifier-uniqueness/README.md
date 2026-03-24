# UC03 — Missing Nullifier Uniqueness

| Property | Value |
|----------|-------|
| **Difficulty** | Medium |
| **Category** | Under-Constrained (UC) |
| **Severity** | Critical |
| **Root Cause** | Nullifier derivation excludes note salt — collision across distinct notes |

## Scenario
A private payment system. Notes are identified by `(value, salt)`. Two notes can share the same value but must be independently spendable. The nullifier must be unique per note.

**Bug:** `nullifier = hash(owner, value)` — salt excluded. Notes with same value and owner collide.

**Fix:** `nullifier = hash(owner, value, salt)` — all unique note components included.

## Running the Exploit
```bash
bash vulnerabilities/01-under-constrained/UC03-missing-nullifier-uniqueness/exploit/exploit.sh
```

## Impact Assessment

| Property | Value |
|----------|-------|
| **Severity** | Critical |
| **Justification** | Nullifier collision enables denial-of-service (spending one note blocks all same-value notes) or double-spend if the nullifier tree check is exploited |
| **Attack Complexity** | Medium — requires two notes with the same `(owner, value)` pair, which is realistic in any payment system |
| **Prerequisites** | Attacker controls note creation and can craft two notes with equal value |
| **Affected Components** | Nullifier derivation, note uniqueness guarantees, UTXO model integrity |

## References
- [AZ01](../../06-aztec-specific/AZ01-note-nullifier-reuse/README.md) — same pattern in Aztec context
- [Aztec Connect Disclosure](https://hackmd.io/@aztec-network/disclosure-of-recent-vulnerabilities)
