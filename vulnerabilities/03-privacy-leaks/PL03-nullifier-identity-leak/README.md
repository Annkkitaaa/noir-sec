# PL03 — Nullifier as Identity Leak

| Property | Value |
|----------|-------|
| **Difficulty** | Medium |
| **Category** | Privacy Leak (PL) |
| **Severity** | High |
| **Root Cause** | Nullifier is deterministically derived from sender address only |

## Scenario
An anonymous transfer circuit publishes `nullifier = hash(sender_address)` to prevent replay. An observer with a list of known addresses computes `hash(addr)` for each and matches against published nullifiers to identify senders.

**Bug:** `nullifier = hash(sender)` — deterministic and linkable.

**Fix:** `nullifier = hash(sender, note_secret)` — random per transaction, unlinkable.


---

## Impact Assessment

**Severity: High**

**Justification:** A deterministic nullifier `pedersen_hash([sender_address])` is a stable unique identifier for each sender, linking all their transactions. An attacker with a list of candidate addresses performs one hash per candidate and matches against published nullifiers -- identifying the sender in O(N) time. Every transaction by the same user produces the same nullifier, creating a traceable on-chain pseudonym. This breaks the anonymity guarantee that nullifiers are intended to provide in private transfer protocols.

**Attack Complexity:** Low -- requires a candidate address list and O(N) hash computations; automated in minutes

**Prerequisites:** Attacker must know (or enumerate) likely sender addresses (often public in permissioned systems)

**Affected Components:** Private transfer circuits, anonymous voting, any protocol where sender anonymity is required

---

## Running the Exploit
```bash
python3 vulnerabilities/03-privacy-leaks/PL03-nullifier-identity-leak/exploit/exploit.py
```
