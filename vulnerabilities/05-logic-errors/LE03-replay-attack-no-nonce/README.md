# LE03 — Replay Attack (No Nonce)

| Property | Value |
|----------|-------|
| **Difficulty** | Easy |
| **Category** | Logic Error (LE) |
| **Severity** | High |
| **Root Cause** | No session-binding nonce — same proof valid indefinitely |

## Scenario
A ZK authentication circuit. Without a nonce or challenge, the proof is identical for every session. An intercepted proof can be replayed at any time.

**Bug:** No nonce in the hash — proof is timeless and replayable.

**Fix:** Add `nonce: pub Field` and include it in the hash — ties the proof to a specific session.


---

## Impact Assessment

**Severity: High**

**Justification:** A valid proof generated once can be replayed indefinitely because nothing in the proof binds it to a specific session, transaction, or time window. An intercepted or previously valid proof can be resubmitted by any party who captures it. In an authentication system, replaying a captured proof grants perpetual access. In a voting system, a captured vote proof can be cast multiple times. The circuit is sound within a single session but provides no replay protection at the protocol level -- a requirement the circuit itself should enforce.

**Attack Complexity:** Low -- only requires capturing one valid proof; no cryptographic attack needed

**Prerequisites:** Attacker must intercept or obtain one previously valid proof (possible via network monitoring or insider access)

**Affected Components:** Authentication circuits, voting proofs, single-use credentials, any protocol lacking nonce binding in its proof commitments

---

## Running the Exploit
```bash
bash vulnerabilities/05-logic-errors/LE03-replay-attack-no-nonce/exploit/exploit.sh
```
