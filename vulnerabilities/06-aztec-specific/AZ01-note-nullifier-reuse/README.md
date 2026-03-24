# AZ01 — Note Nullifier Reuse

| Property | Value |
|----------|-------|
| **Difficulty** | Medium |
| **Category** | Aztec-Specific (AZ) |
| **Severity** | Critical |
| **Root Cause** | Nullifier derivation doesn't include note-specific entropy |

> **Real-world connection:** This vulnerability mirrors the actual Aztec Connect double-spending bug. The nullifier derivation was insufficiently binding to the specific note being spent.

---

## Aztec Network Background

In Aztec's private UTXO model:
- Assets are stored as encrypted **notes** on-chain
- To spend a note, the owner publishes a **nullifier** (hash of the note commitment + secret key)
- The **nullifier tree** is a global set — if a nullifier is already present, the note cannot be spent again
- This is Aztec's double-spending prevention mechanism

A correct nullifier must be:
1. **Unique per note** — different notes → different nullifiers
2. **Deterministic** — same note → same nullifier
3. **Secret** — cannot be linked back to the original note without the private key

This circuit simulates note spending in vanilla Noir. In production Aztec contracts, the same logic uses `aztec-nr` primitives (`NoteInterface`, `context.push_nullifier`).

---

## Scenario

Alice owns two notes:
- **Note A**: `{value: 100, salt: 42, owner: alice_secret}` — note_hash_A
- **Note B**: `{value: 100, salt: 99, owner: alice_secret}` — note_hash_B

These are **different** notes (different salts → different commitments). They should have **different** nullifiers. But do they?

Read [vulnerable/src/main.nr](vulnerable/src/main.nr) and check the nullifier derivation.

---

## Your Challenge

1. Find how the nullifier is computed in the vulnerable circuit
2. Show that Note A and Note B produce identical nullifiers
3. Explain the double-spending/DoS consequence
4. Check against [exploit/exploit.sh](exploit/exploit.sh)
5. Fix the circuit — see [patched/src/main.nr](patched/src/main.nr)

---

## Hints

<details>
<summary>Hint 1 — Mild</summary>

In the vulnerable circuit, what inputs go into `pedersen_hash(...)` for the nullifier computation? Is `note_hash` one of them?
</details>

<details>
<summary>Hint 2 — Moderate</summary>

`nullifier = hash(owner_secret)` — only the owner's secret key. Two notes by the same owner both produce `hash(alice_secret)`. They collide in the nullifier tree.

When Alice spends Note A (publishing `nullifier_A = hash(alice_secret)`), the nullifier tree marks this nullifier as spent. Now Alice tries to spend Note B — but `nullifier_B = hash(alice_secret)` = same value = already in the tree. **Note B is frozen.**
</details>

<details>
<summary>Hint 3 — Strong</summary>

The fix: include the specific note's hash in the nullifier:
```noir
let computed_nullifier = pedersen_hash([owner_secret, note_hash]);
```
Now `nullifier_A = hash(alice_secret, note_hash_A)` ≠ `nullifier_B = hash(alice_secret, note_hash_B)`.
</details>

---

## The Bug

<details>
<summary>Spoiler: Full Explanation</summary>

### Nullifier uniqueness failure

The vulnerable circuit computes:
```noir
let computed_nullifier = pedersen_hash([owner_secret]);
```

For two different notes owned by the same person:
- `nullifier(Note A) = hash(alice_secret)` = **X**
- `nullifier(Note B) = hash(alice_secret)` = **X**

Both produce the same value X.

### Consequences

**DoS attack:** An attacker who knows Alice's notes can trigger Alice to spend Note A (via social engineering or by observing transaction ordering). When Note A is spent, X is added to the nullifier tree. Now Note B can never be spent — its nullifier X is already in the tree.

**Double-spend (in buggy implementations):** If the nullifier check is done incorrectly (e.g., off-chain), Alice could submit two spending transactions for Note A and Note B simultaneously, both appearing valid because neither has hit the nullifier tree yet.

### The fix
```noir
// Vulnerable
let computed_nullifier = pedersen_hash([owner_secret]);

// Patched
let computed_nullifier = pedersen_hash([owner_secret, note_hash]);
```

### Real-world precedent
The Aztec Connect bug involved a similar insufficient binding in nullifier derivation. Reference: https://hackmd.io/@aztec-network/disclosure-of-recent-vulnerabilities

</details>

---

## Running the Exploit

```bash
bash vulnerabilities/06-aztec-specific/AZ01-note-nullifier-reuse/exploit/exploit.sh
```

---

---

## Impact Assessment

**Severity: Critical**

**Justification:** All private notes owned by the same user share a single nullifier because it depends only on `owner_secret`, not note-specific content. In Aztec, spending a note publishes its nullifier; once published, that entry prevents any note sharing the same nullifier from ever being spent. With shared nullifiers, spending note A also permanently invalidates notes B, C, and all others by the same owner -- total balance destruction with one transaction. An adversary can front-run a victim to spend one note and permanently freeze their entire balance. This mirrors the bug class found in Aztec Connect in 2021.

**Attack Complexity:** Low -- only requires the ability to front-run the victim's transaction (standard MEV capability)

**Prerequisites:** Attacker must know the victim's owner address (usually public) and be able to submit transactions

**Affected Components:** All private note spending circuits in Aztec-like systems; any ZK protocol with shared nullifiers across notes

---

---

## Real-World Precedent

**Aztec Connect (PM-01, 2021):** The Aztec Connect vulnerability disclosure describes the real-world consequences of insufficient nullifier binding in a production ZK rollup. Notes without proper nullifier uniqueness create double-spend and denial-of-service risks in live systems.

See [POSTMORTEMS.md](../../../resources/POSTMORTEMS.md#pm-01-aztec-connect----tree-index-range-constraint-bug) for the full Aztec Connect disclosure.

---

## References

- [Aztec Connect Vulnerability Disclosure](https://hackmd.io/@aztec-network/disclosure-of-recent-vulnerabilities)
- [Aztec Network Documentation: Notes and Nullifiers](https://docs.aztec.network)
- [OpenZeppelin: Developer's Guide to Safe Noir Circuits](https://www.openzeppelin.com/news/developer-guide-to-building-safe-noir-circuits)
