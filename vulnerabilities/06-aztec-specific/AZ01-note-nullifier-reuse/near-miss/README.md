# AZ01 Near-Miss: Nullifier Includes Nonce But Not Note Content

**Pattern:** `nullifier = hash(owner_secret, spend_nonce)` — unique per tx but not per note

---

## The Near-Miss

A developer reviews the AZ01 vulnerable circuit (where `nullifier = hash(owner_secret)`)
and recognizes that the nullifier must be unique. They add a `spend_nonce` parameter:

```noir
// Near-miss "fix":
let computed_nullifier = std::hash::pedersen_hash([owner_secret, spend_nonce]);
assert(computed_nullifier == nullifier);
```

This generates a different nullifier for each transaction (as long as spend_nonce varies).
For a single spend, it looks correct — the nullifier is unique.

**But the same note can still be double-spent.**

---

## Why the Near-Miss Fails

The `spend_nonce` is a **prover-controlled value** not bound to the specific note.
The nullifier depends on `owner_secret + spend_nonce`, NOT on which note is being spent.

**Attack (double-spend):**
1. Spend note A (note_hash=H) with spend_nonce=1. Nullifier = hash(secret, 1). Published to nullifier tree.
2. Same note A, spend_nonce=2. Nullifier = hash(secret, 2). **Different nullifier!** Nullifier tree check passes.
3. Note A is now double-spent.

The per-transaction uniqueness hides the per-note reuse.

---

## Three Versions Side-by-Side

| Version | Nullifier | Exploitable? |
|---------|-----------|-------------|
| `vulnerable/` | `hash(owner_secret)` | Yes — same for ALL notes of one owner |
| `near-miss/` | `hash(owner_secret, spend_nonce)` | Yes — same note can be spent with different nonces |
| `patched/` | `hash(owner_secret, note_hash)` | No — bound to the specific note commitment |

---

## The Correct Fix

Bind the nullifier to the specific note being spent:

```noir
let computed_nullifier = std::hash::pedersen_hash([owner_secret, note_hash]);
assert(computed_nullifier == nullifier);
```

With this fix, a given `note_hash` can produce **exactly one** nullifier regardless of
the prover's choice of other parameters. Once that nullifier is published to the nullifier
tree, the note cannot be spent again.

---

## Auditor Note

**Uniqueness is not the same as binding.** When auditing nullifier computations:
1. Does the nullifier uniquely identify **this specific note** (not just this transaction)?
2. Are all inputs to the nullifier hash fixed by the note's contents (not chosen by the prover)?
3. Can the prover select any parameter that would allow the same note to produce a different nullifier?

If the prover can vary any input to the nullifier hash while keeping the note commitment
fixed, the note can be double-spent.
