# Noir Circuit Security Checklist

A practical checklist for auditors reviewing Noir circuits. Organized by vulnerability category with concrete checks and anti-patterns.

Use this alongside automated tools — many of these checks require reading code with intent in mind.

---

## 1. Field Type Safety

- [ ] **No unbounded `Field` inputs where integers are semantically required**
  - Integers like ages, indices, balances, percentages, token IDs should use `u8/u16/u32/u64`, not `Field`
  - `Field` inputs accept values in `[0, p-1]` — any value passes a bounds check
  - Anti-pattern: `fn main(age: Field, min_age: pub Field) { assert(age >= min_age); }`
  - Fix: `fn main(age: u8, min_age: pub u8)`

- [ ] **Array indices use bounded types**
  - An unconstrained `Field` used as an array index could select any element
  - Use `u32` or `u64` for index variables

- [ ] **Comparison semantics match intent**
  - `Field` comparisons work via range decomposition in Noir; verify the constraint is logically correct
  - For `>=`/`<=` on `Field`, the prover must supply a range proof internally

---

## 2. Unconstrained Functions

- [ ] **Every `unsafe { hint_fn() }` return value is explicitly verified**
  - Unconstrained functions run in Brillig (outside the ZK proof)
  - Their outputs are witness hints — the prover controls them
  - The circuit MUST constrain the output via assertions
  - Anti-pattern: `let factors = unsafe { factorize(n) }; assert(factors[0] > 1);`
  - Fix: add `assert(factors[0] * factors[1] == n);`

- [ ] **No business logic in unconstrained functions that isn't re-checked in constrained code**
  - Any decision made inside `unconstrained fn` is invisible to the verifier

- [ ] **Oracle calls are constrained**
  - If an oracle (price feed, merkle witness) returns via `unconstrained fn`, the result must be verified against a public commitment or root
  - Anti-pattern: `let price = unsafe { oracle_get_price(id) }; assert(price >= threshold);`
  - Fix: verify `price` against a signed oracle root or on-chain price feed commitment

---

## 3. Nullifier Uniqueness

- [ ] **Nullifiers include ALL identifying information for the note**
  - A nullifier that only hashes part of a note allows double-spending
  - `nullifier = hash(owner_secret)` — WRONG: same nullifier for all notes owned by the same key
  - `nullifier = hash(note_hash, owner_secret)` — CORRECT: unique per note

- [ ] **Nullifier depends on the note content, not just the owner identity**
  - Pattern: `hash(note_value, note_salt, owner_secret)` ties nullifier to a specific UTXO

- [ ] **Nullifier does NOT reveal the owner's identity**
  - `nullifier = hash(owner_address)` leaks identity (PL03)
  - Include a note-specific secret so the nullifier is unique per note

---

## 4. Witness Uniqueness

- [ ] **Circuits that require distinct witnesses enforce it**
  - If two inputs `a` and `b` must be different, assert `a != b` or `a - b != 0`
  - Anti-pattern: 2-of-2 multi-sig that accepts `credential_a == credential_b`

- [ ] **Set membership proofs don't allow duplicate elements**
  - If proving "N distinct elements," verify each pair is distinct

---

## 5. Privacy: Public vs Private Inputs

- [ ] **No unintentional `pub` keyword on private data**
  - Check every parameter in `fn main(...)` for the `pub` modifier
  - Any `pub` parameter is included in the proof's public inputs and revealed to the verifier
  - Anti-pattern: `fn main(pub secret_key: Field, ...)`

- [ ] **Private inputs are not derivable from public outputs**
  - If `public_output = f(private_input)` and `f` is injective or has small domain, `private_input` is recoverable
  - Hash outputs should use a hash function with full-field output (not truncated)

- [ ] **Public outputs don't leak metadata**
  - Even if value is hidden, patterns in outputs (timing, amount bucketing) can leak information
  - Consider correlation across multiple transactions (PL04)

---

## 6. Field Arithmetic

- [ ] **No subtraction without range check**
  - `a - b` in `Field` wraps mod p — if `b > a`, the result is `p - (b - a)`, a large number, NOT a negative number
  - Before subtracting, assert `a >= b` using bounded types or explicit range check
  - Anti-pattern: `let remaining = balance - withdrawal; assert(remaining != 0);`

- [ ] **No division with unconstrained denominator**
  - Division by zero in Noir: if the denominator could be 0, the circuit either panics or is unsatisfiable
  - Assert the denominator is non-zero before dividing: `assert(divisor != 0);`

- [ ] **Modular arithmetic uses the right type**
  - `Field % n` operates in the scalar field — result may differ from integer modulo for large values
  - For integer modulo semantics, use `u64` or `u32` types

- [ ] **No implicit truncation confusion**
  - Converting between `Field` and `u32/u64` truncates — verify this is intended

---

## 7. Logic Correctness

- [ ] **All private inputs are bound to a public commitment**
  - Every private witness should be "anchored" — either directly constrained, or constrained as part of a hash/commitment that appears as a public input
  - A private input that doesn't affect any public output is a dead variable (LE01)

- [ ] **Ownership is cryptographically bound**
  - "Proving you own key `sk`" means: `public_key = hash(sk)` AND `public_key` appears as a public input
  - Anti-pattern: `assert(hash(sk) == auth_hash)` with no binding between `user_id` and `sk`
  - Fix: `assert(hash(sk) == commitment); assert(commitment == user_commitment);`

- [ ] **No missing nonce in session-based proofs**
  - If a proof is meant to be single-use or session-specific, include a nonce/timestamp that makes it non-replayable
  - Anti-pattern: `fn main(sk: Field, action: pub Field)` — any captured proof can be replayed

---

## 8. Constraint Completeness

- [ ] **Every intermediate computation result is constrained to expected range**
  - Just because a value is computed doesn't mean it's constrained
  - Intermediate `Field` values from `unconstrained` computations need explicit assertions

- [ ] **No over-constraining that breaks valid use cases**
  - Check for constraints that legitimately reject valid inputs (OC01/OC02)
  - Example: using `u32` for a token ID that could legitimately exceed `2^32 - 1`

- [ ] **Impossibe constraint combinations**
  - Scan for `assert(x >= A)` paired with `assert(x <= B)` where `A > B`
  - These circuits are permanently unsatisfiable — no valid proof can ever be generated

---

## 9. Aztec / UTXO-Specific Patterns

- [ ] **Note commitments include all note fields**
  - `note_commitment = hash(value, salt, owner)` — all fields must participate in the commitment
  - Partial commitments allow note forgery

- [ ] **Nullifiers bind to both the note and the spender**
  - `nullifier = hash(note_hash, owner_secret)` — ties spending to a specific note AND owner

- [ ] **Private state changes that affect public state are mediated through constrained interfaces**
  - Unconstrained functions should not directly emit public events or update public storage
  - All private→public value flows must be constrained

- [ ] **Oracle/kernel return values are verified against a commitment or accumulator**
  - Never trust an oracle value that the prover can freely set

---

## 10. Code Review Process

- [ ] **Read every `fn main` parameter list for `pub` / non-`pub` assignments**
- [ ] **Trace every `unconstrained fn` call site** — what is asserted about the return value?
- [ ] **Check every `assert` for completeness** — does it actually prevent the attack?
- [ ] **Compare vulnerable vs patched diff** — is the fix minimal and correct?
- [ ] **Run `nargo check` / `nargo compile`** — circuit must compile without errors
- [ ] **Review Prover.toml** — are test inputs realistic? Do they exercise the vulnerability?
- [ ] **Manually write a malicious Prover.toml** for each vulnerability and confirm it produces a proof

---

## Red Flags (Immediate Investigation Required)

- Any `Field` parameter representing a bounded value (age, score, index, percentage)
- Any `unconstrained fn` whose return value is used in a condition without being re-verified
- `nullifier = hash(owner_secret)` — missing note-specific component
- `assert(x >= A); assert(x <= B)` where A and B values need cross-checking
- A private parameter that doesn't appear in any `assert` or hash computation
- `pub` on a parameter that sounds like private data (`secret`, `key`, `salt`, `seed`)
- Division or modulo operations where the denominator/divisor comes from user input

---

## Severity Classification

| Class | Severity | Impact |
|-------|----------|--------|
| Missing range check on critical input | Critical | Soundness break |
| Unconstrained hint abuse | Critical | Arbitrary proof forgery |
| Missing nullifier uniqueness | Critical | Double spend |
| Missing ownership binding | Critical | Unauthorized action |
| Unconstrained oracle | Critical | Price manipulation |
| Field subtraction underflow | Critical | Balance bypass |
| Accidental public input | High | Privacy break |
| Dead variable | High | Semantic mismatch |
| Replay attack | High | Auth bypass |
| Small domain hash | High | Brute-force |
| Over-constrained (DOS) | Medium | Availability |
| Cross-tx correlation | Medium | Linkability |

---

*See [TAXONOMY.md](../TAXONOMY.md) for full descriptions of each vulnerability class.*
*See [REFERENCES.md](REFERENCES.md) for background literature and tools.*
