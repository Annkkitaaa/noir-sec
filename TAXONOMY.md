# NoirSec Vulnerability Taxonomy

> Formal classification of security vulnerability classes in Noir ZK circuits.
> Version 1.0 — March 2026

---

## Overview

This taxonomy covers six vulnerability classes specific to Noir (Aztec's ZK DSL) and general ZK circuit development. Each class is ordered by typical severity and exploitability.

| ID   | Name                          | Class             | Severity | Detection Difficulty |
|------|-------------------------------|-------------------|----------|----------------------|
| UC01 | Missing Range Check           | Under-Constrained | Critical | Easy                 |
| UC02 | Unconstrained Hint Abuse      | Under-Constrained | Critical | Medium               |
| UC03 | Missing Nullifier Uniqueness  | Under-Constrained | Critical | Medium               |
| UC04 | Duplicate Witness Assignment  | Under-Constrained | High     | Medium               |
| OC01 | Unnecessary Range Restriction | Over-Constrained  | Medium   | Easy                 |
| OC02 | Impossible Constraint Combo   | Over-Constrained  | Medium   | Easy                 |
| PL01 | Accidental Public Input       | Privacy Leak      | High     | Easy                 |
| PL02 | Small Domain Hash Brute Force | Privacy Leak      | High     | Medium               |
| PL03 | Nullifier as Identity Leak    | Privacy Leak      | High     | Medium               |
| PL04 | Correlation via Public Outputs| Privacy Leak      | Medium   | Hard                 |
| FA01 | Integer Overflow in Field     | Field Arithmetic  | Critical | Medium               |
| FA02 | Division by Zero              | Field Arithmetic  | High     | Easy                 |
| FA03 | Modular Arithmetic Misuse     | Field Arithmetic  | High     | Medium               |
| LE01 | Intent vs Implementation      | Logic Error       | High     | Hard                 |
| LE02 | Missing Ownership Check       | Logic Error       | Critical | Medium               |
| LE03 | Replay Attack (No Nonce)      | Logic Error       | High     | Easy                 |
| AZ01 | Note Nullifier Reuse          | Aztec-Specific    | Critical | Medium               |
| AZ02 | Private-to-Public Leakage     | Aztec-Specific    | High     | Hard                 |
| AZ03 | Unconstrained Oracle Trust    | Aztec-Specific    | Critical | Medium               |
| AZ04 | Note Encryption Key Misuse    | Aztec-Specific    | High     | Medium               |
| AZ05 | Storage Slot Collision        | Aztec-Specific    | High     | Medium               |
| AZ06 | Private Function Sender Trust | Aztec-Specific    | Critical | Hard                 |
| CB01 | Unconstrained Struct Constraints | Compiler Bug   | High     | Hard                 |
| CB02 | Constraint Simplification Loop | Compiler Bug    | High     | Hard                 |
| CB03 | u128 Shift Field Overflow     | Compiler Bug      | High     | Medium               |

---

## Category 1: Under-Constrained (UC)

**Definition:** The circuit accepts proofs that violate the intended specification. The constraint system is too permissive — valid proofs can be generated for invalid witnesses.

**Why it's critical:** Under-constrained bugs break the soundness property of the proof system. An attacker can generate proofs of false statements.

**Noir-specific risk:** Noir's `Field` type has no implicit range constraints. Developers from typed languages may assume `Field` behaves like a bounded integer.

---

### UC01 — Missing Range Check

| Property | Value |
|----------|-------|
| **Severity** | Critical |
| **Detection Difficulty** | Easy |
| **CVSS-like Impact** | Proof forgery — prover proves false statements |

**Description:**
A witness value used in computation is declared as `Field` but not constrained to its expected semantic range. Since `Field` can represent any element in `[0, p-1]` (where `p ≈ 2^254` for BN254), the prover can substitute a field element outside the intended range.

**Root Cause:**
Noir's `Field` type is NOT a bounded integer — it is a raw prime-field element. Developers expecting bounded integers must use `u8`, `u16`, `u32`, or `u64`, which carry implicit range checks. Alternatively, explicit `assert(value < MAX)` is required for `Field` inputs.

**Impact:**
Prover can forge proofs for any value in `[0, p-1]`. For example, a 5-year-old can pass an age-check for `>= 18` by providing `age = p-1` (a valid field element larger than 18).

**Real-World Precedent:**
Aztec Connect `tree_index` bug — the Merkle tree leaf index was not constrained to 32 bits. Attackers could provide indices outside `[0, 2^32-1]`, enabling crafted nullifiers that allowed double-spending.
Reference: https://hackmd.io/@aztec-network/disclosure-of-recent-vulnerabilities

**Detection Method:**
- Static analysis: look for `Field` type parameters used in comparison/arithmetic without preceding `assert(val < MAX)` or range-checked conversion
- Manual review: trace all `Field` inputs to identify which carry semantic bounds
- `aztec-lint`: detects some range check patterns via static rules

---

### UC02 — Unconstrained Hint Abuse

| Property | Value |
|----------|-------|
| **Severity** | Critical |
| **Detection Difficulty** | Medium |
| **CVSS-like Impact** | Soundness break — hints accepted without verification |

**Description:**
An `unconstrained fn` computes a hint value outside the proof system (in native "Brillig" execution), but the constrained circuit does not adequately verify the hint's correctness. The prover controls what the unconstrained function returns and can return any value.

**Root Cause:**
This is **the signature Noir vulnerability class** — it does not exist in Circom (which has no concept of native execution hints). In Noir, `unconstrained fn` runs outside the circuit. Its return value is merely a witness hint that the prover provides. If the constrained code does not verify the relationship between the hint and other circuit variables via `assert`, the hint is trusted without proof.

The Noir documentation states: *"every resulting value must be involved in a later constraint against either one of the arguments of the call, or a constant."* Failing to do this breaks soundness.

**Impact:**
Attacker can substitute arbitrary values for unconstrained hints and generate valid proofs for false statements. Classic example: factorization circuit where the prover "proves" any number is composite by providing fake factors.

**Real-World Precedent:**
General class documented in OpenZeppelin's "Developer's Guide to Building Safe Noir Circuits" (Sept 2025). The Noir documentation warns specifically about this pattern.

**Detection Method:**
- Manual review: trace every `unsafe { unconstrained_fn(...) }` call and verify the return value appears in a subsequent `assert` that binds it to the original inputs
- Static analysis: `aztec-lint` has rules for detecting unconstrained values that are not constrained in the calling scope
- Differential testing: compare two executions that modify the unconstrained fn's return value — if both generate valid proofs, the hint is not adequately constrained

---

### UC03 — Missing Nullifier Uniqueness

| Property | Value |
|----------|-------|
| **Severity** | Critical |
| **Detection Difficulty** | Medium |
| **CVSS-like Impact** | Double-spend — same note spent with different nullifiers, or multiple notes share same nullifier |

**Description:**
A nullifier derivation does not include sufficient uniqueness-guaranteeing inputs. Two different notes (with the same value but different salts) can produce colliding nullifiers, or the same note can generate different valid nullifiers.

**Root Cause:**
Nullifiers in ZK systems must be: (1) unique per note, (2) deterministic (same note = same nullifier), (3) unlinkable to the original note. If the nullifier only hashes a subset of the note's components (missing the salt/nonce), multiple notes share the same nullifier.

**Impact:**
Double-spending or denial-of-service by nullifier collision. If nullifier(noteA) == nullifier(noteB), spending noteA nullifies noteB (or vice versa).

**Real-World Precedent:**
Aztec Connect double-spending vulnerability (nullifier binding was insufficient).

**Detection Method:**
- Manual review: verify nullifier derivation includes all unique note components (value + salt + owner + nonce)
- Construct two notes with the same value but different salts — verify they produce different nullifiers

---

### UC04 — Duplicate Witness Assignment

| Property | Value |
|----------|-------|
| **Severity** | High |
| **Detection Difficulty** | Medium |
| **CVSS-like Impact** | Authentication bypass — single secret satisfies multiple independent requirements |

**Description:**
Two logically independent private witness variables are given the same value in the circuit, allowing a single secret to satisfy what should be two distinct requirements. The circuit passes even though only one independent secret exists.

**Root Cause:**
Developer accidentally uses the same variable (or equivalent value) in two constraint branches that should each require independent witnesses. The missing constraint is `assert(secret1 != secret2)`.

**Impact:**
A user with ONE credential can satisfy a 2-of-2 requirement meant to require TWO independent credentials.

**Detection Method:**
- Manual review: identify pairs of private witnesses that should be independent and verify they have a `!=` constraint between them
- Symbolic execution: test whether the circuit can be satisfied with `witness_a == witness_b`

---

## Category 2: Over-Constrained (OC)

**Definition:** The circuit rejects valid proofs — the constraint system is too strict. While less dangerous than under-constrained (no false proofs), over-constrained circuits cause denial-of-service for legitimate users.

---

### OC01 — Unnecessary Range Restriction

| Property | Value |
|----------|-------|
| **Severity** | Medium |
| **Detection Difficulty** | Easy |
| **CVSS-like Impact** | DoS — valid inputs rejected |

**Description:**
A value is range-checked more tightly than necessary, rejecting semantically valid inputs. For example, using `u32` for a token ID that the application layer treats as `u64`.

**Root Cause:**
Developer chose a type that is too narrow for the semantic domain, or added an explicit `assert(val < N)` where N is smaller than the actual valid range.

**Detection Method:**
- Compare type used in circuit vs. type used in the application layer / smart contract
- Test with values at the boundary of the type (e.g., `2^32 - 1` vs `2^32`)

---

### OC02 — Impossible Constraint Combination

| Property | Value |
|----------|-------|
| **Severity** | Medium |
| **Detection Difficulty** | Easy |
| **CVSS-like Impact** | Total DoS — circuit is ALWAYS unsatisfiable |

**Description:**
Two or more constraints directly contradict each other, making the circuit unsatisfiable for any input. The circuit can never generate a valid proof.

**Root Cause:**
Developer introduced conflicting requirements, often during iterative development where one constraint was added without checking compatibility with existing constraints.

**Detection Method:**
- Run `nargo execute` with multiple valid-looking inputs — all should fail with constraint errors
- Formal verification: check for unsatisfiability of the constraint system (NAVe)

---

## Category 3: Privacy Leaks (PL)

**Definition:** The zero-knowledge property is broken — an observer can learn information about private inputs from the proof or its public outputs.

---

### PL01 — Accidental Public Input

| Property | Value |
|----------|-------|
| **Severity** | High |
| **Detection Difficulty** | Easy |
| **CVSS-like Impact** | Complete secret disclosure — private value visible in proof |

**Description:**
A private value is accidentally marked `pub` in the function signature, making it part of the proof's public inputs. The verifier (and anyone else) can read the value directly.

**Root Cause:**
In Noir, `fn main(secret: pub Field)` marks `secret` as a public input. Without `pub`, parameters are private by default. A developer reviewing the signature may add `pub` to the wrong parameter.

**Real-World Precedent:**
Occurs during refactoring — a parameter intended to be private gets `pub` added when another parameter nearby is made public.

**Detection Method:**
- Static analysis (trivial): grep for `pub` on parameters that should be private
- `aztec-lint`: has visibility rules

---

### PL02 — Small Domain Hash Brute Force

| Property | Value |
|----------|-------|
| **Severity** | High |
| **Detection Difficulty** | Medium |
| **CVSS-like Impact** | Private value recovery via offline brute force |

**Description:**
A hash of a private value is published as a public output, but the private value comes from a domain small enough to brute-force. An attacker enumerates all possible preimages, hashes each, and matches against the published hash.

**Root Cause:**
The developer correctly uses a hash commitment, but underestimates the domain size of the private value (e.g., ages 0-150, vote choices 1-5, credit scores 300-850).

**Real-World Precedent:**
OpenZeppelin "Developer's Guide to Building Safe Noir Circuits" (Sept 2025) — explicitly describes this as a Noir-specific pattern. Common in voting and credential systems.

**Detection Method:**
- Identify public outputs that are hashes of private values
- Estimate the domain size — if brute-forceable in reasonable time, flag as PL02
- The `privacy_leak_fuzzer.py` detection script models this

---

### PL03 — Nullifier as Identity Leak

| Property | Value |
|----------|-------|
| **Severity** | High |
| **Detection Difficulty** | Medium |
| **CVSS-like Impact** | Sender identity revealed — de-anonymization |

**Description:**
A nullifier is derived purely from `hash(sender_address)`, preventing double-spending but simultaneously exposing the sender's identity. Anyone with a list of known addresses can match nullifiers to senders.

**Root Cause:**
The developer correctly includes user identity in the nullifier to prevent replay, but doesn't include any note-specific entropy. A proper nullifier should bind to the specific note being spent.

**Impact:**
All transactions from the same sender are linkable via their deterministic nullifier.

**Detection Method:**
- Manual review: check nullifier derivation includes note-specific randomness (salt/nonce), not just sender identity
- Compare two transactions from the same sender — if nullifiers are predictably derived, flag

---

### PL04 — Correlation via Public Outputs

| Property | Value |
|----------|-------|
| **Severity** | Medium |
| **Detection Difficulty** | Hard |
| **CVSS-like Impact** | Probabilistic de-anonymization via cross-transaction analysis |

**Description:**
Individual public outputs appear safe, but combining multiple public outputs across transactions allows an observer to reconstruct private information through correlation.

**Root Cause:**
Privacy analysis is done per-field rather than holistically. The combination of (category + timestamp + amount) may uniquely identify a user even when each field alone is anonymous.

**Detection Method:**
- Enumerate all public output fields and test all k-combinations for information leakage
- Statistical correlation analysis (see `privacy_leak_fuzzer.py`)
- Threat model analysis: who is the attacker, what auxiliary information do they have?

---

## Category 4: Field Arithmetic Pitfalls (FA)

**Definition:** The developer makes assumptions about arithmetic that hold for integers but not for prime-field elements.

---

### FA01 — Integer Overflow in Field

| Property | Value |
|----------|-------|
| **Severity** | Critical |
| **Detection Difficulty** | Medium |
| **CVSS-like Impact** | Balance bypass — arbitrary overdraft or inflation |

**Description:**
The developer assumes subtraction/addition behaves like bounded integer arithmetic. In a prime field, `a - b` always produces a valid field element — there is no underflow. If `a < b`, the result is `p - (b - a)`, a large positive value that passes `result >= 0` style checks.

**Root Cause:**
The BN254 field prime `p ≈ 2^254` means field subtraction wraps modulo p. Expressions like `assert(balance - withdrawal != 0)` do NOT check that the balance is sufficient.

**Real-World Precedent:**
The most common ZK-specific arithmetic vulnerability. Documented in multiple ZK security surveys (ZKAP, SoK SNARK security). Analogous to Tornado Cash note value overflow.

**Detection Method:**
- Pattern match: `a - b` on `Field` type without preceding `assert(a >= b)` using bounded types
- Differential testing: provide `withdrawal > balance`, observe if proof succeeds

---

### FA02 — Division by Zero Non-Constraint

| Property | Value |
|----------|-------|
| **Severity** | High |
| **Detection Difficulty** | Easy |
| **CVSS-like Impact** | Arbitrary value acceptance — any claim satisfies zero-denominator constraint |

**Description:**
A circuit performs a division or multiplicative inverse operation without asserting the divisor is non-zero. When the denominator is zero, the product `0 * result == 0` is satisfied by ANY value of `result`, allowing the prover to claim any quotient.

**Root Cause:**
In field arithmetic, `a * 0 == 0` for any `a`. A circuit verifying `result * divisor == dividend` with `divisor = 0` and `dividend = 0` accepts any `result`.

**Detection Method:**
- Pattern match: look for `* divisor == dividend` patterns without `assert(divisor != 0)`
- Fuzz with `divisor = 0`

---

### FA03 — Modular Arithmetic Misuse

| Property | Value |
|----------|-------|
| **Severity** | High |
| **Detection Difficulty** | Medium |
| **CVSS-like Impact** | Shard/routing bypass — attacker maps to any shard |

**Description:**
Field division (`/`) and derived modulo operations compute field-arithmetic results, not integer results. For field elements near the prime `p`, `a / b` computes `a * b^(-1) mod p`, which differs fundamentally from integer division. A developer expecting integer behavior may write circuits that are trivially exploitable.

**Root Cause:**
Developers familiar with integer-based languages expect `/` to be integer division. In Noir, `/` on `Field` type is field division (multiplication by modular inverse).

**Detection Method:**
- Pattern match: `/` operator on `Field` type
- Test with field elements near `p` to observe unexpected results

---

## Category 5: Logic Errors (LE)

**Definition:** The circuit's constraints correctly implement what the developer wrote, but what the developer wrote does not match the specification.

---

### LE01 — Intent vs Implementation Mismatch

| Property | Value |
|----------|-------|
| **Severity** | High |
| **Detection Difficulty** | Hard |
| **CVSS-like Impact** | Proof forgery using only public information |

**Description:**
The circuit verifies a weaker property than intended. For example, a circuit meant to prove "you own NFT #X" actually proves "you know the public metadata of NFT #X" — anyone can generate a valid proof.

**Root Cause:**
Private inputs appear in the function signature but are never actually used in constraints. The developer may have planned to add them later, or removed constraints during debugging and forgot to restore them.

**Detection Method:**
- Static analysis: identify private inputs that do not appear in any `assert` statement
- `aztec-lint`: has dead variable warnings
- Attempt to generate a proof using only public information

---

### LE02 — Missing Ownership Check

| Property | Value |
|----------|-------|
| **Severity** | Critical |
| **Detection Difficulty** | Medium |
| **CVSS-like Impact** | Authentication bypass — prove ownership of another user's asset |

**Description:**
The circuit proves knowledge of a secret (e.g., `hash(sk) == auth_hash`) but does not bind the secret key to the specific identity (`user_id`) being authorized. Any valid `(sk, auth_hash)` pair can authorize any `user_id`.

**Root Cause:**
OpenZeppelin's "Developer's Guide" (Sept 2025) describes this as a top-tier Noir vulnerability pattern. The developer correctly hashes the secret key but forgets to create a constraint linking the key to the claimed identity.

**Real-World Precedent:**
Described explicitly in OpenZeppelin's Noir security guide as a common authentication circuit error.

**Detection Method:**
- Manual review: verify that authorization circuits bind identity parameters to secret-key parameters via constraints
- Test: does the proof remain valid when `user_id` is swapped to a different user's ID?

---

### LE03 — Replay Attack (No Nonce)

| Property | Value |
|----------|-------|
| **Severity** | High |
| **Detection Difficulty** | Easy |
| **CVSS-like Impact** | Replay — same proof submitted multiple times |

**Description:**
An authentication or authorization proof does not include a nonce, timestamp, or other uniqueness-guaranteeing value. The same proof can be resubmitted at any future time.

**Root Cause:**
Developers focus on the knowledge proof itself and forget that the proof must also be bound to a specific context (session, transaction, block).

**Detection Method:**
- Manual review: check all authentication circuits for a nonce or challenge parameter
- Submit the same proof twice to the verifying application

---

## Category 6: Aztec-Specific (AZ)

**Definition:** Vulnerability patterns unique to the Aztec network's private execution model, UTXO-based note system, and oracle architecture.

**Note on Aztec.nr:** The challenges in this category simulate Aztec's patterns in vanilla Noir. In production Aztec contracts, these patterns would use `aztec-nr` primitives (`NoteInterface`, `context`, `oracle`). The core vulnerability is the same; the Noir code demonstrates the constraint-level issue.

---

### AZ01 — Note Nullifier Reuse

| Property | Value |
|----------|-------|
| **Severity** | Critical |
| **Detection Difficulty** | Medium |
| **CVSS-like Impact** | Double-spend — multiple notes share one nullifier |

**Description:**
In Aztec's UTXO model, notes are "spent" by publishing their nullifier to a global nullifier tree. If nullifier derivation doesn't bind to the specific note being spent (missing the note hash), different notes produce the same nullifier — or the same note can be spent in ways that are not prevented by the nullifier set.

**Root Cause:**
Weak nullifier: `nullifier = hash(owner_secret)` rather than `nullifier = hash(owner_secret, note_hash)`. Multiple notes owned by the same person share identical nullifiers.

**Real-World Precedent:**
This mirrors the actual Aztec Connect double-spending bug — the nullifier derivation was insufficiently binding.
Reference: https://hackmd.io/@aztec-network/disclosure-of-recent-vulnerabilities

**Detection Method:**
- Manual review: verify nullifier includes note-specific entropy (note_hash, salt)
- Create two notes with the same owner but different values/salts — verify nullifiers differ

---

### AZ02 — Private-to-Public State Leakage

| Property | Value |
|----------|-------|
| **Severity** | High |
| **Detection Difficulty** | Hard |
| **CVSS-like Impact** | De-anonymization via transaction graph analysis |

**Description:**
When an Aztec contract transitions data from private to public state, insufficient anonymization allows tracing. The public commitment reveals a deterministic link to the private sender across transactions.

**Root Cause:**
The private-state commitment is computed without sufficient randomness, making the public representation predictable and linkable across multiple unshielding operations by the same user.

**Detection Method:**
- Analyze `user_commitment` derivation — does it include a fresh random salt per transaction?
- Correlate public commitments across multiple transactions from the same simulated user

---

### AZ03 — Unconstrained Oracle Trust

| Property | Value |
|----------|-------|
| **Severity** | Critical |
| **Detection Difficulty** | Medium |
| **CVSS-like Impact** | False state injection — malicious sequencer poisons oracle data |

**Description:**
Aztec contracts use unconstrained oracle calls to read external state (token prices, Merkle roots, block timestamps). If the oracle result is used directly without verification against a trusted commitment or signature, a malicious sequencer can inject false data.

**Root Cause:**
This is a combination of UC02 (unconstrained hint abuse) and the Aztec-specific oracle architecture. The prover (sequencer) controls oracle execution. If the circuit trusts the oracle return value without verification, the sequencer can lie about state.

**Real-World Precedent:**
Documented in Aztec's sequencer security model. Related to the general unconstrained hint problem, but amplified in Aztec because the sequencer is the prover for all private transactions.

**Detection Method:**
- Manual review: every `oracle::get_*` call should be followed by verification against a known-good commitment (Merkle root, signature, etc.)
- Mock the oracle to return false data — verify the proof still accepts it in the vulnerable circuit

---

### AZ04 -- Note Encryption Key Misuse

| Property | Value |
|----------|-------|
| **Severity** | High |
| **Detection Difficulty** | Medium |
| **CVSS-like Impact** | Confidentiality failure -- notes encrypted to wrong key; intended recipient cannot decrypt |

**Description:**
A note encryption circuit uses the sender's key (rather than the recipient's public key) when computing the encrypted note commitment. Any party with access to the sender's key can decrypt all outgoing notes, violating the recipient's expected privacy.

**Root Cause:**
Confusion between sender and recipient key roles in note construction. The circuit correctly verifies the encryption commitment, but uses the wrong key as input to the hash. This is a semantic error rather than a missing constraint.

**Detection Method:**
- Manual review: trace which key is used in the encrypted note hash and verify it is the recipient's public key
- Check that the sender key is verified but not used as the encryption key

---

### AZ05 -- Storage Slot Collision

| Property | Value |
|----------|-------|
| **Severity** | High |
| **Detection Difficulty** | Medium |
| **CVSS-like Impact** | State corruption -- two storage variables share the same slot; writing one overwrites the other |

**Description:**
Two distinct storage variables (e.g., balance and allowance) are assigned to storage slots computed with the same formula and index, causing them to occupy the same slot. Any write to one variable overwrites the other.

**Root Cause:**
Each storage variable must be assigned a unique slot index when calling `pedersen_hash([contract_address, variable_index])`. Using the same index for different variables is a logic error that the type system does not catch.

**Detection Method:**
- Audit all storage slot computations and verify each uses a unique index constant
- Check for duplicated slot formulas in the circuit source

---

### AZ06 -- Private Function Sender Trust

| Property | Value |
|----------|-------|
| **Severity** | Critical |
| **Detection Difficulty** | Hard |
| **CVSS-like Impact** | Authorization bypass -- sequencer/prover can impersonate any authorized sender |

**Description:**
A private function uses an unconstrained oracle to retrieve the caller's identity (`msg.sender`). The returned value is used in authorization logic but is never constrained against the function's public `authorized_sender` parameter. A malicious sequencer can return any value from the oracle, effectively impersonating any authorized party.

**Root Cause:**
This is a UC02 (unconstrained hint abuse) instance specific to Aztec's sender model. The sequencer controls oracle execution; any oracle value that is not cryptographically bound to a public commitment is attacker-controlled.

**Detection Method:**
- Identify all `oracle::get_sender()` / `oracle::get_msg_sender()` calls
- Verify the returned value is asserted against a public `authorized_sender` commitment
- The commitment must be the hash of a secret only the authorized sender knows (e.g., their private key)

---

## Category 7: Compiler Bugs (CB)

**Definition:** Security vulnerabilities introduced by the Noir compiler itself, not by developer error. The source code correctly specifies the intended behavior, but the compiled ACIR circuit does not enforce it.

**Why it matters:** Compiler bugs are more dangerous than developer bugs because source code review appears correct. The compiled artifact is weaker than the source implies.

**Key principle:** The compiler is part of the trusted computing base. Production circuits should be audited at the ACIR level in addition to source level.

---

### CB01 -- Unconstrained Function Generating Hidden Constraints

| Property | Value |
|----------|-------|
| **Severity** | High |
| **Detection Difficulty** | Hard |
| **Fixed In** | Noir v0.28+ |
| **NoirSec Mapping** | UC02 |
| **Noir Issue** | #4442 |

**Description:**
When a struct containing arrays is passed by value into an `unconstrained` function and iterated over, the Noir compiler (pre-v0.28) generated ACIR constraints for code intended to run only in Brillig mode. Hidden constraints appear in the circuit that are invisible to source-level review.

**Detection Method:**
Compare gate counts with and without the unconstrained function body. Any gate count difference signals constraint leakage from Brillig into ACIR.

---

### CB02 -- Constraint Simplification Removing Loop Assertions

| Property | Value |
|----------|-------|
| **Severity** | High |
| **Detection Difficulty** | Hard |
| **Fixed In** | Noir v1.x |
| **NoirSec Mapping** | UC category |
| **Noir Issues** | #9806, #9857 |

**Description:**
The Noir SSA optimizer could simplify away assertions inside loops that involve the loop induction variable. Security-critical range checks in loops were silently removed from the compiled ACIR.

**Detection Method:**
Audit ACIR artifacts directly; compare assertion counts to expected values. Check the Noir CHANGELOG before auditing to identify affected compiler versions.

---

### CB03 -- u128 Left Bit Shift Field Overflow

| Property | Value |
|----------|-------|
| **Severity** | High |
| **Detection Difficulty** | Medium |
| **Fixed In** | Noir v1.x |
| **NoirSec Mapping** | FA01 |
| **Noir Issue** | #9723 |

**Description:**
Left bit shifts on `u128` values could overflow the BN254 scalar field modulus, producing field elements arithmetically incorrect as 128-bit integers. Circuits using large u128 shifts for cryptographic operations could accept incorrect results.

**Detection Method:**
Test shift operations with values near 2^64, 2^96, 2^127. Verify gate counts include range constraint gates for large shift results.

---

## References

See [resources/REFERENCES.md](resources/REFERENCES.md) for full citations.

Key sources informing this taxonomy:
- OpenZeppelin: "A Developer's Guide to Building Safe Noir Circuits" (Sept 2025)
- Nethermind: "Our First Deep Dive into Noir" (July 2025)
- Aztec Connect Vulnerability Disclosure (HackMD)
- NAVe: Formal Noir ACIR Verifier (arxiv 2601.09372, Jan 2026)
- SoK: "What Don't We Know? Understanding Security Vulnerabilities in SNARKs" (arxiv 2402.15293)
- ZKAP: "Practical Security Analysis of ZK Proof Circuits" (eprint 2023/190)
