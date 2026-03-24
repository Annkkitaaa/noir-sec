# UC01 — Missing Range Check

| Property | Value |
|----------|-------|
| **Difficulty** | Easy |
| **Category** | Under-Constrained (UC) |
| **Severity** | Critical |
| **Root Cause** | `Field` type has no implicit range constraint |

---

## Scenario

You are auditing an age-gated content platform built on Noir. Users prove they are old enough to access restricted content by generating a ZK proof. The platform's verifier checks the proof — it does not see the user's actual age, only that the proof is valid.

The circuit is in [vulnerable/src/main.nr](vulnerable/src/main.nr). A new user is 5 years old but wants to access adult content (minimum age: 18). Can they generate a valid proof?

---

## Your Challenge

1. Read [vulnerable/src/main.nr](vulnerable/src/main.nr) — identify the vulnerability
2. Write an exploit: craft a `Prover.toml` that generates a valid proof despite the user being 5
3. Check your exploit against [exploit/exploit.sh](exploit/exploit.sh)
4. Write a fix — modify the circuit to reject invalid witnesses
5. Check your fix against [patched/src/main.nr](patched/src/main.nr)

---

## Hints

<details>
<summary>Hint 1 — Mild (click to reveal)</summary>

What exactly is the Noir `Field` type? What values can it hold?
Check the [Noir docs on Field type](https://noir-lang.org/docs/noir/concepts/data_types/field).

</details>

<details>
<summary>Hint 2 — Moderate (click to reveal)</summary>

The BN254 scalar field prime is:
```
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```
`Field` can hold any value in `[0, p-1]`. What is `p-1`? Is it >= 18?

</details>

<details>
<summary>Hint 3 — Strong (click to reveal)</summary>

Try this `Prover.toml`:
```toml
age = "21888242871839275222246405745257275088548364400416034343698204186575808495616"
min_age = "18"
```
`p-1` is a valid `Field` element. As an integer, `p-1 >> 18`, so `age >= min_age` passes.
The developer intended `age` to be a human age (0–150), but any field element works.

</details>

---

## The Bug

<details>
<summary>Spoiler: Full Explanation (click to reveal)</summary>

### What the developer intended
```
Spec: 0 <= age <= 150 AND age >= min_age
```

### What the circuit actually checks
```
age >= min_age
(where age can be ANY value in [0, p-1])
```

### Why it fails
Noir's `Field` type represents an element of the BN254 scalar field — any integer in `[0, p-1]` where `p ≈ 2^254`. There is **no implicit range constraint**. A malicious prover supplies `age = p-1`, which is a valid field element. Since `p-1` is astronomically larger than 18, the comparison passes.

### The fix
Use `u8` (range `[0, 255]`) instead of `Field`. The `u8` type carries an **implicit range check** that the ZK proof system verifies automatically. Any value outside `[0, 255]` causes the proof to fail.

```noir
// Vulnerable
fn main(age: Field, min_age: pub Field)

// Patched
fn main(age: u8, min_age: pub u8)
```

**General rule:** Never use `Field` for values that have a semantic bound. Use the narrowest integer type that fits the domain.

</details>

---

## Running the Exploit

```bash
# From repo root (run in WSL on Windows)
bash vulnerabilities/01-under-constrained/UC01-missing-range-check/exploit/exploit.sh
```

---

---

## Impact Assessment

**Severity: Critical**

**Justification:** An attacker can bypass any age, balance, or membership threshold by providing a field element (up to 2^254) instead of a bounded integer. In this age-gated platform, submitting `age = p-1` (the BN254 prime minus 1) is a valid `Field` value that passes because no range constraint exists. The circuit accepts the proof as valid. The attack requires no special access or cryptographic knowledge -- only the ability to craft a Prover.toml with a large field element.

**Attack Complexity:** Low -- requires no cryptographic breaks; just provide a large field element as the private input

**Prerequisites:** None -- attacker only needs the ability to submit a proof to the verifier

**Affected Components:** Any circuit accepting user-supplied numeric values as `Field` type without explicit range constraints (age gates, balance checks, eligibility thresholds)

---

---

## Real-World Precedent

**Aztec Connect tree index bug (PM-01, 2021):** A missing 32-bit range constraint on a note tree index in Aztec Connect allowed crafted proofs to reference notes outside valid positions, enabling potential double-spending.

**RISC Zero ExpandU32 (PM-04, 2024):** A 32-bit decomposition circuit lacked range constraints on its component limbs, allowing incorrect decompositions to be proven valid.

See [POSTMORTEMS.md](../../../resources/POSTMORTEMS.md#pm-01-aztec-connect----tree-index-range-constraint-bug) for full details on PM-01 and PM-04.

---

## References

- [Aztec Connect vulnerability disclosure](https://hackmd.io/@aztec-network/disclosure-of-recent-vulnerabilities) — the `tree_index` missing 32-bit range constraint
- [OpenZeppelin: Developer's Guide to Building Safe Noir Circuits](https://www.openzeppelin.com/news/developer-guide-to-building-safe-noir-circuits) — "Finite Field Arithmetic Pitfalls"
- [Noir docs: Field type](https://noir-lang.org/docs/noir/concepts/data_types/field)
- [SoK: Security Vulnerabilities in SNARKs](https://arxiv.org/pdf/2402.15293) — Section on range constraints
