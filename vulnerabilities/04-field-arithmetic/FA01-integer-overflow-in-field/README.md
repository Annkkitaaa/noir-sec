# FA01 — Integer Overflow in Field

| Property | Value |
|----------|-------|
| **Difficulty** | Medium |
| **Category** | Field Arithmetic (FA) |
| **Severity** | Critical |
| **Root Cause** | Field subtraction wraps modulo `p` — no underflow exists in a prime field |

---

## Scenario

A ZK token contract allows users to prove they have sufficient balance to cover a withdrawal. The circuit verifies the balance check and, if valid, the on-chain contract releases the funds.

The circuit is in [vulnerable/src/main.nr](vulnerable/src/main.nr). You have a balance of 100 tokens. Can you prove a withdrawal of 1000?

---

## Your Challenge

1. Read [vulnerable/src/main.nr](vulnerable/src/main.nr) — trace the arithmetic
2. Understand why `assert(remaining != 0)` is insufficient
3. Craft a `Prover.toml` that proves `withdrawal > balance` is valid
4. Check against [exploit/exploit.sh](exploit/exploit.sh)
5. Fix the circuit — see [patched/src/main.nr](patched/src/main.nr)

---

## Hints

<details>
<summary>Hint 1 — Mild</summary>

In mathematics, integers can be negative. In a prime field, all elements are in `[0, p-1]`. What happens when you compute `100 - 1000` in the BN254 field?
</details>

<details>
<summary>Hint 2 — Moderate</summary>

`100 - 1000 (mod p) = p - 900` which is approximately `2^254`. This is a valid, non-zero field element. So `assert(remaining != 0)` passes for **any** withdrawal, even if it exceeds the balance.
</details>

<details>
<summary>Hint 3 — Strong</summary>

The correct check is `assert(withdrawal <= balance)` using `u64` types (integer comparison), not `Field` types (field arithmetic). With `u64`, `1000 <= 100` is false and the proof fails.
</details>

---

## The Bug

<details>
<summary>Spoiler: Full Explanation</summary>

### The field arithmetic trap

The BN254 scalar field has prime:
```
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

In this field, **every** arithmetic operation produces a valid element in `[0, p-1]`. There are no negative numbers, no overflow, no underflow. Subtraction wraps modulo `p`:

```
balance - withdrawal (mod p)
= 100 - 1000 (mod p)
= p - 900
= 21888242871839275222246405745257275088548364400416034343698204186575808494717
```

This is a valid, huge, non-zero field element. The assertion `assert(remaining != 0)` passes.

### Why this happens
The developer assumed `balance - withdrawal >= 0` semantics from integer arithmetic. In a prime field, **this concept doesn't exist**. The result is always "valid" regardless of the relative magnitude.

### The fix
```noir
// Wrong: Field arithmetic wraps
let remaining = balance - withdrawal;
assert(remaining != 0);

// Correct: u64 integer comparison
assert(withdrawal <= balance);
```
Using `u64` enforces bounded integer arithmetic where `1000 <= 100` is correctly false.

### Historical note
This vulnerability class has appeared in multiple real-world ZK systems. It's analogous to integer overflow vulnerabilities in traditional software — except that in ZK circuits, there's no "crash" to signal the error. The proof silently accepts invalid witnesses.

</details>

---

## Running the Exploit

```bash
bash vulnerabilities/04-field-arithmetic/FA01-integer-overflow-in-field/exploit/exploit.sh
```

---

---

## Impact Assessment

**Severity: Critical**

**Justification:** Using `Field` arithmetic for token balances means subtraction wraps modulo the BN254 prime (p ~ 2^254) rather than reverting. An attacker with balance=1 can withdraw p-1 tokens: `1 - (p-1) = 2 mod p`, which passes the `balance >= withdrawal` check. This enables unlimited token minting from essentially nothing. In a DeFi protocol, any account with a minimal balance can drain the entire treasury. The attack requires no privileged access and is deterministic given knowledge of the field modulus.

**Attack Complexity:** Low -- requires knowledge of the BN254 field modulus (public); the overflow is formulaic

**Prerequisites:** A minimal balance (even 1 token) to initiate the attack; no other special access required

**Affected Components:** Token balance circuits, lending protocols, any circuit performing arithmetic comparisons on `Field`-typed financial values

---

---

## Real-World Precedent

**Aztec Connect BigField CRT overflow (PM-02, 2021):** An overflow in the quotient term of a BigField CRT decomposition allowed proving incorrect arithmetic equations -- the same field overflow pattern FA01 demonstrates.

**Noir compiler u128 bit shift (PM-08, 2024):** Left bit shifts on u128 values could overflow into the BN254 field modulus, silently producing incorrect results in circuits relying on large-integer arithmetic.

See [POSTMORTEMS.md](../../../resources/POSTMORTEMS.md#pm-02-aztec-connect----bigfield-crt-overflow) for PM-02 and PM-08 details.

---

## References

- [OpenZeppelin: Safe Noir Circuits Guide](https://www.openzeppelin.com/news/developer-guide-to-building-safe-noir-circuits) — "Finite Field Arithmetic Pitfalls"
- [SoK: Security Vulnerabilities in SNARKs](https://arxiv.org/pdf/2402.15293)
- [ZKAP: Practical Security Analysis of ZK Proof Circuits](https://eprint.iacr.org/2023/190)
