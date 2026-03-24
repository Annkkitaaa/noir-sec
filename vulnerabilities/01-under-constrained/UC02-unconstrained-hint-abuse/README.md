# UC02 — Unconstrained Hint Abuse

| Property | Value |
|----------|-------|
| **Difficulty** | Medium |
| **Category** | Under-Constrained (UC) |
| **Severity** | Critical |
| **Root Cause** | Unconstrained function hint not verified in constrained code |

> **This is the signature Noir vulnerability class.** It does not exist in Circom (no native execution hints). Every Noir auditor must master this pattern.

---

## Scenario

A ZK proof system allows users to prove a number `n` is **composite** (not prime) by providing its factors. This might be used to:
- Prove an RSA modulus `N = p*q` has exactly two large factors
- Exclude prime numbers from an asset pool
- Verify factorization in a ZK game

The circuit uses an `unconstrained fn` to **compute** the factors natively (outside the proof), then checks them inside the circuit.

The circuit is in [vulnerable/src/main.nr](vulnerable/src/main.nr). Can you prove that the prime number **7** is composite?

---

## Your Challenge

1. Read [vulnerable/src/main.nr](vulnerable/src/main.nr) — understand what the unconstrained function does
2. Identify what constraint is missing
3. Prove that n=7 (a prime) is "composite" using the vulnerable circuit
4. Check your exploit against [exploit/exploit.sh](exploit/exploit.sh)
5. Write a fix — add the missing constraint
6. Check against [patched/src/main.nr](patched/src/main.nr)

---

## Background: Unconstrained Functions in Noir

In Noir, `unconstrained fn` executes in **Brillig** — native computation outside the ZK proof circuit. It functions as a **hint provider**: the prover runs it to compute a witness value, then the constrained circuit verifies the value.

```noir
unconstrained fn compute_something(x: Field) -> Field {
    // Runs outside the circuit — prover controls this
    expensive_native_computation(x)
}

fn main(x: Field) {
    // Safety: result verified against x below
    let hint = unsafe { compute_something(x) };
    assert(hint * hint == x); // <- This is what keeps it honest
}
```

**Key rule:** Every value returned by an unconstrained function must be constrained against the function's input arguments or known constants. If this rule is violated, the prover can return ANY value as the hint.

---

## Hints

<details>
<summary>Hint 1 — Mild</summary>

In the vulnerable circuit, `factorize(n)` returns `[f0, f1]`. The circuit checks:
- `f0 > 1`
- `f1 > 1`

What crucial relationship between `f0`, `f1`, and `n` is NOT checked?

</details>

<details>
<summary>Hint 2 — Moderate</summary>

The prover controls what `factorize()` returns. They can make it return `[2, 3]` for any input `n`, regardless of what `n` actually is. Both `2 > 1` and `3 > 1` are true, so both asserts pass.

What one-line assertion would prevent this?

</details>

<details>
<summary>Hint 3 — Strong</summary>

The missing constraint is:
```noir
assert(factors[0] * factors[1] == n);
```
Without it, the prover can prove any number — including primes — is composite.
</details>

---

## The Bug

<details>
<summary>Spoiler: Full Explanation</summary>

### What the developer intended
```
Spec:
  factors[0] > 1
  factors[1] > 1
  factors[0] * factors[1] == n   ← MISSING
```

### What the circuit actually checks
```
factors[0] > 1
factors[1] > 1
(no multiplication constraint)
```

### The exploit
The prover executes `factorize(7)` in Brillig (outside the circuit). They modify it to return `[2, 3]` regardless of `n`. The constrained circuit then checks:
- `2 > 1` ✓
- `3 > 1` ✓
- ~~`2 * 3 == 7`~~ (missing — never checked)

**The proof is valid.** The prime 7 is "proven" composite.

### The fix
```noir
assert(factors[0] * factors[1] == n);
```
This one line binds the hint to the actual input, preventing the prover from lying.

### Noir-specific note
This vulnerability class — "unconstrained hint abuse" — is **unique to Noir**. Circom circuits are entirely constraint-based with no native execution. Noir introduced `unconstrained fn` for performance (expensive computations done natively, verified cheaply), but this creates a new attack surface that every Noir auditor must watch for.

</details>

---

## Running the Exploit

```bash
# From repo root (WSL on Windows)
bash vulnerabilities/01-under-constrained/UC02-unconstrained-hint-abuse/exploit/exploit.sh
```

---

---

## Impact Assessment

**Severity: Critical**

**Justification:** The prover controls unconstrained (Brillig) function return values entirely, bypassing soundness. Returning `[2, 3]` as factors for the prime 7 satisfies both `> 1` assertions and produces a valid proof that 7 is composite. The verifier accepts a false statement as proven. Any circuit that computes witness hints in unconstrained functions and fails to fully constrain the result is vulnerable -- the hint is a suggestion the prover can ignore.

**Attack Complexity:** Low -- the prover provides any values from the unconstrained function; no cryptographic analysis needed

**Prerequisites:** None -- the attack is possible for any input to the circuit

**Affected Components:** Any circuit using `unconstrained fn` to compute hints that are not fully verified by subsequent constraints

---

---

## Real-World Precedent

**Noir compiler issue #4442 (PM-06, 2023):** Passing structs by value into unconstrained functions silently generated ACIR constraints for code that should have run only in Brillig. This blurred the constrained/unconstrained boundary -- the same boundary UC02 demonstrates is critical for soundness.

See [POSTMORTEMS.md](../../../resources/POSTMORTEMS.md#pm-06-noir-compiler----unconstrained-function-generating-constraints-issue-4442) for full details.

---

## References

- [Noir docs: Unconstrained functions](https://noir-lang.org/docs/noir/concepts/unconstrained)
- [OpenZeppelin: Developer's Guide to Safe Noir Circuits](https://www.openzeppelin.com/news/developer-guide-to-building-safe-noir-circuits) — "Logical Constraint Errors"
- [Nethermind: First Deep Dive into Noir](https://www.nethermind.io/blog/our-first-deep-dive-into-noir-what-zk-auditors-learned)
