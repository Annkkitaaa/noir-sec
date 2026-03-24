# UC02 Near-Miss: Non-Zero Check Allows Trivial Factorization

**Pattern:** `factors != 0` check instead of `factors > 1` allows the trivial factor (1, n)

---

## The Near-Miss

A developer reviews the UC02 vulnerable circuit and sees that the product constraint is
missing. They add both a non-zero check AND the product constraint:

```noir
// Near-miss "fix":
assert(factors[0] != 0);
assert(factors[1] != 0);
assert(factors[0] * factors[1] == n);  // Product constraint added!
```

This looks like a complete fix — factors are non-zero AND multiply to n. It compiles and
passes for all genuinely composite inputs like n=15 (factors: 3, 5).

**But primes can still be "proven composite."**

---

## Why the Near-Miss Fails

The check `factors != 0` allows `factors = 1`. The trivial factorization `(1, n)` satisfies:
- `1 != 0` ✓
- `n != 0` ✓ (for n > 0)
- `1 * n == n` ✓ (always true)

A malicious prover sets `factorize(7) = [1, 7]`. All three assertions pass. The prime 7
is "proven composite" via the trivial factorization.

---

## Three Versions Side-by-Side

| Version | Code | Exploitable? |
|---------|------|-------------|
| `vulnerable/` | `assert(f0 > 1); assert(f1 > 1)` — **missing product check** | Yes — any [2,3] factors pass |
| `near-miss/` | `assert(f0 != 0); assert(f1 != 0); assert(f0*f1==n)` | Yes — trivial (1, n) factorization |
| `patched/` | `assert(f0 > 1); assert(f1 > 1); assert(f0*f1==n)` | No — all three required |

---

## The Correct Fix

```noir
assert(factors[0] > 1);   // strictly greater than 1 (not just non-zero)
assert(factors[1] > 1);   // strictly greater than 1
assert(factors[0] * factors[1] == n);  // product matches input
```

The `> 1` bound excludes the trivial factorization `(1, n)` that breaks the non-zero variant.

---

## Auditor Note

**Off-by-one errors in bound checks are a common near-miss pattern.** When a constraint
is supposed to exclude trivial cases (like factor=1), use `> 1` not `!= 0`. These differ
by exactly one value and look nearly identical in code review. Always check whether the
boundary value itself (0, 1, max) is correctly included or excluded.
