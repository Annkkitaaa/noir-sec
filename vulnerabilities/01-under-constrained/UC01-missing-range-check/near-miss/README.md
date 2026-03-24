# UC01 Near-Miss: Range Check on Cast, Not on Witness

**Pattern:** `age as u8` truncates but does not constrain the Field witness

---

## The Near-Miss

A developer reviews the UC01 vulnerable circuit, recognizes that `age: Field` has no range
check, and attempts to fix it by casting to `u8` before the comparison:

```noir
// Near-miss "fix":
let age_u8: u8 = age as u8;
assert(age_u8 >= min_age);
```

This code **compiles and passes** for legitimate inputs. It also looks correct at first
glance — the developer added both a type cast and an assertion.

**But it is still exploitable.**

---

## Why the Near-Miss Fails

The cast `age as u8` computes `age mod 256` — it takes the **lowest 8 bits** of the field
element. It does **not** prove that `age` is a valid 8-bit integer in [0, 255].

The constraint system sees only: `age_u8 >= min_age`

It does NOT see: `age is in [0, 255]`

**Attack:** Set `age = 256 * k + desired_age` for any multiplier `k`.

```
age = 286 (= 256 + 30)
age as u8 = 30         ← computed by circuit
assert(30 >= 18)       ← PASSES
```

A 5-year-old can set `age = 261 = 256 + 5`. If `min_age = 3`, the cast produces `5 >= 3`
which passes, while the actual age field value (261) is far outside any human age range.
More importantly, a value of `p - 1` (the field prime minus 1) would cast to `255 - 1 = 254`
when `p ≡ 0xef... mod 256`, which might pass an 18+ check while representing a 254-bit number.

---

## Three Versions Side-by-Side

| Version | Code | Exploitable? |
|---------|------|-------------|
| `vulnerable/` | `let _ = pedersen_hash([age])` | Yes — no range check at all |
| `near-miss/` | `let age_u8 = age as u8; assert(age_u8 >= min_age)` | Yes — cast truncates, doesn't constrain |
| `patched/` | `fn main(age: u8, ...)` | No — `u8` type adds ACIR range proof |

---

## The Correct Fix

Declare the input as `u8` rather than casting it:

```noir
fn main(age: u8, min_age: pub u8) {
    assert(age >= min_age);
}
```

When `age` is declared as `u8`, the **Noir type system automatically generates an ACIR
range proof** constraining `age` to [0, 255]. The prover cannot supply a value outside
this range — it would fail the range check before reaching the assertion.

---

## Auditor Note

**Be suspicious of `as` casts on Field inputs.** A cast like `x as u32` does NOT prove
that `x` is a 32-bit integer — it computes `x mod 2^32`. The only way to range-constrain
a value in Noir is to declare it with an integer type (`u8`, `u32`, etc.) or add an explicit
range assertion using `std::range_check` or `assert_max_bit_size`.
