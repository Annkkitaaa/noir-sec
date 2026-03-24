# CB03 -- u128 Left Bit Shift Field Overflow

**Category:** Compiler Bug Reproduction
**Noir Issue:** [#9723](https://github.com/noir-lang/noir/blob/master/CHANGELOG.md) ("Left bit shift u128 would overflow Field")
**Severity:** High
**Status:** Fixed in Noir v1.x (post-fix release)
**NoirSec Mapping:** [FA01 -- Integer Overflow in Field](../../vulnerabilities/04-field-arithmetic/FA01-integer-overflow-in-field/)
**Real-World Precedent:** [PM-08 in POSTMORTEMS.md](../../resources/POSTMORTEMS.md#pm-08-noir-compiler----u128-left-bit-shift-field-overflow-issue-9723)

---

## The Bug

Left bit shifts on `u128` values could **overflow the BN254 scalar field modulus** in affected
Noir compiler versions, producing field elements that were arithmetically incorrect as
128-bit integers.

```noir
fn main(base: u128, shift_amount: u8, expected: pub u128) {
    let result = base << shift_amount;  // BUG: may produce wrong result near field prime
    assert(result == expected);
}
```

### The Math

The BN254 scalar field prime:
```
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
  ~ 2^254.8
```

A `u128` left shift: `1 << 127 = 2^127 = 170141183460469231731687303715884105728`

In correct integer arithmetic: `2^127 < p`, so this is safe.

But for shifts that push values near `p`, field reduction could silently wrap to a
small positive number. For example, `large_u128 << shift` might produce a value
that, after field modulo, equals a completely different 128-bit integer that still
passes the assertion.

### Affected Operations

- `u128 << n` where result approaches or exceeds p
- Bitwise operations (XOR, AND, OR) on large u128 values
- Any cryptographic computation that relies on u128 arithmetic (key derivation, hash functions)

---

## Reproduction

```bash
cd compiler-bugs/CB03-u128-shift-field-overflow/reproduction
nargo execute
```

The safe test case (`1 << 10 = 1024`) passes on all compiler versions.

To probe the bug boundary, modify `Prover.toml` to use large shift values:
```toml
base = "1"
shift_amount = "127"   # u128 (Noir requires same bit width for both shift operands)
expected_result = "170141183460469231731687303715884105728"
```

In affected compilers, the expected result would be field-reduced to a different value,
causing either:
- An incorrect witness that still passes (if the prover submits the field-reduced value)
- A failing witness (if the prover submits the mathematically correct value)

---

## Detection

1. **Gate count comparison**: A correct u128 shift with range checking should generate
   range constraint gates. Significantly fewer gates than expected signals missing overflow checks.

2. **Boundary value testing**: Test shift operations with values near 2^64, 2^96, 2^127.
   If expected results differ from actual circuit outputs, the overflow behavior is present.

3. **ACIR inspection**: Verify that the compiled circuit includes range proofs confirming
   the shift result fits within u128 bounds (< 2^128) and does not exceed the field modulus.

---

## Fix

**Upgrade to Noir v1.x** (post-fix version). The fix adds proper range constraint generation
for u128 shift operations, ensuring results are always checked against both the u128 upper
bound (2^128) and the field modulus.

**Defense in depth**: For circuits using large integer types:
- Use `u64` instead of `u128` where possible (values up to 2^64 are safe)
- Add explicit range assertions after shift operations: `assert(result < (1 as u128 << 127))`
- Prefer values well within the field's safe range for intermediate computations

---

## Key Lesson for Auditors

> **`u128` in Noir is not true 128-bit arithmetic.** All values are represented as BN254
> field elements (< p ~ 2^254.8). Shifts and operations near the u128 upper range can
> interact unexpectedly with the field modulus. When reviewing circuits that use large
> integer types with bitwise operations, verify that the operations cannot produce
> values that collide with or overflow into the field modulus.

See CHANGELOG for issue #9723: `https://github.com/noir-lang/noir/blob/master/CHANGELOG.md`
