// FA03 -- Modular Arithmetic Misuse (PATCHED)
// ============================================================
// Fix: Use bounded integer types (u64) for shard arithmetic.
//
// Root cause:
//   Using field arithmetic for modulo operations produces field-element results
//   that are not equivalent to integer modulo for large inputs.
//
// Fix:
//   Use u64 types for user_id and num_shards. Integer modulo on u64 is
//   well-defined and matches the expected semantics.

fn main(
    user_id: u64,          // FIXED: u64 for integer modulo semantics
    num_shards: pub u64,   // FIXED: u64
    shard_id: pub u64      // FIXED: u64
) {
    // FIXED: u64 modulo is correct integer arithmetic.
    // For user_id=1000 and num_shards=256: 1000 % 256 = 232 (correct)
    // For large field elements: they cannot be expressed as u64 (range check catches it)
    assert(num_shards > 0);
    assert(user_id % num_shards == shard_id);
}
