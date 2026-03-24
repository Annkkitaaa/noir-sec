// FA03 -- Modular Arithmetic Misuse
// ============================================================
// Vulnerability ID : FA03
// Category         : Field Arithmetic
// Severity         : High
// Difficulty       : Medium
// ============================================================
//
// Scenario:
//   A sharding protocol assigns users to shards based on their user_id.
//   shard_id = user_id mod num_shards
//
// Spec:
//   shard_id = user_id % num_shards  (INTEGER modulo, 0 <= shard_id < num_shards)
//
// Bug:
//   user_id is a Field type. For values near the BN254 prime p, field arithmetic
//   diverges from integer arithmetic.
//
//   The quotient is computed by an unconstrained function -- the prover controls it.
//   A malicious prover can supply a crafted quotient that satisfies the reconstruction
//   check while assigning themselves to an arbitrary shard.

// Computes the floor quotient as a hint (outside the ZK proof).
// A malicious prover can return ANY field element here.
unconstrained fn compute_quotient(user_id: Field, num_shards: Field) -> Field {
    // Use u64 integer division inside Brillig for correct floor quotient.
    // The prover can still supply a FAKE quotient by bypassing this hint entirely.
    let q: u64 = user_id as u64 / num_shards as u64;
    q as Field
}

fn main(
    user_id: Field,         // Private: user's ID (VULNERABLE: Field type)
    num_shards: pub u64,    // Public:  number of shards (e.g., 256)
    shard_id: pub u64       // Public:  claimed shard assignment
) {
    let num_shards_f: Field = num_shards as Field;
    let shard_id_f: Field = shard_id as Field;

    // Safety: quotient verified by reconstruction below.
    let quotient = unsafe { compute_quotient(user_id, num_shards_f) };

    // BUG 1: quotient is prover-controlled (unconstrained function).
    // BUG 2: Field equation has multiple solutions -- attacker can pick any shard.
    // BUG 3: user_id is Field -- any 254-bit value is a valid "user_id".
    assert(quotient * num_shards_f + shard_id_f == user_id);
    assert(shard_id < num_shards);
}
