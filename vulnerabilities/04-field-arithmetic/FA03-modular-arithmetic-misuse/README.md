# FA03 — Modular Arithmetic Misuse

| Property | Value |
|----------|-------|
| **Difficulty** | Medium |
| **Category** | Field Arithmetic (FA) |
| **Severity** | High |
| **Root Cause** | Field division ≠ integer division — modulo decomposition has multiple solutions |

## Scenario
A sharding circuit proves `shard_id = user_id % num_shards`. Using field arithmetic for the modulo decomposition allows crafted field elements to satisfy the equation for arbitrary target shard_ids.

**Bug:** Field division/subtraction used for integer modulo — not equivalent for large field elements.

**Fix:** Use `u64` types — integer modulo is well-defined and field-anomaly-free.


---

## Impact Assessment

**Severity: High**

**Justification:** Field arithmetic diverges from integer arithmetic for values near the BN254 prime. The circuit accepts `user_id` as an unconstrained `Field`, allowing values up to p-1. A malicious prover crafts `user_id = k*256 + target_shard` for any target shard, providing a field element that satisfies the quotient-remainder reconstruction equation while assigning themselves to an arbitrary shard. This bypasses shard-based access controls, rate limits, or data isolation without any cryptographic break.

**Attack Complexity:** Medium -- requires understanding of field arithmetic and crafting specific field element inputs

**Prerequisites:** Ability to submit proofs with self-chosen private inputs; understanding of BN254 arithmetic

**Affected Components:** Sharding protocols, shard-based access control, routing circuits using `Field` for identifiers with intended integer semantics

---

## Running the Exploit
```bash
bash vulnerabilities/04-field-arithmetic/FA03-modular-arithmetic-misuse/exploit/exploit.sh
```
