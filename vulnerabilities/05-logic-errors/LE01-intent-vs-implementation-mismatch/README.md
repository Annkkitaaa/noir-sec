# LE01 — Intent vs Implementation Mismatch

| Property | Value |
|----------|-------|
| **Difficulty** | Hard |
| **Category** | Logic Error (LE) |
| **Severity** | High |
| **Root Cause** | Private input declared but never used in any constraint — dead variable |

## Scenario
An NFT ownership circuit. `owner_key` appears as a private parameter, suggesting it proves ownership. But it is never used in any `assert` — it's a dead variable. The circuit only verifies public metadata, which anyone can read. Anyone can list Alice's NFT.

**Bug:** `owner_key` is unconstrained — never appears in any `assert`.

**Fix:** `assert(pedersen_hash([owner_key, token_id]) == owner_commitment)`.

## Key Insight
Static analysis tools (including `aztec-lint`) can detect unused private inputs. Always audit that every private parameter participates in at least one constraint that relates it to a public input or constant.


---

## Impact Assessment

**Severity: High**

**Justification:** The circuit computes `metadata_hash` as a public output but never constrains it to prove the caller knows the token owner's private key. Since `metadata_hash` is a deterministic function of public data, any party can compute it independently. An attacker reads the public `token_id` and `extra_data` from the blockchain, computes the hash themselves, and generates a valid proof claiming ownership. The circuit proves 'this is a valid hash computation' -- not 'this prover owns this token'. The intended security requirement was never translated into a constraint.

**Attack Complexity:** Low -- only requires publicly available blockchain data and one hash computation

**Prerequisites:** Access to public blockchain data for the target token (universally available)

**Affected Components:** Token ownership circuits, NFT transfer proofs, any circuit where proving knowledge of private data is conflated with proving computation

---

## Running the Exploit
```bash
bash vulnerabilities/05-logic-errors/LE01-intent-vs-implementation-mismatch/exploit/exploit.sh
```
