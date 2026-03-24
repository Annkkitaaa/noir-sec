# UC04 — Duplicate Witness Assignment

| Property | Value |
|----------|-------|
| **Difficulty** | Medium |
| **Category** | Under-Constrained (UC) |
| **Severity** | High |
| **Root Cause** | Two independent credential slots not constrained to be distinct |

## Scenario
A 2-of-2 credential system. A user must prove knowledge of two independent secrets. If both credential slots can accept the same secret (no `credential_a != credential_b` check), a single credential satisfies both.

**Bug:** Missing `assert(credential_a != credential_b)`.

**Fix:** Add `assert(credential_a != credential_b)` after the hash checks.


---

## Impact Assessment

**Severity: High**

**Justification:** A 2-of-2 multi-signature system is reduced to 1-of-1 because no constraint prevents using the same secret for both slots. An attacker with a single credential registers it for both slots (`hash_a = hash_b = pedersen_hash([secret])`) and generates a valid proof satisfying both checks simultaneously. This completely defeats the purpose of multi-factor authentication -- a single compromised credential bypasses the entire security model. In a multi-sig wallet, one key becomes sufficient to authorize all transactions.

**Attack Complexity:** Low -- requires only one valid credential and the ability to register the same hash for both slots

**Prerequisites:** Attacker must possess one valid credential; access to the registration system to set hash_a = hash_b

**Affected Components:** Multi-factor authentication circuits, threshold signature schemes, 2-of-N approval workflows

---

## Running the Exploit
```bash
bash vulnerabilities/01-under-constrained/UC04-duplicate-witness-assignment/exploit/exploit.sh
```
