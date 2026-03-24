# OC01 — Unnecessary Range Restriction

| Property | Value |
|----------|-------|
| **Difficulty** | Easy |
| **Category** | Over-Constrained (OC) |
| **Severity** | Medium |
| **Root Cause** | Type too narrow for the actual valid domain — rejects legitimate inputs |

## Scenario
An NFT ownership circuit uses `u32` for `token_id`, but the application issues 64-bit token IDs. Any NFT with `token_id >= 2^32` cannot be proven, causing a denial-of-service for legitimate owners.

**Bug:** `token_id: u32` rejects IDs in `[2^32, 2^64-1]`.

**Fix:** `token_id: u64` accepts all valid IDs.


---

## Impact Assessment

**Severity: Medium**

**Justification:** Valid inputs exceeding an unnecessary type restriction are permanently rejected, causing denial of service for legitimate users. Any token minted with an ID greater than 4,294,967,295 cannot be transferred even though the protocol supports larger IDs. This is a liveness failure: the circuit breaks the protocol for valid users without any attacker involvement. In a high-value asset system, this could freeze legitimate funds permanently.

**Attack Complexity:** N/A -- no attacker action required; affects all inputs above the type threshold

**Prerequisites:** None -- occurs automatically for any valid input exceeding the type bound

**Affected Components:** Token ID circuits, identifier systems, any contract where values may grow beyond fixed-width integer bounds

---

## Running the Exploit
```bash
bash vulnerabilities/02-over-constrained/OC01-unnecessary-range-restriction/exploit/exploit.sh
```
