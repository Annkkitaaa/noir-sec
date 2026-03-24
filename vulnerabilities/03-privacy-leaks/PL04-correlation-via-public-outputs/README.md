# PL04 — Correlation via Public Outputs

| Property | Value |
|----------|-------|
| **Difficulty** | Hard |
| **Category** | Privacy Leak (PL) |
| **Severity** | Medium |
| **Root Cause** | Multiple public outputs form quasi-identifiers enabling de-anonymization |

## Scenario
An anonymous voting circuit publishes `(vote_commitment, age_bracket, precinct_code, vote_hour)` per vote. Each field seems safe alone. But combined, they may uniquely identify a voter in small precincts, linking `vote_commitment` to a real identity.

**Bug:** Publishing granular demographic quasi-identifiers per vote.

**Fix:** Minimize public outputs — only publish `vote_commitment`. Aggregate statistics at the batch level.


---

## Impact Assessment

**Severity: Medium**

**Justification:** Publishing correlated demographic fields (age bracket, precinct, vote hour) creates quasi-identifiers that uniquely identify voters in small communities -- a k-anonymity failure applied to ZK proofs. An attacker cross-references the published combination against electoral rolls to deanonymize specific voters and link their vote commitment to their identity. While no single field uniquely identifies a voter, the combination does. In a real election, this creates coercion risk and exposes individual voting choices.

**Attack Complexity:** Medium -- requires external demographic data for cross-referencing; automatable with public records

**Prerequisites:** Access to public records or electoral data to cross-reference with the published quasi-identifiers

**Affected Components:** Voting circuits, compliance proofs, any circuit publishing multiple demographic attributes simultaneously

---

## Running the Exploit
```bash
python3 vulnerabilities/03-privacy-leaks/PL04-correlation-via-public-outputs/exploit/exploit.py
```
