# PL01 — Accidental Public Input

| Property | Value |
|----------|-------|
| **Difficulty** | Easy |
| **Category** | Privacy Leak (PL) |
| **Severity** | High |
| **Root Cause** | `pub` keyword accidentally added to a private parameter |

## Scenario
A private identity commitment circuit. `secret` should be hidden — but `pub` was accidentally added to it during a refactor. The secret appears directly in the proof's public input vector. Any verifier can read it.

**Bug:** `secret: pub Field` — should be `secret: Field`.

**Fix:** Remove the `pub` keyword from `secret`.

## Key Noir Concept
In Noir, all parameters are **private by default**. Only add `pub` to parameters intended to be visible to the verifier. A quick audit of all `pub` parameters against the spec catches this class of bug immediately.


---

## Impact Assessment

**Severity: High**

**Justification:** A private value declared with the `pub` keyword is exposed as a public output in the proof, readable by any verifier or blockchain observer. Once the secret is public, it can be used to derive other commitments, link transactions across time, or impersonate the user. The attacker is the verifier itself -- any party that verifies the proof obtains the private value with zero additional effort. This is a silent vulnerability: the proof verifies correctly, but the privacy guarantee has been eliminated.

**Attack Complexity:** None -- the secret is simply read from the proof's public inputs by any verifier

**Prerequisites:** Only the ability to verify the proof (which is public by design in ZK protocols)

**Affected Components:** Any circuit with sensitive private inputs accidentally marked `pub`; identity circuits, private key derivation, balance proofs

---

## Running the Exploit
```bash
bash vulnerabilities/03-privacy-leaks/PL01-accidental-public-input/exploit/exploit.sh
```
