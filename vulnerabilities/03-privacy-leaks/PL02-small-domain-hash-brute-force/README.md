# PL02 — Small Domain Hash Brute Force

| Property | Value |
|----------|-------|
| **Difficulty** | Medium |
| **Category** | Privacy Leak (PL) |
| **Severity** | High |
| **Root Cause** | Private value has too small a domain; hash is brute-forceable |

---

## Scenario

An anonymous election system proves voter eligibility by age bracket without revealing exact age. The system publishes `bracket_hash = pedersen_hash([bracket])` as a "privacy-preserving" proof of eligibility.

Age brackets:
- `0` = Under 18 (not eligible)
- `1` = 18–30
- `2` = 31–50
- `3` = 51+

The circuit correctly uses a ZK proof so the verifier cannot see the voter's age directly. However, the published `bracket_hash` leaks the exact bracket to any observer.

---

## Your Challenge

1. Read [vulnerable/src/main.nr](vulnerable/src/main.nr)
2. Understand what information `bracket_hash` reveals
3. Run [exploit/exploit.py](exploit/exploit.py) to recover a voter's bracket from their hash
4. Read [patched/src/main.nr](patched/src/main.nr) to understand the fix

---

## Hints

<details>
<summary>Hint 1 — Mild</summary>

`bracket_hash = pedersen_hash([bracket])` where `bracket ∈ {0,1,2,3}`.
How many possible values does `bracket_hash` have?
</details>

<details>
<summary>Hint 2 — Moderate</summary>

Since `bracket` has only 4 possible values, there are only 4 possible hashes.
An attacker precomputes `{hash(0), hash(1), hash(2), hash(3)}` and looks up the target.
This lookup table has 4 entries — it takes microseconds to build and query.
</details>

<details>
<summary>Hint 3 — Strong</summary>

The fix is adding a **secret salt**:
```noir
bracket_hash = pedersen_hash([bracket, salt])
```
Now an attacker needs the salt (which they don't know) to compute the preimage.
</details>

---

## The Bug

<details>
<summary>Spoiler: Full Explanation</summary>

### Why hashing alone is not sufficient for small domains

The ZK proof correctly hides the voter's **exact age** — the verifier cannot learn the specific value. However, the circuit publishes `bracket_hash = hash(bracket)`, and `bracket` has only **4 possible values**.

An attacker builds a precomputed table in microseconds:
```
hash(0) = 0x...
hash(1) = 0x...
hash(2) = 0x...
hash(3) = 0x...
```
Then looks up any published `bracket_hash` to instantly determine the voter's bracket.

**The ZK property is preserved** (the prover's exact age is hidden), but the **privacy property is broken** (the bracket is leaked through the small-domain hash).

### The fix
Add a user-specific secret `salt` to the hash:
```noir
bracket_hash = pedersen_hash([bracket, salt])
```
The salt must have at least 128 bits of entropy. Now the preimage space is `4 * 2^128 ≈ 2^130` combinations — computationally infeasible to brute-force.

### General rule
Any hash of a private value that is published publicly must have sufficient **preimage entropy** — the private value (plus any salts) must span a space too large to brute-force. For human-scale values (age, score, count), always add a salt.

### Real-world impact
This vulnerability pattern was explicitly documented by OpenZeppelin (Sept 2025) as a common Noir circuit error. It affects:
- Voting systems (bracket, score)
- Age-gating (bracket)
- Credit scoring (range)
- Geographic location (small region code)

</details>

---

## Running the Exploit

```bash
# Requires Python 3.10+ and nargo installed (WSL on Windows)
python3 vulnerabilities/03-privacy-leaks/PL02-small-domain-hash-brute-force/exploit/exploit.py
```

---

---

## Impact Assessment

**Severity: High**

**Justification:** Publishing `pedersen_hash([bracket])` where `bracket in {0,1,2,3}` is equivalent to publishing the bracket itself. An attacker precomputes all four possible hash values offline and matches any published hash against the lookup table instantly. In a voting system, every voter's age bracket is fully recoverable. In a credit system, the risk tier is exposed. The attacker needs only the public hash and a few milliseconds of computation -- no cryptographic attack is required.

**Attack Complexity:** Low -- precomputation requires exactly 4 hash computations; matching is O(1)

**Prerequisites:** None -- only the on-chain published hash value is needed

**Affected Components:** Any circuit publishing hash(small_domain_input); age brackets, score tiers, binary flags, categorical attributes

---

## References

- [OpenZeppelin: Developer's Guide to Safe Noir Circuits](https://www.openzeppelin.com/news/developer-guide-to-building-safe-noir-circuits) — "Privacy Leaks" section explicitly covers this
- [SoK: Security Vulnerabilities in SNARKs](https://arxiv.org/pdf/2402.15293) — Section on information-theoretic leakage
