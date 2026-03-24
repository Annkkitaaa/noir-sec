# LE02 — Missing Ownership Check

| Property | Value |
|----------|-------|
| **Difficulty** | Medium |
| **Category** | Logic Error (LE) |
| **Severity** | Critical |
| **Root Cause** | Secret key constrained to auth_hash but not bound to user_id |

> **Source:** This vulnerability is described directly in OpenZeppelin's "Developer's Guide to Building Safe Noir Circuits" (Sept 2025) as a primary example of authentication circuit logic errors.

---

## Scenario

A decentralized access control system. Users register by computing `auth_hash = hash(sk)` and storing it on-chain. To perform privileged actions on behalf of `user_id`, a user generates a ZK proof showing they know `sk` such that `hash(sk) == auth_hash`.

The circuit is in [vulnerable/src/main.nr](vulnerable/src/main.nr).

**Alice** has `user_id = 1` with her `auth_hash_alice = hash(sk_alice)`.
**Bob** has `user_id = 2` with his `auth_hash_bob = hash(sk_bob)`.

Bob wants to perform a privileged action on Alice's account. Can he do it?

---

## Your Challenge

1. Read [vulnerable/src/main.nr](vulnerable/src/main.nr)
2. Identify what the circuit verifies vs. what it should verify
3. Explain how Bob can authorize Alice's account using his own credentials
4. Check against [exploit/exploit.sh](exploit/exploit.sh)
5. Fix the circuit — see [patched/src/main.nr](patched/src/main.nr)

---

## Hints

<details>
<summary>Hint 1 — Mild</summary>

The circuit checks: `hash(sk) == auth_hash`.

Is `user_id` involved in any constraint?
</details>

<details>
<summary>Hint 2 — Moderate</summary>

Bob has a valid `(sk_bob, auth_hash_bob)` pair. The circuit accepts any valid `(sk, auth_hash)` pair. Nothing stops Bob from providing `user_id = alice_id` alongside his own valid `(sk_bob, auth_hash_bob)`.

The `user_id` parameter is declared public but **never constrained**.
</details>

<details>
<summary>Hint 3 — Strong</summary>

The missing constraint is:
```noir
assert(pedersen_hash([sk]) == user_id);
```
This forces `user_id` to be deterministically derived from `sk`. Only the holder of `sk` can generate proofs for the `user_id` derived from that key.
</details>

---

## The Bug

<details>
<summary>Spoiler: Full Explanation</summary>

### What the circuit verifies
```
hash(sk) == auth_hash  ← proves knowledge of sk
```

### What the spec requires
```
hash(sk) == auth_hash   ← proves knowledge of sk
hash(sk) == user_id     ← MISSING: proves this sk is bound to this user_id
```

### The exploit
Bob provides:
- `sk = sk_bob` (his own secret — he knows it)
- `auth_hash = hash(sk_bob)` (his own registered hash)
- `user_id = alice_id` (Alice's account)

The circuit checks: `hash(sk_bob) == auth_hash_bob` ✓
The circuit does NOT check: `alice_id == hash(sk_bob)` ✗ (check missing)

**The proof is valid.** Bob successfully authorizes actions on Alice's account.

### The fix
Register `user_id = hash(sk)`. Add the constraint:
```noir
assert(sk_hash == user_id);
```
Now `user_id` is cryptographically bound to `sk`. Bob's `hash(sk_bob) != alice_id`, so the proof fails.

### Why this happens
The developer wrote `user_id: pub Field` thinking it was "just an identifier," not realizing it needed to be constrained to the authenticating key. Private inputs that appear in the signature but are not used in any `assert` are "dead variables" — they don't contribute to the proof's security.

</details>

---

## Running the Exploit

```bash
bash vulnerabilities/05-logic-errors/LE02-missing-ownership-check/exploit/exploit.sh
```

---

---

## Impact Assessment

**Severity: Critical**

**Justification:** The circuit verifies knowledge of a secret key matching a hash, but never binds that key to a specific user account. Any registered user (Bob) can use their own valid `(sk_bob, auth_hash_bob)` pair while setting `user_id` to any other user's account (Alice). The proof is sound -- Bob does know a key matching his auth_hash -- but the system incorrectly authorizes Bob to act as Alice. In an access control system, this is complete privilege escalation: one registered account grants access to all accounts. In a token system, any registered user can drain any other user's balance.

**Attack Complexity:** Low -- the attacker uses legitimately obtained credentials; no cryptographic attack required

**Prerequisites:** Attacker must possess a valid registered account with their own `(sk, auth_hash)` pair (standard user registration)

**Affected Components:** Access control systems, delegation circuits, any protocol requiring binding of credentials to specific user identities

---

## References

- [OpenZeppelin: Developer's Guide to Building Safe Noir Circuits](https://www.openzeppelin.com/news/developer-guide-to-building-safe-noir-circuits) — this exact pattern is the lead example
- [Nethermind: First Deep Dive into Noir](https://www.nethermind.io/blog/our-first-deep-dive-into-noir-what-zk-auditors-learned)
