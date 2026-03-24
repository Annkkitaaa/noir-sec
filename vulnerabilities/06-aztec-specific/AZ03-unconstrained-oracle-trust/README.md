# AZ03 — Unconstrained Oracle Trust

| Property | Value |
|----------|-------|
| **Difficulty** | Medium |
| **Category** | Aztec-Specific (AZ) |
| **Severity** | Critical |
| **Root Cause** | Oracle result from `unconstrained fn` used without commitment verification |

> **Aztec-specific:** In Aztec's execution model, the sequencer IS the prover for private transactions and controls oracle execution. This makes this vulnerability uniquely dangerous in the Aztec context.

## Scenario
A DeFi collateral circuit (simulated in vanilla Noir). An oracle provides the current asset price. The circuit checks `asset_price >= price_threshold`. But the price comes from an unconstrained function — the prover controls what it returns.

**Bug:** Oracle price used directly from `unconstrained fn` — no commitment verification.

**Fix:** Make `oracle_price` a public input verified against a trusted price feed commitment.

## Aztec Context
In production Aztec contracts, `context.oracle.get_price()` is an unconstrained call. If the contract trusts the oracle result without verifying it against a Merkle root or price feed signature, a malicious sequencer can inject any price value.

## Running the Exploit
```bash
bash vulnerabilities/06-aztec-specific/AZ03-unconstrained-oracle-trust/exploit/exploit.sh
```

## Impact Assessment

| Property | Value |
|----------|-------|
| **Severity** | Critical |
| **Justification** | Malicious sequencer can inject any oracle price, bypassing all DeFi collateral checks. In Aztec, the sequencer IS the prover — oracle trust is a direct soundness failure |
| **Attack Complexity** | Low in Aztec (sequencer controls Brillig execution); Medium in vanilla Noir (requires modified binary) |
| **Prerequisites** | Attacker must be the sequencer (highly realistic in early Aztec deployments) |
| **Affected Components** | Oracle calls, any circuit logic gated by external state, DeFi collateral/price checks |

## References
- [Aztec Documentation: Oracles](https://docs.aztec.network)
- [UC02](../../01-under-constrained/UC02-unconstrained-hint-abuse/README.md) — same pattern, different context
- [Nethermind: First Deep Dive into Noir](https://www.nethermind.io/blog/our-first-deep-dive-into-noir-what-zk-auditors-learned)
