// AZ03 -- Unconstrained Oracle Trust
// ============================================================
// Vulnerability ID : AZ03
// Category         : Aztec-Specific
// Severity         : Critical
// Difficulty       : Medium
// Hint Level       : 2
// ============================================================
//
// Aztec Network context:
//   Aztec contracts use "oracles" -- unconstrained functions that read
//   external state (token prices, Merkle roots, block timestamps).
//   In Aztec's execution model, the sequencer (who creates the proof)
//   also controls oracle execution.
//
//   If oracle results are used without verification against a trusted
//   commitment, the sequencer can inject false state.
//
//   This circuit simulates a DeFi collateral check in vanilla Noir.
//
// Spec:
//   Prove that asset_price >= price_threshold (sufficient collateral value).
//   asset_price must come from a TRUSTED oracle -- not attacker-controlled.
//
// Bug:
//   The oracle price comes from an unconstrained function.
//   A malicious sequencer can make the oracle return any price.
//   They can borrow against a worthless asset by reporting a false price.

// Simulates an Aztec oracle call -- in real Aztec this would call
// context.oracle.get_price(asset_id). Here we simulate with unconstrained fn.
unconstrained fn oracle_get_price(asset_id: Field) -> u64 {
    // In Aztec: this calls an external oracle -- sequencer controls the return value.
    // In vanilla Noir: prover controls what this returns.
    // For demo: hardcoded, but a malicious prover can change this to any value.
    if asset_id == 1 { 42000_u64 }  // BTC: $42,000
    else if asset_id == 2 { 2500_u64 }  // ETH: $2,500
    else { 0_u64 }
}

fn main(
    asset_id: pub Field,           // Public:  which asset to use as collateral
    borrow_amount: pub u64,        // Public:  how much to borrow
    price_threshold: pub u64,      // Public:  minimum required price for collateral
    collateral_amount: pub u64     // Public:  how much collateral is pledged
) {
    // Safety: price is verified against threshold.
    let asset_price: u64 = unsafe { oracle_get_price(asset_id) };

    // !!BUG: Oracle result used directly without validation!!
    //
    // A malicious prover (Aztec sequencer) can make oracle_get_price return
    // ANY value for any asset_id. They could return $1,000,000 for a $1 token,
    // allowing them to borrow against a worthless asset.
    //
    // There is no on-chain price feed commitment to verify against.
    assert(asset_price >= price_threshold);
    assert(collateral_amount > 0);

    // MISSING: Verify asset_price against a signed price feed or Merkle root.
    // Example: assert(pedersen_hash([asset_id, asset_price]) == oracle_commitment);
    // where oracle_commitment is a public value verified off-chain.
}
