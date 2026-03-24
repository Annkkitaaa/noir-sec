// AZ03 -- Unconstrained Oracle Trust (PATCHED)
// ============================================================
// Fix: Make price a public input verified against a trusted price feed commitment.
//
// Root cause:
//   oracle_get_price() is unconstrained -- the prover controls its return value.
//   Any price can be reported for any asset, enabling false collateral claims.
//
// Fix (Option A -- simplest):
//   Make oracle_price a PUBLIC INPUT provided by a trusted external party.
//   The price is now part of the public statement, not an unconstrained hint.
//   The verifier (application) independently verifies the price source.
//
// Fix (Option B -- stronger, requires trusted price feed):
//   Include a price_oracle_commitment (Merkle root or signed hash from trusted feed).
//   Verify: pedersen_hash([asset_id, oracle_price]) is in the commitment.
//   This binds the price to a specific trusted data source.
//
// We implement Option A here for clarity.

fn main(
    asset_id: pub Field,
    borrow_amount: pub u64,
    price_threshold: pub u64,
    collateral_amount: pub u64,
    oracle_price: pub u64,           // ADDED: price is now a PUBLIC input
    oracle_commitment: pub Field     // ADDED: commitment to (asset_id, price)
) {
    // FIXED: Verify oracle_price against a trusted commitment.
    // The commitment is verified externally (Merkle proof, signature, etc.)
    // Here we use a simplified hash commitment for demonstration.
    let expected_commitment = std::hash::pedersen_hash([asset_id, oracle_price as Field]);
    assert(expected_commitment == oracle_commitment);

    // Now check collateral value.
    // oracle_price is now a public, verifiable input -- not a prover-controlled hint.
    assert(oracle_price >= price_threshold);
    assert(collateral_amount > 0);
}
