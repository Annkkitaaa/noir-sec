// PL04 -- Correlation via Public Outputs (PATCHED)
// ============================================================
// Fix: Remove granular public outputs that enable correlation.
//      Only publish what is strictly necessary for the use case.
//
// Root cause:
//   Publishing (age_bracket, precinct_code, vote_hour) together creates
//   quasi-identifiers. Their combination may uniquely identify voters
//   in small communities, enabling vote de-anonymization.
//
// Fix:
//   Option A (minimal): Only publish the eligibility proof, not demographics.
//   Option B (statistical): Aggregate before publishing (batch statistics, not per-vote).
//
//   We implement Option A here: only vote_commitment is public.
//   Statistical analysis should happen at the aggregate level, not per-proof.

fn main(
    voter_secret: Field,
    vote_choice: Field,
    voter_age: u8,
    vote_commitment: pub Field  // ONLY public output: commitment to vote
    // REMOVED: age_bracket (enables correlation)
    // REMOVED: precinct_code (enables correlation)
    // REMOVED: vote_hour (enables correlation)
) {
    // Verify eligibility (age >= 18) -- privately.
    assert(voter_age >= 18);

    // Record the vote commitment.
    let commitment = std::hash::pedersen_hash([voter_secret, vote_choice]);
    assert(commitment == vote_commitment);

    // No demographic information is published per-vote.
    // Statistical analysis is done by the election authority on aggregates.
}
