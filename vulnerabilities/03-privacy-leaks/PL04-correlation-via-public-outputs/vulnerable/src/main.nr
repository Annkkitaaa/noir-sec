// PL04 -- Correlation via Public Outputs
// ============================================================
// Vulnerability ID : PL04
// Category         : Privacy Leak
// Severity         : Medium
// Difficulty       : Hard
// Hint Level       : 3
// ============================================================
//
// Scenario:
//   An anonymous voting system. Voters prove:
//     1. They are eligible to vote (age >= 18)
//     2. Their vote is recorded
//   The system publishes demographic info for statistical purposes.
//
//   Each public output field seems safe individually:
//     - vote_commitment: hides which candidate was chosen
//     - age_bracket: general category (1=young, 2=adult, 3=senior)
//     - precinct_code: geographical area (1-10)
//     - vote_hour: which hour of the day (0-23) the vote was cast
//
// Bug:
//   Combining (age_bracket + precinct_code + vote_hour) may uniquely identify
//   a voter in a small community. If only one senior (bracket=3) voted in
//   precinct 7 between 9-10am, their vote_commitment (and thus vote choice)
//   is de-anonymized through correlation.

fn main(
    voter_secret: Field,          // Private: voter's identity secret
    vote_choice: Field,           // Private: chosen candidate (1, 2, or 3)
    voter_age: u8,                // Private: voter's age
    precinct: u8,                 // Private: geographical precinct (1-10)
    vote_timestamp: u32,          // Private: Unix timestamp of vote
    vote_commitment: pub Field,   // Public:  commitment to (voter_secret, vote_choice)
    age_bracket: pub u8,          // Public:  1=18-30, 2=31-60, 3=61+
    precinct_code: pub u8,        // Public:  precinct (1-10)
    vote_hour: pub u8             // Public:  hour of day (0-23)
) {
    // Verify vote commitment.
    let commitment = std::hash::pedersen_hash([voter_secret, vote_choice]);
    assert(commitment == vote_commitment);

    // Verify age bracket is correctly derived.
    let computed_bracket: u8 = if voter_age < 18 { 0 }
        else if voter_age <= 30 { 1 }
        else if voter_age <= 60 { 2 }
        else { 3 };
    assert(computed_bracket == age_bracket);
    assert(age_bracket >= 1); // Must be 18+

    // Verify precinct code.
    assert(precinct == precinct_code);
    assert(precinct >= 1);
    assert(precinct <= 10);

    // Verify vote_hour is derived from timestamp.
    // VULNERABLE: Publishing vote_hour + age_bracket + precinct_code creates
    // a correlation attack surface. In a small precinct, (3, 7, 9) may
    // uniquely identify a voter and de-anonymize their vote_choice.
    let computed_hour: u8 = ((vote_timestamp / 3600) % 24) as u8;
    assert(computed_hour == vote_hour);
}
