// UC04 -- Duplicate Witness Assignment (PATCHED)
// ============================================================
// Fix applied: Assert credential_a != credential_b.
//
// Root cause:
//   Without assert(credential_a != credential_b), a single secret can
//   satisfy both credential slots if both are registered to the same hash.
//
// Fix:
//   Explicitly require the two credentials to be distinct.
//   This ensures the 2-of-2 requirement actually needs 2 independent secrets.

fn main(
    credential_a: Field,
    credential_b: Field,
    hash_a: pub Field,
    hash_b: pub Field
) {
    let computed_hash_a = std::hash::pedersen_hash([credential_a]);
    let computed_hash_b = std::hash::pedersen_hash([credential_b]);

    assert(computed_hash_a == hash_a);
    assert(computed_hash_b == hash_b);

    // FIXED: Credentials must be distinct -- prevents one secret satisfying both.
    assert(credential_a != credential_b);
}
