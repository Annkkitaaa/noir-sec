// AZ05 -- Storage Slot Collision (PATCHED)
// Fix: Use distinct indices for each variable (domain separation).

fn main(
    contract_address: pub Field,
    balance_value: Field,
    allowance_value: Field,
    balance_slot: pub Field,
    allowance_slot: pub Field
) {
    // FIXED: Use distinct indices -- 0 for balance, 1 for allowance.
    // Each variable now has a unique, collision-free storage slot.
    let computed_balance_slot = std::hash::pedersen_hash([contract_address, 0]);
    let computed_allowance_slot = std::hash::pedersen_hash([contract_address, 1]); // FIXED: index=1

    assert(computed_balance_slot == balance_slot);
    assert(computed_allowance_slot == allowance_slot);

    // Now balance_slot != allowance_slot for any contract_address.
    // Writing to balance does not affect the allowance storage slot.
}
