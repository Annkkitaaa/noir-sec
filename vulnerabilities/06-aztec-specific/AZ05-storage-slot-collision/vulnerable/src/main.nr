// AZ05 -- Storage Slot Collision
// ============================================================
// Vulnerability ID : AZ05
// Category         : Aztec-Specific
// Severity         : High
// Difficulty       : Hard
// ============================================================
//
// Scenario:
//   An Aztec contract derives storage slots for two state variables using
//   pedersen_hash([contract_address, variable_index]).
//
// Bug:
//   Both variables use the same index (0), causing them to occupy the
//   same storage slot. Writing to "balance" overwrites "allowance" and
//   vice versa. The circuit accepts this -- but state is corrupted.
//
// Spec:
//   balance_slot   = hash(contract_address, BALANCE_INDEX)
//   allowance_slot = hash(contract_address, ALLOWANCE_INDEX)
//   where BALANCE_INDEX != ALLOWANCE_INDEX

fn main(
    contract_address: pub Field,
    balance_value: Field,        // Private: user balance
    allowance_value: Field,      // Private: spending allowance
    balance_slot: pub Field,     // Public:  storage slot for balance
    allowance_slot: pub Field    // Public:  storage slot for allowance
) {
    // !!BUG: Both variables use slot_index=0 -- same slot!!
    // balance_slot == allowance_slot: writing balance OVERWRITES allowance.
    let computed_balance_slot = std::hash::pedersen_hash([contract_address, 0]);
    let computed_allowance_slot = std::hash::pedersen_hash([contract_address, 0]); // BUG: same index!

    assert(computed_balance_slot == balance_slot);
    assert(computed_allowance_slot == allowance_slot);

    // Since both assert the same slot, balance_slot == allowance_slot.
    // Any write to the balance slot also overwrites the allowance.
    // MISSING: use distinct indices (e.g., 0 for balance, 1 for allowance)
}
