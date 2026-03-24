// UC01 -- Missing Range Check (PATCHED)
// ============================================================
// Fix applied: Replace Field type with u8 for bounded integer values.
//
// Root cause:
//   Field represents any element in [0, p-1] where p is the BN254 scalar field
//   prime (~2^254). There is no implicit range constraint. A prover could
//   provide age = p-1, which satisfies age >= 18 even for a 5-year-old.
//
// Fix:
//   Use u8 (range [0, 255]) for age. The u8 type carries an implicit range
//   check -- any value outside [0, 255] causes the proof to fail immediately.
//   For human ages (0--150), u8 is appropriate and safe.
//
//   Alternative fix (if Field must be used):
//     assert(age as u8 as Field == age); // forces age into [0, 255]
//     assert(age >= min_age);

fn main(
    age: u8,         // FIXED: u8 constrains age to [0, 255] -- no field anomalies
    min_age: pub u8  // FIXED: u8 for consistency
) {
    // Now age is guaranteed to be a real human age in [0, 255].
    // A prover cannot supply age = p-1 because p-1 does not fit in a u8.
    assert(age >= min_age);
}
