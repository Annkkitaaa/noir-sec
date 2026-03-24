// UC01 -- Missing Range Check
// ============================================================
// Vulnerability ID : UC01
// Category         : Under-Constrained
// Severity         : Critical
// Difficulty       : Easy
// ============================================================
//
// Scenario:
//   An age-gated content platform issues ZK proofs. Users prove they meet
//   the minimum age requirement (e.g., 18+) WITHOUT revealing their exact age.
//   The platform verifier trusts the circuit to enforce the age check.
//
// Spec:
//   Prove that: age >= min_age, where age is a valid human age [0, 150]
//
// Your challenge:
//   A 5-year-old wants to access adult content. Can they generate a valid proof?
//   Read this circuit, find the bug, and write an exploit.
//   Then check your answer against exploit/exploit.sh and patched/src/main.nr.

fn main(
    age: Field,       // Private: the user's actual age
    min_age: pub u8   // Public:  minimum age requirement (e.g., 18)
) {
    // BUG: 'age' is declared as Field -- a 254-bit integer with NO range constraint.
    // ANY field element (including 0, 5, p-1 = 2^254+...) satisfies this circuit.
    //
    // The developer intended to check age >= min_age and age <= 150.
    // But there is NO assertion enforcing these bounds.
    //
    // An attacker can pass age = 5 (a 5-year-old) and the proof succeeds.
    // They can also pass age = p-1 (a 254-bit number) and the proof succeeds.
    //
    // In Noir, Field types cannot be compared directly with >= or <=.
    // The correct fix is to declare 'age' as u8, which adds an ACIR range proof
    // constraining age to [0, 255] and enables integer comparisons.
    //
    // Missing: assert(age_as_u8 >= min_age) with age declared as u8.
    let _ = std::hash::pedersen_hash([age]);
}
