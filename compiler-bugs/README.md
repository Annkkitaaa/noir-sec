# Compiler Bug Reproductions

This directory contains reproductions of **documented Noir compiler bugs** that affect
circuit security. These are distinct from developer-introduced vulnerabilities: the source
code may be correct, but the compiled circuit is insecure due to a compiler defect.

---

## Why Compiler Bugs Matter for ZK Security

In traditional software, a compiler bug might produce incorrect behavior that causes crashes
or wrong outputs. In ZK circuits, a compiler bug can:

1. **Remove constraints from ACIR** that were present in source code, making the circuit
   accept proofs for false statements (soundness failure)
2. **Add unexpected constraints** from code the developer intended to run unconstrained,
   making the circuit's actual security properties invisible to source-level review
3. **Produce arithmetic overflow** in compiled operations, allowing a prover to satisfy
   assertions with mathematically incorrect witness values

The compiler is part of the **trusted computing base** for any ZK circuit. Source code
review alone is insufficient — production circuits should also be audited at the ACIR level.

---

## Bug Inventory

| ID | Issue | Severity | Fixed In | NoirSec Mapping |
|----|-------|----------|----------|-----------------|
| CB01 | [#4442](https://github.com/noir-lang/noir/issues/4442) Unconstrained struct generates ACIR constraints | High | v0.28+ | UC02 |
| CB02 | [#9806](https://github.com/noir-lang/noir/blob/master/CHANGELOG.md) Loop assertion simplification | High | v1.x fix | UC category |
| CB03 | [#9723](https://github.com/noir-lang/noir/blob/master/CHANGELOG.md) u128 left shift field overflow | High | v1.x fix | FA01 |

All three bugs are **fixed** in current Noir versions. They are preserved here as:
- Educational reference for auditors
- Regression test patterns
- Historical record of the compiler's trusted computing base history

---

## Reproductions

Each subdirectory contains:
- `README.md` — bug description, impact analysis, detection guidance
- `reproduction/src/main.nr` — minimal Noir circuit demonstrating the pattern
- `reproduction/Prover.toml` — safe test inputs (work on fixed compilers)
- `reproduction/Nargo.toml` — standalone package (not in workspace)

```
compiler-bugs/
  CB01-unconstrained-struct-constraints/
  CB02-constraint-simplification-loop/
  CB03-u128-shift-field-overflow/
```

---

## Running the Reproductions

```bash
# All three circuits should execute correctly on nargo 1.0.0-beta.19+
cd compiler-bugs/CB01-unconstrained-struct-constraints/reproduction && nargo execute
cd compiler-bugs/CB02-constraint-simplification-loop/reproduction && nargo execute
cd compiler-bugs/CB03-u128-shift-field-overflow/reproduction && nargo execute
```

These are regression tests: they should **pass** on fixed compilers. If you are evaluating
an older Noir version, they may exhibit the bug behavior described in each README.

---

## Key Auditing Lessons

1. **Pin compiler versions**: Use a specific `nargo` version for production deployments.
   Check the CHANGELOG for known CVEs before upgrading.

2. **Audit at ACIR level**: For security-critical circuits, compare source-level assertions
   to the actual compiled ACIR. The `nargo info` command shows gate counts; significant
   discrepancies from expected values warrant investigation.

3. **The unsafe boundary**: Treat every `unconstrained fn` call and every `unsafe {}` block
   as a security-critical annotation. CB01 shows that even the compiler itself can violate
   the constrained/unconstrained boundary.

4. **Large integer arithmetic**: CB03 shows that `u128` operations are not true 128-bit
   arithmetic — they operate within the BN254 field. Any operation that could approach
   the field modulus requires explicit range verification.

---

## References

- [Noir CHANGELOG](https://github.com/noir-lang/noir/blob/master/CHANGELOG.md)
- [Noir Issue #4442](https://github.com/noir-lang/noir/issues/4442)
- [POSTMORTEMS.md](../resources/POSTMORTEMS.md) -- PM-06, PM-07, PM-08
