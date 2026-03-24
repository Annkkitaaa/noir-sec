# Real-World Vulnerability Mappings

This document maps NoirSec's vulnerability taxonomy to documented real-world bugs in
production ZK systems. These are not theoretical -- each caused or could have caused
loss of funds, privacy breaches, or protocol failure.

> **Note on URL verification:** Links were accurate as of the project build date.
> Verify all external URLs before citing in formal reports.

---

## Mapping Table

| # | Incident | Project | Year | NoirSec Category | Severity | Status |
|---|----------|---------|------|-------------------|----------|--------|
| PM-01 | Tree index range constraint missing | Aztec Connect | 2021 | UC01 | Critical | Fixed |
| PM-02 | BigField CRT overflow | Aztec Connect | 2021 | FA01 + UC01 | Critical | Fixed |
| PM-03 | Under-constrained bugs in circomlib | circomlib | 2023 | UC01-UC04 | Critical | Fixed (some) |
| PM-04 | Multiple under-constrained bugs in RISC Zero V2 | RISC Zero | 2024 | UC01, UC04 | Critical | Fixed |
| PM-05 | Sapling spend circuit counterfeiting | Zcash | 2019 | UC category | Critical | Fixed (silent) |
| PM-06 | Unconstrained function generating constraints | Noir compiler | 2023 | UC02 | High | Fixed (v0.28+) |
| PM-07 | Constraint simplification removing necessary constraints | Noir compiler | 2024 | UC category | High | Fixed |
| PM-08 | u128 left bit shift overflowing into field | Noir compiler | 2024 | FA01 | High | Fixed |

---

## Detailed Mappings

### PM-01: Aztec Connect -- Tree Index Range Constraint Bug

**Project:** Aztec Connect (Aztec 2.0 production system)
**Year:** 2021 (disclosed after fix)
**NoirSec Mapping:** [UC01 -- Missing Range Check](../vulnerabilities/01-under-constrained/UC01-missing-range-check/)
**Severity:** Critical -- enabled double-spending of notes in the Aztec rollup

**What happened:**
The Aztec Connect rollup circuit used a `u32`-sized range constraint to validate a note
tree index, but the actual note tree supported 32-bit indices. An off-by-one or missing
range check on the index allowed a crafted proof to reference notes outside the intended
range, creating the possibility of spending the same note multiple times by using different
but valid-looking indices.

**How it maps to UC01:**
The NoirSec UC01 challenge demonstrates the exact pattern: a `Field` type input with no
range constraint where a bounded integer type was intended. In the Aztec bug, the note tree
index lacked the necessary range proof that would have constrained it to valid note positions.
The fix was adding an explicit range constraint -- the same lesson UC01 teaches.

**Key takeaway for auditors:**
Every numeric input that represents a bounded domain (array index, timestamp, balance, age)
must be explicitly range-constrained. In Noir, use `u8`, `u16`, `u32`, or `u64` instead of
`Field` for bounded values -- the type system enforces the range proof automatically.

**Source:** https://hackmd.io/@aztec-network/disclosure-of-recent-vulnerabilities

---

### PM-02: Aztec Connect -- BigField CRT Overflow

**Project:** Aztec Connect (Aztec 2.0 production system)
**Year:** 2021 (same disclosure as PM-01)
**NoirSec Mapping:** [FA01 -- Integer Overflow in Field](../vulnerabilities/04-field-arithmetic/FA01-integer-overflow-in-field/) + [UC01 -- Missing Range Check](../vulnerabilities/01-under-constrained/UC01-missing-range-check/)
**Severity:** Critical -- allowed proving incorrect arithmetic equations

**What happened:**
When performing arithmetic over non-native fields (emulating a 256-bit integer field inside
the BN254 scalar field using Chinese Remainder Theorem decomposition), the quotient term in
the CRT decomposition was not given a sufficient range constraint. The quotient could overflow
the intended range, meaning a prover could substitute an incorrect quotient that satisfied
the modular equation while representing a different arithmetic result. This broke the
soundness of any computation that relied on the BigField abstraction.

**How it maps to FA01 + UC01:**
This is a compound bug: FA01's field arithmetic overflow vulnerability combined with UC01's
missing range constraint. The underlying issue is that emulating large-integer arithmetic
inside a ZK circuit requires careful range proofs on intermediate values -- the same lesson
both FA01 and UC01 teach. BigField arithmetic is a common pattern in ZK circuits (RSA
verification, ECDSA, cross-chain bridging) and is a high-risk area for exactly this class
of bug.

**Key takeaway for auditors:**
When reviewing circuits that implement arithmetic over non-native fields or emulated integer
types, verify that all intermediate quotients, remainders, and decomposition values have
tight range constraints. The circuit may be logically correct for honest inputs but breakable
with carefully crafted oversized intermediates.

**Source:** https://hackmd.io/@aztec-network/disclosure-of-recent-vulnerabilities

---

### PM-03: QED-It / Picus -- Under-Constrained Bugs in circomlib

**Project:** circomlib (widely used Circom circuit library)
**Year:** 2023 (disclosed via academic paper)
**NoirSec Mapping:** [UC01-UC04](../vulnerabilities/01-under-constrained/) (general under-constrained category)
**Severity:** Critical -- affected circuits used in production ZK applications

**What happened:**
Researchers from QED-It using their Picus automated circuit verification tool discovered
eight zero-day under-constrained vulnerabilities in circomlib, the standard library for
Circom-based ZK circuits. The bugs included comparators, bitwise operations, and hash
function implementations that appeared correct but could accept proofs for false statements.
Several bugs had been present in widely-deployed contracts for years before discovery.

**How it maps to the UC category:**
These bugs are textbook under-constrained patterns: circuits that compute the correct result
for honest inputs but do not fully constrain the witness, allowing a malicious prover to
substitute incorrect values that still satisfy all explicit constraints. The circomlib bugs
and NoirSec's UC01-UC04 challenges share the same root cause -- the gap between a circuit's
intended semantics and its actual constraint set.

**Key takeaway for auditors:**
Standard libraries are not automatically safe. Every imported circuit component should be
reviewed for under-constrained patterns, especially comparators, bitwise operations, and
modular arithmetic. Automated tools like Picus can find these bugs faster than manual review
but are not a substitute for it.

**Source:** https://eprint.iacr.org/2023/512
(Picus: Automated Synthesis of Mechanically Verifiable Zero-Knowledge Proofs)

---

### PM-04: Veridise -- RISC Zero V2 Circuit Bugs

**Project:** RISC Zero ZK virtual machine (V2 circuit)
**Year:** 2024 (security audit)
**NoirSec Mapping:** [UC01 -- Missing Range Check](../vulnerabilities/01-under-constrained/UC01-missing-range-check/), [UC04 -- Duplicate Witness Assignment](../vulnerabilities/01-under-constrained/UC04-duplicate-witness-assignment/)
**Severity:** Critical -- affected the soundness of the RISC Zero proof system

**What happened:**
A Veridise security audit of the RISC Zero V2 circuit discovered multiple under-constrained
bugs including: `ExpandU32` (32-bit decomposition without sufficient range constraints),
`DecomposeLow2` (low-bit decomposition missing a constraint), `DoDiv` (division operation
with an unconstrained quotient), `Decoder` (instruction decoder accepting invalid opcodes),
and `PoseidonStoreOut` (Poseidon hash output without full constraint coverage). Each bug
allowed a malicious prover to produce a valid ZK proof for an incorrect RISC-V execution
trace, breaking the fundamental soundness guarantee of the VM.

**How it maps to UC01/UC04:**
`ExpandU32` and `DecomposeLow2` directly mirror UC01: a value is decomposed into parts
but the parts lack range constraints, allowing incorrect decompositions to be proven.
`DoDiv` mirrors the unconstrained hint pattern in UC02/UC04 where a computed intermediate
value (the quotient) is not fully constrained by the circuit.

**Key takeaway for auditors:**
Bit decomposition and arithmetic decomposition circuits (split a value into limbs, bits,
quotient+remainder) are the highest-risk patterns for missing range constraints. For each
decomposition, verify: (1) each component is range-constrained, (2) the reconstruction
equation is enforced, and (3) the decomposition is unique (no two valid decompositions
for the same value).

**Source:** https://veridise.com/audits/ (RISC Zero V2 audit report)

---

### PM-05: Zcash Sapling -- Silent Counterfeiting Vulnerability

**Project:** Zcash Sapling spend circuit
**Year:** 2019 (fixed silently before public disclosure; disclosed October 2019)
**NoirSec Mapping:** [UC category](../vulnerabilities/01-under-constrained/) -- under-constrained verification in the spend circuit
**Severity:** Critical -- would have enabled unlimited ZEC counterfeiting

**What happened:**
The Zcash spend circuit contained a subtle under-constrained bug in the verification
of the note commitment. The bug was present in production for approximately five months
(March to July 2019) before being identified and fixed in the Sapling upgrade. If exploited,
an attacker could have created ZEC out of thin air by generating a valid spend proof for a
note that was never committed to the blockchain. The Zcash team confirmed no exploitation
occurred during the vulnerability window, and the fix was deployed before public disclosure.

**How it maps to the UC category:**
The Sapling bug is a classic under-constrained verification failure: the circuit accepted
proofs for notes that satisfied the circuit's constraints but did not correspond to actual
on-chain commitments. This is the broadest expression of the UC category -- the constraint
system was insufficient to enforce the intended semantics of "prove membership in the note
commitment tree."

**Key takeaway for auditors:**
Even circuits developed by experienced ZK teams with extensive review can contain critical
under-constrained bugs. For circuits involving Merkle membership proofs, nullifiers, or
commitment verification, formal verification or extensive differential testing should be
applied. The Zcash bug is a strong argument for the importance of tools like Picus and
for the value of security challenges like NoirSec.

**Source:** https://electriccoin.co/blog/zcash-counterfeiting-vulnerability-successfully-remediated/

---

### PM-06: Noir Compiler -- Unconstrained Function Generating Constraints (Issue #4442)

**Project:** Noir compiler (noirc)
**Year:** 2023 (Noir v0.x era)
**NoirSec Mapping:** [UC02 -- Unconstrained Hint Abuse](../vulnerabilities/01-under-constrained/UC02-unconstrained-hint-abuse/)
**Severity:** High -- blurred the boundary between constrained and unconstrained execution

**What happened:**
When a struct containing arrays was passed by value into an `unconstrained` function and
iterated over, the Noir compiler inadvertently generated ACIR constraints for code that
should have executed only in Brillig (native, unconstrained) mode. This meant that code
developers believed was "outside the proof" was silently contributing to the constraint
system. An auditor reviewing the constrained code would believe they had a complete picture
of the circuit's constraints, not realizing the unconstrained code was also generating
hidden constraints.

**How it maps to UC02:**
UC02 demonstrates the inverse but equally dangerous pattern: code that should be
constrained (hint verification) is placed in an unconstrained function and thus generates
no constraints. Issue #4442 shows the reverse: code intended to be unconstrained accidentally
generates constraints. Both bugs exploit the same fundamental confusion between Brillig
(native execution, no proof) and ACIR (proof-generating execution). The lesson for UC02
is precisely the same: the constrained/unconstrained boundary must be treated as a critical
security boundary and audited explicitly.

**Key takeaway for auditors:**
When auditing Noir circuits, explicitly enumerate all `unconstrained fn` calls and verify
that: (1) their return values are fully constrained by subsequent assertions, and (2) no
constraint-generating code accidentally appears in unconstrained context (or vice versa).
Treat the `unsafe` keyword as a security-critical annotation requiring explicit review.

**Source:** https://github.com/noir-lang/noir/issues/4442

---

### PM-07: Noir Compiler -- Constraint Simplification Over-Optimization

**Project:** Noir compiler (noirc SSA optimizer)
**Year:** 2024 (Noir v1.x era)
**NoirSec Mapping:** General UC category -- optimizer removing necessary constraints
**Severity:** High -- optimizer could silently weaken security properties

**What happened:**
Two related bugs in the Noir compiler's SSA optimization pass were discovered: Issue #9806
("Do not simplify constraints with induction variable") and Issue #9857 ("Check for signed
division overflow"). In #9806, the optimizer simplified away constraints that involved loop
induction variables, potentially removing checks that were necessary for soundness. In
#9857, signed integer division could produce results that overflowed without detection.
Both bugs could cause the compiled circuit to be weaker than the source code implied.

**How it maps to the UC category:**
These are compiler-mediated under-constrained vulnerabilities: the source code correctly
specifies constraints, but the compiler removes or weakens them. From an auditor's
perspective, this is more dangerous than a developer error -- the source code review would
appear secure, but the actual deployed circuit would not be. It highlights that the compiler
itself is part of the trusted computing base.

**Key takeaway for auditors:**
For production deployments, audit circuits at the compiled artifact level (ACIR) in addition
to the source level, especially for loops containing security-critical assertions. Check the
Noir CHANGELOG before auditing to identify which compiler versions may have affected the
codebase being reviewed.

**Source:** https://github.com/noir-lang/noir/blob/master/CHANGELOG.md
(Search for issues #9806 and #9857)

---

### PM-08: Noir Compiler -- u128 Left Bit Shift Field Overflow (Issue #9723)

**Project:** Noir compiler (noirc arithmetic)
**Year:** 2024 (Noir v1.x era)
**NoirSec Mapping:** [FA01 -- Integer Overflow in Field](../vulnerabilities/04-field-arithmetic/FA01-integer-overflow-in-field/)
**Severity:** High -- arithmetic operations on u128 could silently overflow into field modulus

**What happened:**
Left bit shifts on `u128` values could overflow the BN254 scalar field modulus, producing
field elements that were arithmetically incorrect as 128-bit integers. A shift that should
produce a value like `2^127` might instead produce a small positive number due to field
reduction. Any circuit relying on large u128 shifts for cryptographic operations (hash
functions, key derivation, large integer arithmetic) could produce incorrect results that
nonetheless passed all circuit assertions.

**How it maps to FA01:**
FA01 demonstrates field overflow in financial arithmetic; Issue #9723 shows the same class
of bug in bitwise operations on large integers. The root cause is identical: an implicit
assumption that 128-bit integer arithmetic operates modulo `2^128`, when in reality it
operates modulo the BN254 prime `p < 2^254`. For `u128`, values above `p` can never
exist, but the field reduction creates unexpected results for shift operations near the
upper range.

**Key takeaway for auditors:**
When reviewing circuits that use large integer types (`u64`, `u128`) in combination with
bitwise operations, verify that the operations cannot produce values that collide with or
overflow into the field modulus. Prefer using values well within the field's safe range for
intermediate computations, and add explicit range assertions after any operation that could
produce large values.

**Source:** https://github.com/noir-lang/noir/blob/master/CHANGELOG.md
(Search for issue #9723 "Left bit shift u128 would overflow Field")

---

## Cross-Reference Index

| NoirSec Vuln | Real-World Precedent(s) |
|--------------|------------------------|
| UC01 | PM-01 (Aztec Connect tree index), PM-03 (circomlib), PM-04 (RISC Zero ExpandU32) |
| UC02 | PM-06 (Noir #4442 unconstrained boundary) |
| UC03 | PM-01 (nullifier-adjacent -- same Aztec disclosure) |
| UC04 | PM-04 (RISC Zero DoDiv quotient) |
| FA01 | PM-02 (Aztec BigField overflow), PM-08 (Noir #9723 bit shift) |
| FA02 | PM-02 (division/quotient constraint class) |
| AZ01 | PM-01 (Aztec nullifier/note spending class) |
| All UC | PM-05 (Zcash Sapling -- broadest UC failure), PM-03 (circomlib), PM-07 (compiler optimizer) |

---

## Resources for Further Reading

- [ZKSecurity.xyz Bug Tracker](https://www.zkbugs.io/) -- curated database of ZK circuit bugs
- [SoK: Security of ZK Proof Systems](https://arxiv.org/pdf/2402.15293) -- academic survey
- [OpenZeppelin: Developer's Guide to Safe Noir Circuits](https://www.openzeppelin.com/news/developer-guide-to-building-safe-noir-circuits)
- [Aztec Network Security Disclosures](https://hackmd.io/@aztec-network/disclosure-of-recent-vulnerabilities)
- [Noir Language Issues (GitHub)](https://github.com/noir-lang/noir/issues)
- [Veridise ZK Audit Reports](https://veridise.com/audits/)
- [Electric Coin Co: Zcash Sapling Counterfeiting Disclosure](https://electriccoin.co/blog/zcash-counterfeiting-vulnerability-successfully-remediated/)
