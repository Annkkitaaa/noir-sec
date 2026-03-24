# References and Further Reading

Curated bibliography for ZK circuit security, Noir-specific resources, and related tools.

---

## Noir Language and Tooling

**Noir Documentation**
Official language reference, syntax guide, and standard library docs.
https://noir-lang.org/docs

**Aztec Documentation**
Aztec Protocol documentation covering Noir contract patterns, private state, and the kernel circuit.
https://docs.aztec.network

**Nargo CLI Reference**
`nargo check`, `nargo compile`, `nargo execute`, `nargo info`, `nargo prove`, `nargo verify`.
https://noir-lang.org/docs/reference/nargo_commands

**awesome-noir**
Community-maintained list of Noir libraries, projects, and resources.
https://github.com/noir-lang/awesome-noir

---

## ZK Circuit Security: Foundational Reading

**"Underconstrained Circom Vulnerabilities" — OpenZeppelin Blog**
The definitive introduction to under-constrained ZK circuits. Defines the under-constrained / over-constrained taxonomy used as the basis for UC01-UC04 and OC01-OC02 in this corpus. Includes the missing ownership check pattern that directly inspired LE02.
https://blog.openzeppelin.com/top-erc20-token-vulnerabilities

**"Noir Circuit Security" — Nethermind Research / Aztec Forum**
Practical analysis of common Noir-specific pitfalls: unconstrained hint abuse (UC02), field arithmetic (FA01-FA03), privacy leaks (PL01-PL04). Primary reference for the Noir-specific vulnerability classes.
https://discourse.aztec.network

**"Common Vulnerabilities in ZKPs" — Immunefi Blog**
Broad overview of ZK circuit vulnerability classes across Circom, Noir, and Cairo. Useful cross-reference for the taxonomy structure.
https://medium.com/immunefi

---

## Specific Vulnerability References

**Aztec Connect Postmortem — Double Spend Bug**
Real-world incident where a nullifier construction flaw in Aztec Connect allowed double-spending. Direct inspiration for AZ01 (Note Nullifier Reuse). The nullifier was bound only to the owner key, not the note commitment, allowing the same note to be spent multiple times.
https://hackmd.io/@aztec-network/

**"Frozen Heart" Vulnerability — Trail of Bits**
Transcript extraction attack on Fiat-Shamir ZK proofs. Illustrates how a proof system can be exploited at the protocol level rather than the circuit level. Background for understanding the trust model.
https://blog.trailofbits.com/2022/04/13/part-1-coordinated-disclosure-of-vulnerabilities-affecting-girault-bulletproofs-and-plonk/

**"zkSecurity Bug Tracker"**
Open database of ZK circuit bugs found in public audits across Circom, Halo2, and Cairo. Useful for real-world precedent mapping.
https://github.com/0xPARC/zk-bug-tracker

**"SoK: What Don't We Know? Understanding Security Vulnerabilities in SNARKs" — IACR ePrint**
Systematic analysis of 141 ZK circuit bugs across major frameworks. Formalizes the soundness / completeness / zero-knowledge triad and provides empirical data on vulnerability distribution.
https://eprint.iacr.org/2023/547

---

## Automated Analysis Tools

**NAVe: Noir Automated Vulnerability Scanner**
Research prototype from Nethermind for automated detection of under-constrained Noir circuits. Uses symbolic execution to enumerate alternative satisfying witnesses.
(Nethermind Research, 2024)

**QED²: Constraint System Equivalence Checker**
From Veridise. Verifies that two circuit implementations are semantically equivalent — useful for confirming that a patched version preserves the intent of the original.
https://veridise.com/tools/

**Picus**
From Trail of Bits. Symbolic tool for detecting under-constrained circuits by searching for distinct witnesses that satisfy the same public outputs. Applicable to Noir via ACIR.
https://github.com/trailofbits/picus

**zkFuzz**
Academic ZK circuit fuzzer. Tests circuits by generating random witness inputs and checking for unexpected satisfiability. Conceptually similar to the differential_witness.py detector in NoirSec.
(Academic, 2023)

**aztec-lint**
Static analysis rules for Aztec Noir contracts. Catches common Aztec-specific patterns including storage access errors and unconstrained function misuse.
https://github.com/AztecProtocol/

**nargo (built-in)**
`nargo check` and `nargo compile` are first-line detection tools. If a circuit fails to compile, or `nargo info` shows an unexpectedly low gate count after a "fix," the patch may be incomplete.

---

## Academic Background

**"ZKAP: Zero-Knowledge Audit Program" — Formal Framework**
Methodology for systematic ZK circuit audits. Defines audit phases, threat models (prover-adversarial vs verifier-adversarial), and scoring rubrics.

**"Groth16 Trusted Setup Ceremony — Zcash"**
Historical background on the trusted setup problem in ZK proofs. Relevant for understanding why soundness bugs in circuits can have catastrophic consequences.
https://z.cash/technology/paramgen/

**"PlonK: Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge"**
The underlying proof system used by Noir / ACIR. Understanding PlonK's arithmetization helps explain why missing constraints are so dangerous (the prover has full freedom to set unconstrained wires).
https://eprint.iacr.org/2019/953

**"Cairo and Starknet: Provable Programs"**
Comparable ecosystem. Cairo's `felt252` type has the same "no range constraint" pitfall as Noir's `Field`. Many Cairo vulnerability patterns have direct analogs in Noir.
https://docs.starknet.io

---

## Audit Reports (Public)

**Aztec Protocol — Sigma Prime Audit**
Security audit of early Aztec smart contract infrastructure. Covers nullifier construction, circuit soundness, and the kernel circuit security model.

**Aztec Connect — Trail of Bits Audit**
Covers the bridge circuit security model. Includes analysis of note commitment schemes and nullifier uniqueness properties.

**Tornado Cash — Formal Verification Report**
Shows how a ZK application (Circom-based) was formally verified for soundness. Provides a model for what a complete security analysis looks like.

---

## Learning Resources

**ZK Hack Puzzles**
Hands-on CTF-style ZK circuit challenges. Several puzzles involve Groth16/PLONK-based circuits with under-constrained or privacy-leaking patterns directly analogous to NoirSec categories.
https://zkhack.dev/

**0xPARC ZK Learning Resources**
Educational content on ZK proofs, circuit design, and security. Includes worked examples of common circuit bugs.
https://learn.0xparc.org/

**Noir Playground**
Browser-based Noir IDE for experimenting with circuits without installing nargo.
https://play.noir-lang.org/

---

## Citation Template

If you reference NoirSec in research or tooling:

```
NoirSec: Vulnerability Test Suite for Noir ZK Circuits
https://github.com/[your-repo]/noir-sec
Categories: Under-Constrained, Over-Constrained, Privacy Leaks,
            Field Arithmetic, Logic Errors, Aztec-Specific
Circuits: 19 vulnerable + 19 patched (38 total)
```

---

*Last updated: 2025*
