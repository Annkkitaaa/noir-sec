# NoirSec — Validation Report

Generated: 2026-03-24 16:09

---

## Vulnerability Coverage

| ID | Name | Severity | Difficulty | Vulnerable | Patched |
|----|------|----------|------------|------------|---------|
| UC01 | Missing Range Check | 🔴 Critical | Easy | ✅ | ✅ |
| UC02 | Unconstrained Hint Abuse | 🔴 Critical | Medium | ✅ | ✅ |
| UC03 | Missing Nullifier Uniqueness | 🔴 Critical | Medium | ✅ | ✅ |
| UC04 | Duplicate Witness Assignment | 🟠 High | Medium | ✅ | ✅ |
| OC01 | Unnecessary Range Restriction | 🟡 Medium | Easy | ✅ | ✅ |
| OC02 | Impossible Constraint Combination | 🟡 Medium | Easy | ✅ | ✅ |
| PL01 | Accidental Public Input | 🟠 High | Easy | ✅ | ✅ |
| PL02 | Small Domain Hash Brute Force | 🟠 High | Medium | ✅ | ✅ |
| PL03 | Nullifier as Identity Leak | 🟠 High | Medium | ✅ | ✅ |
| PL04 | Correlation via Public Outputs | 🟡 Medium | Hard | ✅ | ✅ |
| FA01 | Integer Overflow in Field | 🔴 Critical | Medium | ✅ | ✅ |
| FA02 | Division by Zero | 🟠 High | Easy | ✅ | ✅ |
| FA03 | Modular Arithmetic Misuse | 🟠 High | Medium | ✅ | ✅ |
| LE01 | Intent vs Implementation | 🟠 High | Hard | ✅ | ✅ |
| LE02 | Missing Ownership Check | 🔴 Critical | Medium | ✅ | ✅ |
| LE03 | Replay Attack (No Nonce) | 🟠 High | Easy | ✅ | ✅ |
| AZ01 | Note Nullifier Reuse | 🔴 Critical | Medium | ✅ | ✅ |
| AZ02 | Private-to-Public Leakage | 🟠 High | Hard | ✅ | ✅ |
| AZ03 | Unconstrained Oracle Trust | 🔴 Critical | Medium | ✅ | ✅ |
| AZ04 | Note Encryption Key Misuse | 🟠 High | Medium | ✅ | ✅ |
| AZ05 | Storage Slot Collision | 🟠 High | Medium | ✅ | ✅ |
| AZ06 | Private Function Sender Trust | 🔴 Critical | Hard | ✅ | ✅ |

**Total:** 22 vulnerabilities | Vulnerable circuits: 22/22 | Patched circuits: 22/22

---

## Notes

- Run `bash scripts/verify_all.sh` to compile-check all circuits with nargo
- Run `bash detection/run_all.sh` for automated detection analysis
- See [TAXONOMY.md](TAXONOMY.md) for full vulnerability descriptions
