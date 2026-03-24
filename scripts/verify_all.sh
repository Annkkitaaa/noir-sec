#!/usr/bin/env bash
# NoirSec — Verify All Circuits
# Compiles and checks every vulnerable and patched circuit in the repository.
# Usage: bash scripts/verify_all.sh

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0
FAIL=0
SKIP=0

echo "============================================"
echo " NoirSec — Verifying All Circuits"
echo "============================================"
echo ""

check_circuit() {
    local path="$1"
    local label="$2"
    if [ ! -d "$path" ]; then
        echo "  SKIP $label (directory not found)"
        ((SKIP++)) || true
        return
    fi
    cd "$path"
    if nargo check 2>/dev/null; then
        echo "  PASS $label"
        ((PASS++)) || true
    else
        echo "  FAIL $label"
        ((FAIL++)) || true
    fi
    cd "$REPO_ROOT"
}

# Category 1: Under-Constrained
echo "--- 01 Under-Constrained ---"
check_circuit "vulnerabilities/01-under-constrained/UC01-missing-range-check/vulnerable"        "UC01 vulnerable"
check_circuit "vulnerabilities/01-under-constrained/UC01-missing-range-check/patched"           "UC01 patched"
check_circuit "vulnerabilities/01-under-constrained/UC02-unconstrained-hint-abuse/vulnerable"   "UC02 vulnerable"
check_circuit "vulnerabilities/01-under-constrained/UC02-unconstrained-hint-abuse/patched"      "UC02 patched"
check_circuit "vulnerabilities/01-under-constrained/UC03-missing-nullifier-uniqueness/vulnerable" "UC03 vulnerable"
check_circuit "vulnerabilities/01-under-constrained/UC03-missing-nullifier-uniqueness/patched"    "UC03 patched"
check_circuit "vulnerabilities/01-under-constrained/UC04-duplicate-witness-assignment/vulnerable" "UC04 vulnerable"
check_circuit "vulnerabilities/01-under-constrained/UC04-duplicate-witness-assignment/patched"    "UC04 patched"
echo ""

# Category 2: Over-Constrained
echo "--- 02 Over-Constrained ---"
check_circuit "vulnerabilities/02-over-constrained/OC01-unnecessary-range-restriction/vulnerable" "OC01 vulnerable"
check_circuit "vulnerabilities/02-over-constrained/OC01-unnecessary-range-restriction/patched"    "OC01 patched"
check_circuit "vulnerabilities/02-over-constrained/OC02-impossible-constraint-combination/vulnerable" "OC02 vulnerable"
check_circuit "vulnerabilities/02-over-constrained/OC02-impossible-constraint-combination/patched"    "OC02 patched"
echo ""

# Category 3: Privacy Leaks
echo "--- 03 Privacy Leaks ---"
check_circuit "vulnerabilities/03-privacy-leaks/PL01-accidental-public-input/vulnerable" "PL01 vulnerable"
check_circuit "vulnerabilities/03-privacy-leaks/PL01-accidental-public-input/patched"    "PL01 patched"
check_circuit "vulnerabilities/03-privacy-leaks/PL02-small-domain-hash-brute-force/vulnerable" "PL02 vulnerable"
check_circuit "vulnerabilities/03-privacy-leaks/PL02-small-domain-hash-brute-force/patched"    "PL02 patched"
check_circuit "vulnerabilities/03-privacy-leaks/PL03-nullifier-identity-leak/vulnerable" "PL03 vulnerable"
check_circuit "vulnerabilities/03-privacy-leaks/PL03-nullifier-identity-leak/patched"    "PL03 patched"
check_circuit "vulnerabilities/03-privacy-leaks/PL04-correlation-via-public-outputs/vulnerable" "PL04 vulnerable"
check_circuit "vulnerabilities/03-privacy-leaks/PL04-correlation-via-public-outputs/patched"    "PL04 patched"
echo ""

# Category 4: Field Arithmetic
echo "--- 04 Field Arithmetic ---"
check_circuit "vulnerabilities/04-field-arithmetic/FA01-integer-overflow-in-field/vulnerable" "FA01 vulnerable"
check_circuit "vulnerabilities/04-field-arithmetic/FA01-integer-overflow-in-field/patched"    "FA01 patched"
check_circuit "vulnerabilities/04-field-arithmetic/FA02-division-by-zero-no-constraint/vulnerable" "FA02 vulnerable"
check_circuit "vulnerabilities/04-field-arithmetic/FA02-division-by-zero-no-constraint/patched"    "FA02 patched"
check_circuit "vulnerabilities/04-field-arithmetic/FA03-modular-arithmetic-misuse/vulnerable" "FA03 vulnerable"
check_circuit "vulnerabilities/04-field-arithmetic/FA03-modular-arithmetic-misuse/patched"    "FA03 patched"
echo ""

# Category 5: Logic Errors
echo "--- 05 Logic Errors ---"
check_circuit "vulnerabilities/05-logic-errors/LE01-intent-vs-implementation-mismatch/vulnerable" "LE01 vulnerable"
check_circuit "vulnerabilities/05-logic-errors/LE01-intent-vs-implementation-mismatch/patched"    "LE01 patched"
check_circuit "vulnerabilities/05-logic-errors/LE02-missing-ownership-check/vulnerable" "LE02 vulnerable"
check_circuit "vulnerabilities/05-logic-errors/LE02-missing-ownership-check/patched"    "LE02 patched"
check_circuit "vulnerabilities/05-logic-errors/LE03-replay-attack-no-nonce/vulnerable" "LE03 vulnerable"
check_circuit "vulnerabilities/05-logic-errors/LE03-replay-attack-no-nonce/patched"    "LE03 patched"
echo ""

# Category 6: Aztec-Specific
echo "--- 06 Aztec-Specific ---"
check_circuit "vulnerabilities/06-aztec-specific/AZ01-note-nullifier-reuse/vulnerable" "AZ01 vulnerable"
check_circuit "vulnerabilities/06-aztec-specific/AZ01-note-nullifier-reuse/patched"    "AZ01 patched"
check_circuit "vulnerabilities/06-aztec-specific/AZ02-private-to-public-state-leakage/vulnerable" "AZ02 vulnerable"
check_circuit "vulnerabilities/06-aztec-specific/AZ02-private-to-public-state-leakage/patched"    "AZ02 patched"
check_circuit "vulnerabilities/06-aztec-specific/AZ03-unconstrained-oracle-trust/vulnerable" "AZ03 vulnerable"
check_circuit "vulnerabilities/06-aztec-specific/AZ03-unconstrained-oracle-trust/patched"    "AZ03 patched"
check_circuit "vulnerabilities/06-aztec-specific/AZ04-note-encryption-key-misuse/vulnerable" "AZ04 vulnerable"
check_circuit "vulnerabilities/06-aztec-specific/AZ04-note-encryption-key-misuse/patched"    "AZ04 patched"
check_circuit "vulnerabilities/06-aztec-specific/AZ05-storage-slot-collision/vulnerable" "AZ05 vulnerable"
check_circuit "vulnerabilities/06-aztec-specific/AZ05-storage-slot-collision/patched"    "AZ05 patched"
check_circuit "vulnerabilities/06-aztec-specific/AZ06-private-function-sender-trust/vulnerable" "AZ06 vulnerable"
check_circuit "vulnerabilities/06-aztec-specific/AZ06-private-function-sender-trust/patched"    "AZ06 patched"
echo ""

# Near-miss examples
echo "--- Near-Miss Examples ---"
check_circuit "vulnerabilities/01-under-constrained/UC01-missing-range-check/near-miss"  "UC01 near-miss"
check_circuit "vulnerabilities/01-under-constrained/UC02-unconstrained-hint-abuse/near-miss" "UC02 near-miss"
check_circuit "vulnerabilities/06-aztec-specific/AZ01-note-nullifier-reuse/near-miss"    "AZ01 near-miss"
echo ""

# Compiler bug reproductions
echo "--- Compiler Bug Reproductions ---"
check_circuit "compiler-bugs/CB01-unconstrained-struct-constraints/reproduction" "CB01 reproduction"
check_circuit "compiler-bugs/CB02-constraint-simplification-loop/reproduction"  "CB02 reproduction"
check_circuit "compiler-bugs/CB03-u128-shift-field-overflow/reproduction"       "CB03 reproduction"
echo ""

echo "============================================"
echo " Results: PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
