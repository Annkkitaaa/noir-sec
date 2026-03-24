#!/usr/bin/env bash
# NoirSec: Run All Detection Scripts
# ====================================
# Runs all automated detectors against all vulnerability challenges.
# Produces a summary table showing which vulnerabilities were auto-detected.
#
# Usage: bash detection/run_all.sh
# Requirements: nargo installed, Python 3.10+, run in WSL on Windows

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DETECT_DIR="$REPO_ROOT/detection"

echo "============================================"
echo " NoirSec — Automated Detection Run"
echo "============================================"
echo ""
echo "Note: Automated detection has significant limitations."
echo "      See detection/README.md for the detection limitation table."
echo ""

# Check dependencies
if ! command -v nargo &>/dev/null; then
    echo "ERROR: nargo not found. Run: bash scripts/setup.sh"
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found. Install Python 3.10+"
    exit 1
fi

PASS=0
PARTIAL=0
MANUAL=0

run_detector() {
    local vuln_id="$1"
    local vuln_dir="$2"
    local detector="$3"
    local expected="$4"

    echo -n "  $vuln_id [$detector]: "

    if [ ! -d "$vuln_dir" ]; then
        echo "SKIP (directory not found)"
        return
    fi

    case "$detector" in
        differential)
            output=$(python3 "$DETECT_DIR/differential_witness.py" "$vuln_dir" 2>&1)
            if echo "$output" | grep -q "FINDING"; then
                echo "DETECTED"
                ((PASS++)) || true
            else
                echo "not detected (manual review needed)"
                ((PARTIAL++)) || true
            fi
            ;;
        privacy)
            output=$(python3 "$DETECT_DIR/privacy_leak_fuzzer.py" "$vuln_dir" 2>&1)
            if echo "$output" | grep -q "FINDING"; then
                echo "DETECTED"
                ((PASS++)) || true
            else
                echo "not detected (manual review needed)"
                ((PARTIAL++)) || true
            fi
            ;;
        manual)
            echo "MANUAL REVIEW REQUIRED (automated detection not applicable)"
            ((MANUAL++)) || true
            ;;
    esac
}

echo "--- Under-Constrained ---"
run_detector "UC01" "$REPO_ROOT/vulnerabilities/01-under-constrained/UC01-missing-range-check/vulnerable"         "differential" "DETECTED"
run_detector "UC02" "$REPO_ROOT/vulnerabilities/01-under-constrained/UC02-unconstrained-hint-abuse/vulnerable"   "manual"        "MANUAL"
run_detector "UC03" "$REPO_ROOT/vulnerabilities/01-under-constrained/UC03-missing-nullifier-uniqueness/vulnerable" "differential" "PARTIAL"
run_detector "UC04" "$REPO_ROOT/vulnerabilities/01-under-constrained/UC04-duplicate-witness-assignment/vulnerable" "differential" "PARTIAL"
echo ""

echo "--- Over-Constrained ---"
run_detector "OC01" "$REPO_ROOT/vulnerabilities/02-over-constrained/OC01-unnecessary-range-restriction/vulnerable" "differential" "PARTIAL"
run_detector "OC02" "$REPO_ROOT/vulnerabilities/02-over-constrained/OC02-impossible-constraint-combination/vulnerable" "differential" "PARTIAL"
echo ""

echo "--- Privacy Leaks ---"
run_detector "PL01" "$REPO_ROOT/vulnerabilities/03-privacy-leaks/PL01-accidental-public-input/vulnerable"       "privacy"   "DETECTED"
run_detector "PL02" "$REPO_ROOT/vulnerabilities/03-privacy-leaks/PL02-small-domain-hash-brute-force/vulnerable" "privacy"   "DETECTED"
run_detector "PL03" "$REPO_ROOT/vulnerabilities/03-privacy-leaks/PL03-nullifier-identity-leak/vulnerable"       "manual"    "MANUAL"
run_detector "PL04" "$REPO_ROOT/vulnerabilities/03-privacy-leaks/PL04-correlation-via-public-outputs/vulnerable" "manual"   "MANUAL"
echo ""

echo "--- Field Arithmetic ---"
run_detector "FA01" "$REPO_ROOT/vulnerabilities/04-field-arithmetic/FA01-integer-overflow-in-field/vulnerable" "differential" "PARTIAL"
run_detector "FA02" "$REPO_ROOT/vulnerabilities/04-field-arithmetic/FA02-division-by-zero-no-constraint/vulnerable" "differential" "DETECTED"
run_detector "FA03" "$REPO_ROOT/vulnerabilities/04-field-arithmetic/FA03-modular-arithmetic-misuse/vulnerable"  "manual"       "MANUAL"
echo ""

echo "--- Logic Errors ---"
run_detector "LE01" "$REPO_ROOT/vulnerabilities/05-logic-errors/LE01-intent-vs-implementation-mismatch/vulnerable" "privacy"  "PARTIAL"
run_detector "LE02" "$REPO_ROOT/vulnerabilities/05-logic-errors/LE02-missing-ownership-check/vulnerable"           "manual"   "MANUAL"
run_detector "LE03" "$REPO_ROOT/vulnerabilities/05-logic-errors/LE03-replay-attack-no-nonce/vulnerable"            "manual"   "MANUAL"
echo ""

echo "--- Aztec-Specific ---"
run_detector "AZ01" "$REPO_ROOT/vulnerabilities/06-aztec-specific/AZ01-note-nullifier-reuse/vulnerable"           "differential" "PARTIAL"
run_detector "AZ02" "$REPO_ROOT/vulnerabilities/06-aztec-specific/AZ02-private-to-public-state-leakage/vulnerable" "manual"      "MANUAL"
run_detector "AZ03" "$REPO_ROOT/vulnerabilities/06-aztec-specific/AZ03-unconstrained-oracle-trust/vulnerable"      "manual"      "MANUAL"
run_detector "AZ04" "$REPO_ROOT/vulnerabilities/06-aztec-specific/AZ04-note-encryption-key-misuse/vulnerable"      "manual"      "MANUAL"
run_detector "AZ05" "$REPO_ROOT/vulnerabilities/06-aztec-specific/AZ05-storage-slot-collision/vulnerable"          "differential" "PARTIAL"
run_detector "AZ06" "$REPO_ROOT/vulnerabilities/06-aztec-specific/AZ06-private-function-sender-trust/vulnerable"   "manual"      "MANUAL"
echo ""

TOTAL=$((PASS + PARTIAL + MANUAL))
echo "============================================"
echo " Detection Summary:"
echo "   Auto-detected:     $PASS/$TOTAL"
echo "   Partial/heuristic: $PARTIAL/$TOTAL"
echo "   Manual only:       $MANUAL/$TOTAL"
echo ""
echo " Key insight: $MANUAL vulnerabilities require MANUAL review."
echo " Automated tools cover ~$(( (PASS + PARTIAL) * 100 / TOTAL ))% of vulnerability classes."
echo " A skilled human auditor is essential for complete coverage."
echo "============================================"
echo ""

# ── Optional: Differential Witness Batch Scan ─────────────────────────────────
echo "--- Differential Witness Batch Scan (noir_diff_test.py) ---"
echo "    Comparing all vulnerable/patched pairs for constraint divergence..."
echo "    (this may take a few minutes -- use Ctrl+C to skip)"
echo ""
python3 "$DETECT_DIR/noir_diff_test.py" --scan-all "$REPO_ROOT/vulnerabilities/" --iterations 15
