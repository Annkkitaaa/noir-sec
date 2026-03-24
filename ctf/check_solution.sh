#!/usr/bin/env bash
# NoirSec CTF Solution Checker
# =============================
# Verifies that a proposed exploit for a given challenge ID actually works.
# Usage: bash ctf/check_solution.sh <CHALLENGE_ID>
# Example: bash ctf/check_solution.sh CTF-01

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHALLENGE_ID="${1:-}"

if [ -z "$CHALLENGE_ID" ]; then
    echo "Usage: bash ctf/check_solution.sh <CHALLENGE_ID>"
    echo "Example: bash ctf/check_solution.sh CTF-01"
    echo ""
    echo "Available challenge IDs:"
    grep '^id = ' "$REPO_ROOT/ctf/challenges.toml" | sed 's/id = "\(.*\)"/  \1/'
    exit 1
fi

# Check nargo
if ! command -v nargo &>/dev/null; then
    echo "ERROR: nargo not found. Install nargo and add to PATH."
    exit 1
fi

# Map challenge ID to exploit script
declare -A EXPLOIT_MAP
EXPLOIT_MAP["CTF-01"]="vulnerabilities/01-under-constrained/UC01-missing-range-check/exploit/exploit.sh"
EXPLOIT_MAP["CTF-02"]="vulnerabilities/01-under-constrained/UC02-unconstrained-hint-abuse/exploit/exploit.sh"
EXPLOIT_MAP["CTF-03"]="vulnerabilities/01-under-constrained/UC03-missing-nullifier-uniqueness/exploit/exploit.sh"
EXPLOIT_MAP["CTF-04"]="vulnerabilities/01-under-constrained/UC04-duplicate-witness-assignment/exploit/exploit.sh"
EXPLOIT_MAP["CTF-05"]="vulnerabilities/04-field-arithmetic/FA01-integer-overflow-in-field/exploit/exploit.sh"
EXPLOIT_MAP["CTF-06"]="vulnerabilities/04-field-arithmetic/FA02-division-by-zero-no-constraint/exploit/exploit.sh"
EXPLOIT_MAP["CTF-07"]="vulnerabilities/04-field-arithmetic/FA03-modular-arithmetic-misuse/exploit/exploit.sh"
EXPLOIT_MAP["CTF-08"]="vulnerabilities/03-privacy-leaks/PL01-accidental-public-input/exploit/exploit.sh"
EXPLOIT_MAP["CTF-09"]="vulnerabilities/03-privacy-leaks/PL02-small-domain-hash-brute-force/exploit/exploit.py"
EXPLOIT_MAP["CTF-10"]="vulnerabilities/03-privacy-leaks/PL03-nullifier-identity-leak/exploit/exploit.sh"
EXPLOIT_MAP["CTF-11"]="vulnerabilities/03-privacy-leaks/PL04-correlation-via-public-outputs/exploit/exploit.py"
EXPLOIT_MAP["CTF-12"]="vulnerabilities/02-over-constrained/OC01-unnecessary-range-restriction/exploit/exploit.sh"
EXPLOIT_MAP["CTF-13"]="vulnerabilities/02-over-constrained/OC02-impossible-constraint-combination/exploit/exploit.sh"
EXPLOIT_MAP["CTF-14"]="vulnerabilities/05-logic-errors/LE01-intent-vs-implementation-mismatch/exploit/exploit.sh"
EXPLOIT_MAP["CTF-15"]="vulnerabilities/05-logic-errors/LE02-missing-ownership-check/exploit/exploit.sh"
EXPLOIT_MAP["CTF-16"]="vulnerabilities/05-logic-errors/LE03-replay-attack-no-nonce/exploit/exploit.sh"
EXPLOIT_MAP["CTF-17"]="vulnerabilities/06-aztec-specific/AZ01-note-nullifier-reuse/exploit/exploit.sh"
EXPLOIT_MAP["CTF-18"]="vulnerabilities/06-aztec-specific/AZ02-private-to-public-state-leakage/exploit/exploit.py"
EXPLOIT_MAP["CTF-19"]="vulnerabilities/06-aztec-specific/AZ03-unconstrained-oracle-trust/exploit/exploit.sh"
EXPLOIT_MAP["CTF-20"]="vulnerabilities/06-aztec-specific/AZ04-note-encryption-key-misuse/exploit/exploit.sh"
EXPLOIT_MAP["CTF-21"]="vulnerabilities/06-aztec-specific/AZ05-storage-slot-collision/exploit/exploit.sh"
EXPLOIT_MAP["CTF-22"]="vulnerabilities/06-aztec-specific/AZ06-private-function-sender-trust/exploit/exploit.sh"

EXPLOIT="${EXPLOIT_MAP[$CHALLENGE_ID]:-}"
if [ -z "$EXPLOIT" ]; then
    echo "Unknown challenge ID: $CHALLENGE_ID"
    echo "Run without arguments to see valid IDs."
    exit 1
fi

EXPLOIT_PATH="$REPO_ROOT/$EXPLOIT"
if [ ! -f "$EXPLOIT_PATH" ]; then
    echo "ERROR: Exploit file not found: $EXPLOIT_PATH"
    exit 1
fi

echo "========================================"
echo " NoirSec CTF -- Solution Check"
echo " Challenge: $CHALLENGE_ID"
echo " Exploit:   $EXPLOIT"
echo "========================================"
echo ""

# Run the exploit
if [[ "$EXPLOIT" == *.py ]]; then
    python3 "$EXPLOIT_PATH"
else
    bash "$EXPLOIT_PATH"
fi

EXIT_CODE=$?
echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "========================================"
    echo " EXPLOIT SUCCEEDED -- Challenge solved!"
    echo "========================================"
else
    echo "========================================"
    echo " EXPLOIT FAILED -- Keep trying!"
    echo "========================================"
    exit 1
fi
