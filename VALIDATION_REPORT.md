# NoirSec — Full Validation Report

**Date:** 2026-03-24 (Updated with additions)
**Nargo version:** 1.0.0-beta.19
**Platform:** Windows 11 + WSL (Ubuntu)
**Circuits:** 50 total (22 vulnerable + 22 patched + 3 near-miss + 3 compiler-bug reproductions)

---

## Step 1: Environment

| Check | Result |
|-------|--------|
| nargo installed | ✅ v1.0.0-beta.19 via direct tarball to `/home/ankitasingh/.nargo/bin/` |
| WSL available | ✅ Ubuntu |
| BN254 prime respected | ✅ All Prover.toml values < field modulus |

---

## Step 2: Compile All Circuits

`bash scripts/verify_all.sh` → **50/50 PASS, 0 FAIL**

All circuits compile cleanly under nargo beta.19.

Fixes applied during build:
- Replaced non-ASCII characters (em/en dashes, `→`, `∈`, `∞`) with ASCII equivalents
- Changed `Field` comparison types to `u64`/`u8` where required
- Added `as Field` casts for `pedersen_hash` inputs
- Moved inner `unconstrained fn` to top-level (FA03)

---

## Step 3: Execute All Circuits

Final result: **36 PASS | 2 EXPECTED FAIL | 0 GENUINE FAIL** (core 38 circuits)

Additional circuits (AZ04-AZ06 vulnerable/patched, near-miss x3, CB reproductions x3): all PASS

| Circuit | Result | Notes |
|---------|--------|-------|
| UC01 vulnerable | ✅ PASS | Age=5 accepted (no range check) |
| UC01 patched | ✅ PASS | u8 range check enforced |
| UC02 vulnerable | ✅ PASS | Prime 7 "proven" composite |
| UC02 patched | ✅ PASS | f0*f1==n constraint enforced |
| UC03 vulnerable | ✅ PASS | Duplicate nullifier possible |
| UC03 patched | ✅ PASS | Note salt included in hash |
| UC04 vulnerable | ✅ PASS | One credential satisfies 2-of-2 |
| UC04 patched | ✅ PASS | Duplicate check enforced |
| OC01 vulnerable | ⚠️ XFAIL | Expected: valid token_id rejected (u32 overflow) |
| OC01 patched | ✅ PASS | u64 type accepts any valid token_id |
| OC02 vulnerable | ⚠️ XFAIL | Expected: impossible constraint combination |
| OC02 patched | ✅ PASS | Contradictory assert removed |
| PL01 vulnerable | ✅ PASS | Secret exposed as public input |
| PL01 patched | ✅ PASS | Secret is private |
| PL02 vulnerable | ✅ PASS | Small domain hash brute-forceable |
| PL02 patched | ✅ PASS | Salt added to hash |
| PL03 vulnerable | ✅ PASS | Nullifier = hash(address) leaks identity |
| PL03 patched | ✅ PASS | Nullifier includes random note_secret |
| PL04 vulnerable | ✅ PASS | Demographic quasi-identifiers published |
| PL04 patched | ✅ PASS | Only vote_commitment published |
| FA01 vulnerable | ✅ PASS | Field overflow accepted |
| FA01 patched | ✅ PASS | u64 overflow rejected |
| FA02 vulnerable | ✅ PASS | Division by zero accepted |
| FA02 patched | ✅ PASS | Zero denominator rejected |
| FA03 vulnerable | ✅ PASS | Field arithmetic misuse |
| FA03 patched | ✅ PASS | u64 integer arithmetic enforced |
| LE01 vulnerable | ✅ PASS | Dead variable metadata_hash |
| LE01 patched | ✅ PASS | metadata_hash constrained |
| LE02 vulnerable | ✅ PASS | user_id not bound to sk |
| LE02 patched | ✅ PASS | user_id = pedersen_hash([sk]) |
| LE03 vulnerable | ✅ PASS | No nonce (replay possible) |
| LE03 patched | ✅ PASS | Nonce bound to commitment |
| AZ01 vulnerable | ✅ PASS | Nullifier reuse possible |
| AZ01 patched | ✅ PASS | Nullifier includes note_hash |
| AZ02 vulnerable | ✅ PASS | Commitment leaks balance history |
| AZ02 patched | ✅ PASS | Commitment includes salt |
| AZ03 vulnerable | ✅ PASS | Oracle price unconstrained |
| AZ03 patched | ✅ PASS | Oracle price is public + committed |

**OC01/OC02 vulnerable expected failures are the vulnerability demonstrations themselves.**

---

## Step 4: Exploit Validation

All 19 exploit scripts exit with rc=0.

### Active Exploits (nargo execute proven)

| Script | Result |
|--------|--------|
| UC01 exploit.sh | ✅ age=p-1 bypasses age check; patched rejects it |
| UC02 exploit.sh | ✅ Prime 7 "proven" composite; patched catches it |
| UC04 exploit.sh | ✅ credential=42 satisfies 2-of-2; patched blocks it |
| FA01 exploit.sh | ✅ Overdraft of field(p-1) tokens accepted; patched blocks it |
| FA02 exploit.sh | ✅ Zero-capital loan accepted; patched blocks it |
| LE02 exploit.sh | ✅ Bob authorizes Alice's user_id=1; patched blocks it |

### Conceptual Demonstrations (valid for multi-tx/off-chain attacks)

| Script | Type | Reason |
|--------|------|--------|
| UC03 exploit.sh | Conceptual | Nullifier collision requires blockchain state |
| OC01 exploit.sh | Conceptual | Shows valid input rejected (over-constraint) |
| OC02 exploit.sh | Conceptual | Shows patched circuit accepts valid input |
| PL01 exploit.sh | Conceptual | Privacy leakage (no proof forgery needed) |
| FA03 exploit.sh | Conceptual | Field-near-prime exploit is complex to stage |
| LE01 exploit.sh | Conceptual | Information leakage analysis |
| LE03 exploit.sh | Conceptual | Replay requires two distinct proof submissions |
| AZ01 exploit.sh | Conceptual | Nullifier DoS requires nullifier tree state |
| AZ03 exploit.sh | Conceptual | Oracle manipulation requires Brillig modification |

Python exploits (PL02, PL03, PL04, AZ02): ✅ All run successfully — demonstrate off-chain analysis attacks.

---

## Step 5: Script Validation

| Check | Result |
|-------|--------|
| All 15 exploit.sh executable (+x) | ✅ |
| All 4 exploit.py executable (+x) | ✅ |
| Shell syntax (bash -n) | ✅ 15/15 clean |
| Python syntax (py_compile) | ✅ 4/4 clean |

---

## Step 6: Detection Scripts

| Script | Status |
|--------|--------|
| `detection/constraint_counter.py` | ✅ Parses nargo info gate counts; correctly shows +/- constraints |
| `detection/differential_witness.py` | ✅ Runs witness mutation tests; reports limitations |
| `detection/privacy_leak_fuzzer.py` | ✅ Detects public param exposure and domain size |
| `scripts/verify_all.sh` | ✅ 38/38 PASS |
| `scripts/generate_report.py` | ✅ Generates REPORT.md with 19/19 coverage |

Bug fixed: `constraint_counter.py` regex `{2,6}` → `{1,6}` to match 1-digit gate counts.

---

## Step 7: Documentation

| Check | Result |
|-------|--------|
| 21 README files present | ✅ |
| All 19 vuln READMEs have Vulnerability + Fix sections | ✅ 19/19 |
| README.md references all 19 vulns | ✅ |
| TAXONOMY.md references all 19 vulns | ✅ (519 lines) |

---

## Step 8: Final Suite Summary (v1.0 baseline)

```
Circuits:      38 total  (19 vulnerable + 19 patched)
Execute pass:  36/38     (2 XFAIL by design -- OC01/OC02 vulnerable)
Exploits:       6 active + 9 conceptual + 4 Python = 19 total (0 errors)
Scripts:       15 bash + 4 Python -- 19/19 syntactically valid
Detection:      3 tools working
Docs:          21 README + TAXONOMY + REPORT generated
```

**NoirSec v1.0 validation: COMPLETE**

---

## Step 9: Additions Summary (v1.1)

| Addition | Status | Details |
|----------|--------|---------|
| AZ04-AZ06 new Aztec vulns | ✅ COMPLETE | 6 new circuits (3 vuln + 3 patched), 3 exploits |
| Differential testing framework | ✅ COMPLETE | `detection/noir_diff_test.py` -- detects 7/22 UC signals |
| Real-world postmortems | ✅ COMPLETE | `resources/POSTMORTEMS.md` -- 8 incidents, PM-01 to PM-08 |
| Compiler bug reproductions | ✅ COMPLETE | `compiler-bugs/` -- CB01-CB03 all compile on beta.19 |
| Near-miss examples | ✅ COMPLETE | UC01, UC02, AZ01 near-miss circuits all execute |
| CTF wrapper | ✅ COMPLETE | `ctf/` -- 22 challenges, 4400 points, check_solution.sh |
| Impact justifications | ✅ COMPLETE | All 22 vuln READMEs have Impact Assessment sections |
| GitHub Actions CI | ✅ COMPLETE | `.github/workflows/verify.yml` |

### v1.1 Final Numbers

```
Circuits:      50 total (22 vuln + 22 patched + 3 near-miss + 3 CB reproductions)
Compile check: 50/50 PASS (verify_all.sh)
Vulnerability coverage: 22/22
CTF challenges: 22 (4400 points total)
Compiler bugs: 3 (CB01-CB03 with READMEs and reproductions)
Near-miss examples: 3 (UC01, UC02, AZ01)
Real-world incidents mapped: 8 (PM-01 to PM-08)
Differential test signals: 7/22 pairs detected automatically
```

**NoirSec v1.1 validation: COMPLETE ✅**

---

## Known Limitations

1. **OC01/OC02 vulnerable circuits always fail** — this IS the vulnerability demonstration. Valid inputs are rejected. No Prover.toml fix is possible by design.

2. **Some exploits are conceptual** — multi-transaction attacks (replay, nullifier DoS), Brillig oracle manipulation, and blockchain-state-dependent attacks cannot be demonstrated in a single `nargo execute` call.

3. **constraint_counter interpretation for UC01** — UC01 vulnerable has more gates than patched because the vulnerable circuit still calls `pedersen_hash` (unused hash computation). The interpretation "patched has fewer constraints" is technically correct but counter-intuitive for this specific case.

4. **nargo beta.19 compatibility** — All circuits use features available in nargo 1.0.0-beta.19. Some newer Noir syntax may require updating `compiler_version` in Nargo.toml if upgrading.
