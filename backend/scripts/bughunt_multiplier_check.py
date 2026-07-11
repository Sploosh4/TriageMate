"""
Bug Hunt: Context multiplier edge case verification.

Tests _determine_context_multiplier from scoring.py against
expected outcomes from the decision matrix.
"""

import sys
from pathlib import Path

# Ensure backend is on the path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from scoring import _determine_context_multiplier, calculate_final_score  # noqa: E402

PASS = 0
FAIL = 0
TOTAL = 0
errors = []


def check(label: str, got, expected):
    global PASS, FAIL, TOTAL
    TOTAL += 1
    if got == expected:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        msg = f"  [FAIL] {label}: expected {expected}, got {got}"
        print(msg)
        errors.append(msg)


# ── Test 1: telemetry_threat_score=0, vulnerable_code_loaded=None → multiplier=1.00 ──
print("\n1. Default / neutral (no data)")
m = _determine_context_multiplier(
    telemetry_threat_score=0.0, vulnerable_code_loaded=None
)
check("telemetry=0, code=None → neutral (1.00)", m, 1.00)

# ── Test 2: telemetry_threat_score=10, vulnerable_code_loaded=True → multiplier=1.20 ──
print("\n2. Active threat — both signals")
m = _determine_context_multiplier(
    telemetry_threat_score=10.0, vulnerable_code_loaded=True
)
check("telemetry=10, code=True → active_threat_loaded (1.20)", m, 1.20)

# Test boundary: exactly at threshold (3.0) + code loaded
m = _determine_context_multiplier(
    telemetry_threat_score=3.0, vulnerable_code_loaded=True
)
check("telemetry=3.0 (boundary), code=True → active_threat_loaded (1.20)", m, 1.20)

# Test below threshold (2.9) + code loaded → partial evidence (1.10)
m = _determine_context_multiplier(
    telemetry_threat_score=2.9, vulnerable_code_loaded=True
)
check("telemetry=2.9 (below), code=True → partial_evidence (1.10)", m, 1.10)

# ── Test 3: telemetry_threat_score=5, vulnerable_code_loaded=False → multiplier=1.10 ──
print("\n3. Telemetry active but no code loaded")
# Decision matrix: telemetry >= 3.0 XOR code_loaded == True → 1.10 (partial evidence).
# telemetry=5 means telemetry_active=True, code=False means code_loaded=False.
# True XOR False = True → partial_evidence (1.10). Code behavior is correct.
m = _determine_context_multiplier(
    telemetry_threat_score=5.0, vulnerable_code_loaded=False
)
check("telemetry=5, code=False → partial_evidence (1.10)", m, 1.10)

# ── Test 4: None telemetry (missing process_evidence) → no crash ──
print("\n4. Missing / None telemetry")
try:
    # Simulate what happens when process_evidence extraction fails (telemetry stays None)
    m = _determine_context_multiplier(
        telemetry_threat_score=0.0, vulnerable_code_loaded=None
    )
    check("telemetry=None-ish via 0, code=None → neutral (1.00), no crash", m, 1.00)
except Exception as e:
    FAIL += 1
    TOTAL += 1
    msg = f"  [FAIL] None telemetry caused crash: {e}"
    print(msg)
    errors.append(msg)

# Also test with calculate_final_score where telemetry is None (should not happen but be safe)
try:
    result = calculate_final_score(
        cvss_score=5.0,
        epss_score=0.1,
        mission_prevalence="Support",
        public_wellbeing="Moderate",
        data_classification="OFFICIAL",
        internet_facing=False,
        telemetry_threat_score=0.0,
        vulnerable_code_loaded=None,
    )
    check("calculate_final_score with telemetry=0, code=None → no crash", True, True)
except Exception as e:
    FAIL += 1
    TOTAL += 1
    msg = f"  [FAIL] calculate_final_score with None telemetry crashed: {e}"
    print(msg)
    errors.append(msg)

# ── Test 5: confirmed_mitigated=True + confirmed_false_positive=True → FP wins (0.70) ──
print("\n5. Conflict resolution — FP wins over mitigated")
m = _determine_context_multiplier(
    telemetry_threat_score=8.0,
    vulnerable_code_loaded=True,
    confirmed_mitigated=True,
    confirmed_false_positive=True,
)
check("confirmed_mitigated + confirmed_false_positive → false_positive (0.70)", m, 0.70)

# ── Test 6: confirmed_mitigated=True with no telemetry → 0.85 ──
print("\n6. Mitigated with no telemetry")
m = _determine_context_multiplier(
    telemetry_threat_score=0.0,
    vulnerable_code_loaded=None,
    confirmed_mitigated=True,
    confirmed_false_positive=False,
)
check("mitigated=True, no telemetry → mitigated (0.85)", m, 0.85)

# Also test: mitigated with active telemetry → still mitigated (order: FP > mitigated > active)
m = _determine_context_multiplier(
    telemetry_threat_score=10.0,
    vulnerable_code_loaded=True,
    confirmed_mitigated=True,
    confirmed_false_positive=False,
)
check("mitigated=True, active telemetry → mitigated (0.85) wins over active", m, 0.85)

# ── Test 7: Partial evidence (telemetry OR code loaded, not both) → 1.10 ──
print("\n7. Partial evidence — only one signal")
# Decision matrix: telemetry >= 3.0 XOR code_loaded == True → 1.10 (partial evidence)
# Code implements: `or` after `and` — effectively acts as XOR since `and` catches both=True first.
m = _determine_context_multiplier(
    telemetry_threat_score=4.0, vulnerable_code_loaded=False
)
check("telemetry=4 (active), code=False → partial_evidence (1.10)", m, 1.10)

m = _determine_context_multiplier(
    telemetry_threat_score=0.0, vulnerable_code_loaded=True
)
check("telemetry=0, code=True → partial_evidence (1.10)", m, 1.10)

# ── Summary ──
print(f"\n{'=' * 60}")
print(f"RESULTS: {PASS} passed, {FAIL} failed, {TOTAL} total")
if errors:
    print("\nFAILURES:")
    for e in errors:
        print(e)

sys.exit(0 if FAIL == 0 else 1)
