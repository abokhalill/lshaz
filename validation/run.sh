#!/usr/bin/env bash
# lshaz Validation Harness — Top-Level Runner
# Executes Tier 1 (corpus regression) and/or Tier 2 (ground truth benchmarks).
#
# Usage:
#   ./validation/run.sh                        # Both tiers
#   ./validation/run.sh --tier1                # Corpus regression only
#   ./validation/run.sh --tier2                # Ground truth benchmarks only
#   ./validation/run.sh --tier2 --no-perf      # Skip perf counters
#   ./validation/run.sh --tier2 --rule FL002   # Single rule benchmark
#   ./validation/run.sh --help                 # Show this help
#
# Exit codes:
#   0  All assertions passed
#   1  One or more assertions failed

set -uo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    sed -n '2,/^$/s/^# \?//p' "$0"
    exit 0
}

RUN_TIER1=true
RUN_TIER2=true
TIER2_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h) usage ;;
        --tier1)   RUN_TIER1=true; RUN_TIER2=false; shift ;;
        --tier2)   RUN_TIER1=false; RUN_TIER2=true; shift ;;
        --rule)    TIER2_ARGS+=("$1" "$2"); shift 2 ;;
        --no-perf) TIER2_ARGS+=("$1"); shift ;;
        *)
            echo "Unknown flag: $1" >&2
            usage
            ;;
    esac
done

# Ensure binary is built.
if [[ ! -x "$ROOT_DIR/build/lshaz" ]]; then
    echo "Building lshaz..."
    cmake -S "$ROOT_DIR" -B "$ROOT_DIR/build" -DCMAKE_BUILD_TYPE=Release >/dev/null 2>&1
    cmake --build "$ROOT_DIR/build" -j"$(nproc)" 2>&1
    echo ""
fi

TIER1_EXIT=0
TIER2_EXIT=0

echo "╔══════════════════════════════════════════════╗"
echo "║       lshaz Validation Harness               ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

if $RUN_TIER1; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  TIER 1: Corpus-Scale Regression"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    bash "$SCRIPT_DIR/tier1/run_corpus.sh" || TIER1_EXIT=$?
    echo ""
fi

if $RUN_TIER2; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  TIER 2: Ground Truth Microbenchmarks"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    if [[ ${#TIER2_ARGS[@]} -gt 0 ]]; then
        bash "$SCRIPT_DIR/tier2/run_benchmarks.sh" "${TIER2_ARGS[@]}" || TIER2_EXIT=$?
    else
        bash "$SCRIPT_DIR/tier2/run_benchmarks.sh" || TIER2_EXIT=$?
    fi

    # Statistical analysis if results exist.
    if [[ -d "$SCRIPT_DIR/tier2/results" ]] && command -v python3 >/dev/null 2>&1; then
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  TIER 2: Statistical Analysis"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        python3 "$SCRIPT_DIR/tier2/analyze_results.py" "$SCRIPT_DIR/tier2/results" || true
    fi
    echo ""
fi

# --- Final Verdict ---
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║              FINAL VERDICT                   ║"
echo "╠══════════════════════════════════════════════╣"

if $RUN_TIER1; then
    if [[ "$TIER1_EXIT" -eq 0 ]]; then
        echo "║  Tier 1 (Corpus Regression):    PASS         ║"
    else
        echo "║  Tier 1 (Corpus Regression):    FAIL         ║"
    fi
fi

if $RUN_TIER2; then
    if [[ "$TIER2_EXIT" -eq 0 ]]; then
        echo "║  Tier 2 (Ground Truth):         PASS         ║"
    else
        echo "║  Tier 2 (Ground Truth):         FAIL         ║"
    fi
fi

echo "╚══════════════════════════════════════════════╝"

EXIT_CODE=0
if [[ "$TIER1_EXIT" -ne 0 || "$TIER2_EXIT" -ne 0 ]]; then
    EXIT_CODE=1
fi
exit $EXIT_CODE
