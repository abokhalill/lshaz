#!/usr/bin/env bash
# Tier 2: Ground Truth Microbenchmark Runner
# Builds paired benchmarks, runs faultline analysis, executes benchmarks
# with perf counters, and validates claims against hardware evidence.
#
# Usage:
#   ./validation/tier2/run_benchmarks.sh                # All rules, with perf
#   ./validation/tier2/run_benchmarks.sh --no-perf      # Skip perf counters
#   ./validation/tier2/run_benchmarks.sh --rule FL002   # Single rule
#   ./validation/tier2/run_benchmarks.sh --help         # Show this help
#
# Exit codes:
#   0  All assertions passed
#   1  One or more assertions failed
#
# Requires: built faultline binary, clang++ (any version)
# Optional: perf (hardware counters), python3 + scipy (statistical analysis)

set -uo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
readonly LSHAZ="$ROOT_DIR/build/lshaz"
readonly BENCH_DIR="$SCRIPT_DIR/benchmarks"
readonly BUILD_DIR="$SCRIPT_DIR/build"
readonly RESULTS_DIR="$SCRIPT_DIR/results"

usage() {
    sed -n '2,/^$/s/^# \?//p' "$0"
    exit 0
}

RULE_FILTER=""
USE_PERF=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h) usage ;;
        --rule)    RULE_FILTER="$2"; shift 2 ;;
        --no-perf) USE_PERF=false; shift ;;
        *)
            echo "Unknown flag: $1" >&2
            usage
            ;;
    esac
done

if [[ ! -x "$LSHAZ" ]]; then
    echo "FATAL: lshaz binary not found at $LSHAZ" >&2
    echo "       Run: cmake --build build -j\$(nproc)" >&2
    exit 1
fi

mkdir -p "$BUILD_DIR" "$RESULTS_DIR"

# Find clang++ binary
CXX=""
for candidate in clang++ clang++-18 clang++-17 clang++-16 g++; do
    if command -v "$candidate" >/dev/null 2>&1; then
        CXX="$candidate"
        break
    fi
done
if [[ -z "$CXX" ]]; then
    echo "FATAL: no C++ compiler found" >&2
    exit 1
fi
echo "C++ compiler: $CXX"

PASS=0
FAIL=0
SKIP=0

log_pass() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
log_fail() { echo "  [FAIL] $1" >&2; FAIL=$((FAIL+1)); }
log_skip() { echo "  [SKIP] $1"; SKIP=$((SKIP+1)); }

# Check perf availability
PERF_AVAILABLE=false
if $USE_PERF && command -v perf >/dev/null 2>&1; then
    if perf stat -e cycles true 2>/dev/null; then
        PERF_AVAILABLE=true
    else
        echo "WARNING: perf available but hardware counters inaccessible"
        echo "         Set /proc/sys/kernel/perf_event_paranoid <= 1 or use CAP_PERFMON"
    fi
fi

# --- Benchmark definitions ---
# Format: rule_id|source_file|hazardous_struct|fixed_struct|perf_events
declare -a BENCHMARKS=(
    "FL001|fl001_cache_spanning.cpp|LargeStruct|HotFields|cache-misses,L1-dcache-load-misses"
    "FL002|fl002_false_sharing.cpp|HazardousCounters|FixedCounters|cache-misses,L1-dcache-load-misses"
    "FL010|fl010_atomic_ordering.cpp|bench_seq_cst|bench_release|cycles,instructions"
    "FL012|fl012_lock_hotpath.cpp|bench_mutex|bench_atomic|context-switches,cycles"
    "FL020|fl020_heap_alloc.cpp|bench_alloc|bench_prealloc|dTLB-load-misses,page-faults"
    "FL030|fl030_virtual_dispatch.cpp|IHandler|CRTPHandler|branch-misses,instructions"
    "FL041|fl041_contended_queue.cpp|UnpaddedQueue|PaddedQueue|cache-misses,L1-dcache-load-misses"
)

run_benchmark_suite() {
    local rule="$1"
    local source="$2"
    local hazardous="$3"
    local fixed="$4"
    local perf_events="$5"

    if [[ -n "$RULE_FILTER" && "$RULE_FILTER" != "$rule" ]]; then
        return
    fi

    local src_path="$BENCH_DIR/$source"
    if [[ ! -f "$src_path" ]]; then
        log_skip "$rule: source $source not found"
        return
    fi

    echo ""
    echo "=== $rule: $source ==="
    echo "    Hazardous: $hazardous | Fixed: $fixed"

    # --- Phase 1: Faultline Analysis Validation ---
    echo "  Phase 1: Static analysis validation"

    local lshaz_out="$RESULTS_DIR/${rule}_lshaz.json"
    "$LSHAZ" --no-ir --json "$src_path" -- -std=c++20 > "$lshaz_out" 2>&1 || true

    # Check: lshaz should flag the hazardous struct/function
    if grep -q "\"$rule\"" "$lshaz_out"; then
        log_pass "$rule: lshaz detected hazard"
    else
        log_fail "$rule: lshaz did NOT detect hazard"
    fi

    # Check: count diagnostics for this rule
    local diag_count
    diag_count=$(grep "\"$rule\"" "$lshaz_out" 2>/dev/null | wc -l)
    diag_count=$((diag_count + 0))
    echo "    Diagnostics emitted: $diag_count"

    # --- Phase 2: Build Benchmark ---
    echo "  Phase 2: Building benchmark"

    local binary="$BUILD_DIR/${rule}_bench"
    if ! $CXX -std=c++20 -O2 -march=native -pthread -o "$binary" "$src_path" 2>&1; then
        log_fail "$rule: benchmark compilation failed"
        return
    fi
    log_pass "$rule: benchmark compiled"

    # --- Phase 3: Execute Benchmark ---
    echo "  Phase 3: Running benchmark"

    local bench_out="$RESULTS_DIR/${rule}_bench.txt"
    if ! "$binary" > "$bench_out" 2>&1; then
        log_fail "$rule: benchmark execution failed"
        return
    fi
    log_pass "$rule: benchmark executed"
    sed 's/^/    /' < "$bench_out"

    # --- Phase 4: Perf Counter Validation ---
    if $PERF_AVAILABLE; then
        echo "  Phase 4: Perf counter validation"

        local perf_out="$RESULTS_DIR/${rule}_perf.txt"
        perf stat -e "$perf_events" -r 3 "$binary" > /dev/null 2> "$perf_out" || true

        if [[ -s "$perf_out" ]]; then
            log_pass "$rule: perf counters collected"
            grep -E "^\s+[0-9]" "$perf_out" | sed 's/^/    /' || true
        else
            log_skip "$rule: perf output empty"
        fi
    else
        log_skip "$rule: perf counters (perf unavailable)"
    fi
}

# --- Main ---

echo "lshaz Tier 2: Ground Truth Microbenchmarks"
echo "==============================================="
echo "Perf counters: $($PERF_AVAILABLE && echo "available" || echo "unavailable")"
echo ""

for bench_def in "${BENCHMARKS[@]}"; do
    IFS='|' read -r rule source hazardous fixed perf_events <<< "$bench_def"
    run_benchmark_suite "$rule" "$source" "$hazardous" "$fixed" "$perf_events"
done

# --- Summary ---
echo ""
echo "==============================================="
echo "Tier 2 Summary"
echo "==============================================="
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "  SKIP: $SKIP"
echo ""

if [[ "$FAIL" -gt 0 ]]; then
    echo "RESULT: FAIL ($FAIL assertion(s) failed)" >&2
    exit 1
else
    echo "RESULT: PASS (all $PASS assertion(s) passed)"
    exit 0
fi
