#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tier 1: Corpus-Scale Regression Harness
# Runs lshaz against real-world codebases and validates output properties.
#
# Usage:
#   ./validation/tier1/run_corpus.sh                # All corpora
#   ./validation/tier1/run_corpus.sh --corpus folly  # Single external corpus
#   ./validation/tier1/run_corpus.sh --help          # Show this help
#
# Exit codes:
#   0  All assertions passed
#   1  One or more assertions failed
#
# Requires: built lshaz binary, git (for external corpora)

set -uo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
readonly LSHAZ="$ROOT_DIR/build/lshaz"
readonly CORPUS_DIR="$ROOT_DIR/validation/tier1/corpora"
readonly RESULTS_DIR="$ROOT_DIR/validation/tier1/results"

usage() {
    sed -n '2,/^$/s/^# \?//p' "$0"
    exit 0
}

CORPUS_FILTER=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h) usage ;;
        --corpus)  CORPUS_FILTER="$2"; shift 2 ;;
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

mkdir -p "$CORPUS_DIR" "$RESULTS_DIR"

PASS=0
FAIL=0
SKIP=0
TOTAL_DIAGNOSTICS=0

log_pass() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
log_fail() { echo "  [FAIL] $1" >&2; FAIL=$((FAIL+1)); }
log_skip() { echo "  [SKIP] $1"; SKIP=$((SKIP+1)); }

# --- Assertion functions ---

assert_no_crash() {
    local exit_code="$1"
    local corpus="$2"
    local file="$3"
    if [[ "$exit_code" -gt 2 ]]; then
        log_fail "$corpus/$file: lshaz crashed (exit code $exit_code)"
        return 0
    fi
    if [[ "$exit_code" -eq 2 ]]; then
        log_skip "$corpus/$file: parse error (exit code 2, missing headers?)"
        return 0
    fi
    log_pass "$corpus/$file: no crash (exit=$exit_code)"
    return 0
}

assert_deterministic() {
    local run1="$1"
    local run2="$2"
    local corpus="$3"
    local file="$4"
    if diff -q "$run1" "$run2" >/dev/null 2>&1; then
        log_pass "$corpus/$file: deterministic output"
    else
        log_fail "$corpus/$file: non-deterministic output (diff between runs)"
        diff "$run1" "$run2" | head -20 >&2
    fi
}

assert_valid_locations() {
    local output="$1"
    local source_root="$2"
    local corpus="$3"
    local file="$4"
    local invalid=0

    # Extract file:line references from diagnostic output
    while IFS= read -r line; do
        if [[ "$line" =~ ^(/[^:]+):([0-9]+): ]]; then
            local ref_file="${BASH_REMATCH[1]}"
            local ref_line="${BASH_REMATCH[2]}"
            if [[ -f "$ref_file" ]]; then
                local total_lines
                total_lines=$(wc -l < "$ref_file")
                if [[ "$ref_line" -gt "$total_lines" ]]; then
                    echo "    invalid location: $ref_file:$ref_line (file has $total_lines lines)" >&2
                    invalid=$((invalid+1))
                fi
            fi
        fi
    done < "$output"

    if [[ "$invalid" -eq 0 ]]; then
        log_pass "$corpus/$file: all locations valid"
    else
        log_fail "$corpus/$file: $invalid invalid location(s)"
    fi
}

assert_distribution_sanity() {
    local json_output="$1"
    local corpus="$2"
    local file="$3"

    # Count diagnostics per rule from JSON output
    local total
    total=$(grep '"ruleID"' "$json_output" 2>/dev/null | wc -l)
    total=$((total + 0))

    if [[ "$total" -eq 0 ]]; then
        log_pass "$corpus/$file: no diagnostics (clean file)"
        return
    fi

    TOTAL_DIAGNOSTICS=$((TOTAL_DIAGNOSTICS + total))

    # Check no single rule dominates (>60% of diagnostics for this file)
    local max_rule_count=0
    local max_rule=""
    for rule in FL001 FL002 FL010 FL011 FL012 FL020 FL021 FL030 FL031 FL040 FL041 FL050 FL060 FL061 FL090; do
        local count
        count=$(grep "\"$rule\"" "$json_output" 2>/dev/null | wc -l)
        count=$((count + 0))
        if [[ "$count" -gt "$max_rule_count" ]]; then
            max_rule_count=$count
            max_rule=$rule
        fi
    done

    local threshold=$((total * 60 / 100))
    if [[ "$max_rule_count" -gt "$threshold" && "$total" -gt 5 ]]; then
        log_fail "$corpus/$file: rule $max_rule dominates ($max_rule_count/$total = $(( max_rule_count * 100 / total ))%)"
    else
        log_pass "$corpus/$file: distribution sane (max=$max_rule:$max_rule_count/$total)"
    fi
}

assert_evidence_parseable() {
    local json_output="$1"
    local corpus="$2"
    local file="$3"

    # Check that structuralEvidence fields contain expected key=value patterns
    local evidence_count=0
    local bad=0
    while IFS= read -r line; do
        # Extract value between quotes after "structuralEvidence": "
        local val
        val=$(echo "$line" | sed -n 's/.*"structuralEvidence"[[:space:]]*:[[:space:]]*"\(.*\)".*/\1/p')
        if [[ -n "$val" ]]; then
            evidence_count=$((evidence_count+1))
            if [[ ! "$val" =~ [a-z_]+= ]]; then
                bad=$((bad+1))
            fi
        fi
    done < <(grep '"structuralEvidence"' "$json_output" 2>/dev/null || true)

    if [[ "$evidence_count" -eq 0 ]]; then
        log_pass "$corpus/$file: no evidence fields to check"
    elif [[ "$bad" -eq 0 ]]; then
        log_pass "$corpus/$file: evidence fields parseable ($evidence_count checked)"
    else
        log_fail "$corpus/$file: $bad/$evidence_count unparseable evidence field(s)"
    fi
}

# --- Inline corpus for self-contained testing ---
# Uses the project's own test samples as a guaranteed-available corpus,
# plus attempts to clone external corpora if network is available.

run_internal_corpus() {
    echo "=== Internal Corpus (test/samples) ==="
    local corpus="internal"

    for src in "$ROOT_DIR"/test/samples/*.cpp; do
        local basename
        basename=$(basename "$src")
        local out1="$RESULTS_DIR/${corpus}_${basename}_run1.txt"
        local out2="$RESULTS_DIR/${corpus}_${basename}_run2.txt"
        local json_out="$RESULTS_DIR/${corpus}_${basename}.json"

        # Run 1 (CLI output)
        local exit_code=0
        "$LSHAZ" scan "$src" --no-ir -- -std=c++20 > "$out1" 2>&1 || exit_code=$?
        assert_no_crash "$exit_code" "$corpus" "$basename"

        # Run 2 (determinism check)
        "$LSHAZ" scan "$src" --no-ir -- -std=c++20 > "$out2" 2>&1 || true
        assert_deterministic "$out1" "$out2" "$corpus" "$basename"

        # Location validity
        assert_valid_locations "$out1" "$ROOT_DIR" "$corpus" "$basename"

        # JSON output for distribution and evidence checks
        "$LSHAZ" scan "$src" --no-ir --format json -- -std=c++20 > "$json_out" 2>&1 || true
        assert_distribution_sanity "$json_out" "$corpus" "$basename"
        assert_evidence_parseable "$json_out" "$corpus" "$basename"
    done
}

run_external_corpus() {
    local name="$1"
    local repo="$2"
    local rev="$3"
    local flags="$4"
    shift 4
    local paths=("$@")

    if [[ -n "$CORPUS_FILTER" && "$CORPUS_FILTER" != "$name" ]]; then
        log_skip "corpus $name (filtered)"
        return
    fi

    echo "=== External Corpus: $name ==="

    local clone_dir="$CORPUS_DIR/$name"
    if [[ ! -d "$clone_dir" ]]; then
        echo "  Cloning $repo ($rev)..."
        if ! git clone --depth 1 --branch "$rev" "$repo" "$clone_dir" 2>/dev/null; then
            # Try without --branch for repos where rev is a commit
            if ! git clone --depth 1 "$repo" "$clone_dir" 2>/dev/null; then
                log_skip "corpus $name: clone failed"
                return
            fi
        fi
    fi

    for relpath in "${paths[@]}"; do
        local src="$clone_dir/$relpath"
        if [[ ! -f "$src" ]]; then
            log_skip "$name/$relpath: file not found"
            continue
        fi

        local safe_name="${relpath//\//_}"
        local out1="$RESULTS_DIR/${name}_${safe_name}_run1.txt"
        local out2="$RESULTS_DIR/${name}_${safe_name}_run2.txt"
        local json_out="$RESULTS_DIR/${name}_${safe_name}.json"

        # shellcheck disable=SC2086
        local exit_code=0
        "$LSHAZ" scan "$src" --no-ir -- $flags > "$out1" 2>&1 || exit_code=$?
        assert_no_crash "$exit_code" "$name" "$relpath"

        # shellcheck disable=SC2086
        "$LSHAZ" scan "$src" --no-ir -- $flags > "$out2" 2>&1 || true
        assert_deterministic "$out1" "$out2" "$name" "$relpath"

        assert_valid_locations "$out1" "$clone_dir" "$name" "$relpath"

        # shellcheck disable=SC2086
        "$LSHAZ" scan "$src" --no-ir --format json -- $flags > "$json_out" 2>&1 || true
        assert_distribution_sanity "$json_out" "$name" "$relpath"
        assert_evidence_parseable "$json_out" "$name" "$relpath"
    done
}

# --- Main ---

echo "lshaz Tier 1: Corpus-Scale Regression"
echo "=========================================="
echo ""

run_internal_corpus

# External corpora — best-effort, skip on network failure
run_external_corpus "folly" \
    "https://github.com/facebook/folly.git" "main" \
    "-std=c++20 -I. -Ifolly" \
    "folly/concurrency/ConcurrentHashMap.h" \
    "folly/MPMCQueue.h" \
    "folly/ProducerConsumerQueue.h"

run_external_corpus "abseil" \
    "https://github.com/abseil/abseil-cpp.git" "master" \
    "-std=c++17 -I." \
    "absl/synchronization/mutex.h" \
    "absl/container/internal/raw_hash_set.h" \
    "absl/base/internal/spinlock.h"

run_external_corpus "seastar" \
    "https://github.com/scylladb/seastar.git" "master" \
    "-std=c++20 -I. -Iinclude" \
    "include/seastar/core/queue.hh" \
    "include/seastar/core/shared_ptr.hh"

# --- Summary ---
echo ""
echo "=========================================="
echo "Tier 1 Summary"
echo "=========================================="
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "  SKIP: $SKIP"
echo "  Total diagnostics across corpus: $TOTAL_DIAGNOSTICS"
echo ""

if [[ "$FAIL" -gt 0 ]]; then
    echo "RESULT: FAIL ($FAIL assertion(s) failed)" >&2
    exit 1
else
    echo "RESULT: PASS (all $PASS assertion(s) passed)"
    exit 0
fi
