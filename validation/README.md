# lshaz Validation Harness

Ground-truth validation for lshaz's microarchitectural diagnostic claims.
Inspired by [Jepsen](https://jepsen.io/) — every claim the tool makes must be
backed by reproducible evidence on real hardware.

## Tiers

### Tier 1: Corpus-Scale Regression

Runs lshaz against internal test samples and external open-source C++
codebases (folly, abseil, seastar). Five assertions per file:

| Assertion | Description |
|-----------|-------------|
| **No crash** | Exit code ≠ 2 (segfault/abort) |
| **Deterministic** | Two consecutive runs produce byte-identical output |
| **Valid locations** | Every `file:line` reference points to an existing line |
| **Distribution sanity** | No single rule exceeds 60% of diagnostics (for files with >5 diagnostics) |
| **Evidence parseable** | Every `structuralEvidence` field contains `key=value` pairs |

External corpora are best-effort (skipped on network failure or clone error).

### Tier 2: Ground Truth Microbenchmarks

Per-rule paired benchmarks (hazardous vs. fixed code) with hardware validation.
Each benchmark runs through four phases:

| Phase | Description |
|-------|-------------|
| **1. Static analysis** | lshaz must emit the target rule's diagnostic on the benchmark file |
| **2. Build** | Compile the benchmark with `-O2 -march=native` |
| **3. Execute** | Run 5 trials, collect wall-clock timings |
| **4. Perf counters** | Collect hardware counters via `perf stat` (optional) |

Statistical analysis (when scipy is available) runs a paired t-test (α=0.01)
with Cohen's d effect size. When scipy is unavailable, raw mean ratios are
reported for manual inspection.

#### Benchmark Coverage

| Rule | Benchmark | Hazardous | Fixed | Mechanism |
|------|-----------|-----------|-------|-----------|
| FL001 | `fl001_cache_spanning.cpp` | 192B struct (3 cache lines) | 32B hot-only struct | L1D miss amplification |
| FL002 | `fl002_false_sharing.cpp` | Two atomics, same line | `alignas(64)` padded | MESI invalidation |
| FL010 | `fl010_atomic_ordering.cpp` | `seq_cst` store (XCHG) | `release` store (MOV) | x86-64 TSO store cost |
| FL012 | `fl012_lock_hotpath.cpp` | `std::mutex` in hot loop | `atomic::fetch_add` | Lock contention |
| FL020 | `fl020_heap_alloc.cpp` | `new`/`delete` per iteration | Stack-allocated buffer | Allocator overhead |
| FL030 | `fl030_virtual_dispatch.cpp` | Virtual call in loop | CRTP static dispatch | Indirect branch cost |
| FL041 | `fl041_contended_queue.cpp` | Head/tail same cache line | `alignas(64)` padded | Producer-consumer contention |

## Usage

```bash
# Full validation (both tiers)
./validation/run.sh

# Tier 1 only
./validation/run.sh --tier1

# Tier 2 only
./validation/run.sh --tier2

# Tier 2 without perf counters (Phase 4 skipped)
./validation/run.sh --tier2 --no-perf

# Single rule benchmark
./validation/run.sh --tier2 --rule FL002

# Run tiers directly
./validation/tier1/run_corpus.sh
./validation/tier1/run_corpus.sh --corpus folly
./validation/tier2/run_benchmarks.sh --no-perf
./validation/tier2/run_benchmarks.sh --rule FL010

# Statistical analysis on existing results
python3 ./validation/tier2/analyze_results.py ./validation/tier2/results
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All assertions passed |
| 1 | One or more assertions failed |

Each tier exits independently. The top-level `run.sh` exits 1 if either tier
fails.

## Requirements

| Dependency | Required | Purpose |
|------------|----------|---------|
| `build/lshaz` | Yes | The analyzer binary under test |
| `clang++` (any version) | Yes | Benchmark compilation |
| `git` | Tier 1 only | Cloning external corpora |
| `perf` | Optional | Hardware counter collection (Phase 4) |
| Python 3.8+ | Optional | Statistical analysis |
| `scipy` + `numpy` | Optional | Paired t-test; graceful fallback to ratio reporting |

For perf counter access, set `perf_event_paranoid ≤ 1`:
```bash
sudo sysctl kernel.perf_event_paranoid=1
```

## Adding a New Benchmark

1. Create `validation/tier2/benchmarks/flXXX_name.cpp` with paired
   hazardous/fixed code. Follow the existing pattern: `--- HAZARDOUS` /
   `--- FIXED` comments, consistent `printf` output format.
2. Add the rule to the `BENCHMARKS` array in `run_benchmarks.sh`.
3. Add the rule to the `RULES` list in `analyze_results.py`.
4. Update this table in the README.
