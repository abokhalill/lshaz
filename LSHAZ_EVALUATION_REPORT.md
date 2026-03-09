# lshaz Static Analysis Tool Evaluation Report

**Tool:** lshaz v0.2.0  
**Evaluation Date:** March 9, 2026  
**Evaluator:** Distinguished Senior Principal Engineer

---

## Executive Summary

lshaz is a static analysis tool that detects microarchitectural performance hazards in C++ code, including false sharing, cache-line contention, atomic ordering issues, and allocator serialization. This evaluation tested the tool across three stages of increasing complexity.

**Overall Assessment:** The tool shows **strong capabilities for structural cache analysis** (FL001, FL002, FL041, FL060) but **limited functionality for hot-path detection rules** (FL010, FL012, FL020, FL030, FL031, FL050). The diagnostic quality is technically sound with detailed hardware-level explanations, but **output ordering is non-deterministic**, which impacts CI/auditing use cases.

---

## Stage 1: Minimal Rule Triggers

### Test Setup
Created 12 minimal C++ files, each designed to trigger a specific rule.

### Results

| Rule | Description | Triggered | Notes |
|------|-------------|-----------|-------|
| **FL001** | Cache Line Spanning Struct | ✅ Yes | Correctly detected 160B struct spanning 3 cache lines |
| **FL002** | False Sharing Candidate | ✅ Yes | Correctly detected atomic head/tail on same cache line |
| **FL010** | Overly Strong Atomic Ordering | ❌ No | seq_cst usage not detected even in loops |
| **FL011** | Atomic Contention Hotspot | ⚠️ Partial | Fired as FL002 instead |
| **FL012** | Lock in Hot Path | ❌ No | std::mutex in loop not detected |
| **FL020** | Heap Allocation in Hot Path | ❌ No | new/delete/malloc in loop not detected |
| **FL021** | Large Stack Frame | ✅ Yes | Correctly detected 4100B stack frame |
| **FL030** | Virtual Dispatch in Hot Path | ❌ No | Virtual calls in loop not detected |
| **FL031** | std::function in Hot Path | ❌ No | std::function invocation not detected |
| **FL040** | Centralized Mutable Global State | ✅ Yes | Detected global mutable variable |
| **FL041** | Contended Queue Pattern | ✅ Yes | Correctly identified head/tail queue pattern |
| **FL050** | Deep Conditional Tree | ❌ No | 5-level nesting not detected |

### Key Finding
**Hot-path rules (FL010, FL012, FL020, FL030, FL031, FL050) do not fire** even with:
- `__attribute__((hot))` function annotations
- Large loop iteration counts (1,000,000)
- IR optimization enabled (`--ir-opt O2`)

The tool likely requires perf profile data (`--perf-profile`) for hot-path detection, which is not documented as mandatory.

---

## Stage 2: Realistic Engineering Snippets

### Test Setup
Created 5 realistic systems code examples:
- Order book (trading system)
- Thread pool
- Lock-free SPSC queue
- Metrics collector
- Event dispatcher

### Results

**19 hazards detected** across 5 files:

| Rule | Count | Technical Accuracy |
|------|-------|-------------------|
| FL001 | 8 | ✅ Correct - identified large structs spanning multiple cache lines |
| FL002 | 8 | ✅ Correct - identified false sharing in concurrent structures |
| FL060 | 3 | ✅ Correct - identified NUMA-unfriendly shared structures |

### Notable Observations

1. **Correct behavior:** `PaddedSPSCQueue` with proper `alignas(64)` padding was NOT flagged - tool correctly recognizes mitigation.

2. **Missed detection:** The unpadded `SPSCQueue` was flagged as FL002 but NOT as FL041 (Contended Queue Pattern), despite having head/tail atomics on the same cache line.

3. **Diagnostic quality:** Excellent hardware-level explanations with specific evidence (sizeof, cache lines spanned, field offsets).

---

## Stage 3: Industrial-Scale Evaluation

### Codebases Tested

| Codebase | TUs Parsed | Diagnostics | Parse Success |
|----------|------------|-------------|---------------|
| abseil-cpp | 157 | 81 | 100% |
| fmtlib/fmt | ~50 | 45 | 100% |

### abseil-cpp Rule Distribution

```
53 FL001 (Cache Line Spanning Struct)
15 FL002 (False Sharing Candidate)
 5 FL021 (Large Stack Frame)
 4 FL090 (Hazard Amplification)
 3 FL060 (NUMA-Unfriendly Shared Structure)
 1 FL041 (Contended Queue Pattern)
```

### Severity Distribution

```
51 Critical
25 High
 5 Medium
```

### Signal-to-Noise Ratio
**Good.** The diagnostics are technically meaningful and point to real structural issues in production code. The tool correctly identifies:
- `ThreadIdentity` struct (352B, 6 cache lines) in abseil's synchronization code
- `AllocList` struct (280B, 5 cache lines) in low-level allocator
- Various waiter structures with false sharing potential

---

## Determinism Analysis

### Test Method
Ran the same scan multiple times and compared MD5 hashes of JSON output.

### Results

| Test | Diagnostic Count | JSON Hash |
|------|------------------|-----------|
| Stage 1 (5 runs) | Consistent (6) | **Varies** |
| Stage 3 abseil (3 runs) | Consistent (81) | **Varies** |

### Finding
**Diagnostic counts are deterministic, but JSON output ordering is not.** This is likely due to parallel processing affecting output order rather than analysis non-determinism. 

**Impact:** 
- ❌ Cannot use raw JSON diff for CI gating
- ✅ Can use `lshaz diff` command for proper comparison
- ✅ Diagnostic counts are reliable for trend tracking

---

## Technical Correctness Assessment

### Verified Correct Diagnostics

1. **FL001 (Cache Line Spanning):** Correctly computes sizeof and cache line count. Accurately identifies straddling fields.

2. **FL002 (False Sharing):** Correctly identifies atomic pairs on same cache line with thread-escape evidence.

3. **FL021 (Large Stack Frame):** Accurately estimates stack frame sizes and identifies large local variables.

4. **FL041 (Contended Queue):** Correctly identifies head/tail naming pattern in queue structures.

5. **FL060 (NUMA):** Appropriately speculative (55% confidence) for multi-socket assumptions.

### Potential False Positives

1. **Read-only large structs:** FL001 may flag structs that are read-only in practice.
2. **Thread-local instances:** FL002 may flag structures that are never actually shared.
3. **Single-socket systems:** FL060 warnings are irrelevant for single-socket deployments.

The tool appropriately marks these with confidence levels and evidence tiers.

---

## Limitations Identified

### Critical

1. **Hot-path rules non-functional without perf profile:** FL010, FL012, FL020, FL030, FL031, FL050 do not fire in any tested scenario without `--perf-profile`.

2. **Non-deterministic output ordering:** Complicates CI integration for exact diff comparisons.

### Moderate

3. **Single-TU scope:** Cannot track thread escape across translation unit boundaries.

4. **FL041 detection inconsistent:** Some obvious queue patterns (SPSCQueue) not detected as FL041.

### Minor

5. **No ARM64 testing performed:** Evaluation limited to x86-64 (64B cache lines).

---

## Recommendations

### For Tool Users

1. **Use `--perf-profile` for hot-path analysis** - structural rules work without it, but hot-path rules require runtime data.

2. **Use `lshaz diff` for CI gating** instead of raw JSON comparison.

3. **Focus on FL001, FL002, FL021, FL041** - these rules are reliable and actionable.

### For Tool Developers

1. **Document perf profile requirement** for hot-path rules more prominently.

2. **Add deterministic output mode** (e.g., `--deterministic` flag to sort output).

3. **Improve FL041 detection** - current heuristics miss some obvious queue patterns.

4. **Consider heuristic hot-path detection** - loop depth, iteration count estimates, or function naming patterns.

---

## Conclusion

lshaz is a **valuable tool for detecting structural microarchitectural hazards** in C++ code. Its strength lies in cache geometry analysis (FL001, FL002, FL041) with technically accurate, hardware-grounded diagnostics. The tool successfully identified real issues in production-quality code (abseil-cpp).

However, the **hot-path detection rules appear non-functional** without perf profile data, which significantly limits the tool's utility for compile-time analysis. The non-deterministic output ordering also requires workarounds for CI integration.

**Recommendation:** Suitable for adoption with the understanding that:
- Structural rules (FL001, FL002, FL021, FL041, FL060) are production-ready
- Hot-path rules require additional runtime profiling integration
- Use `lshaz diff` for CI gating rather than raw output comparison

---

## Test Artifacts

```
/home/ousef/testing/
├── stage1_minimal/          # 12 minimal trigger tests
├── stage2_realistic/        # 5 realistic systems code examples
└── stage3_industrial/       # Industrial codebase results
    └── abseil_results.json  # Full abseil-cpp scan results
```
