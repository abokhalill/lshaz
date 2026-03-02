# Faultline

Static structural analyzer for C++ that maps source-level patterns to microarchitectural latency hazards on Linux x86-64.

Built on Clang/LLVM. Assumes 64-byte cache lines, x86-64 TSO memory model, and Linux first-touch NUMA page placement.

---

## What This Tool Does

Faultline inspects C++ source (via Clang AST) and optionally LLVM IR to detect struct layouts, atomic patterns, allocation sites, and dispatch structures that are likely to cause cache-line contention, false sharing, branch misprediction, or allocator serialization on x86-64 hardware.

It does not profile. It does not instrument. It performs compile-time structural analysis and reports findings with file, line, column, severity, confidence, and hardware-specific reasoning.

It is not a linter. It does not enforce style. It identifies structural patterns that map to known hardware performance penalties under concurrency or memory-subsystem pressure.

### Platform Support

| Platform | Status | Notes |
|---|---|---|
| Linux x86-64 | Supported | Primary target. All assumptions validated against this model. |
| WSL2 | Supported | Linux userspace; same kernel path. |
| macOS (Intel or Apple Silicon) | Not supported | Different cache-line geometry, no validated PMU model. |
| Windows native | Not supported | IR emission and subprocess control assume POSIX. |

### Where It Fits

| Existing Tool | What It Provides | Gap | Faultline's Role |
|---|---|---|---|
| `pahole` | Post-build struct layout via DWARF/BTF | No hot-path context, no atomic/ordering analysis, no function attribution | AST/IR-level reasoning with source location diagnostics |
| `perf` / PMU tracing | Runtime ground-truth counters, bottleneck attribution | Requires a running workload; discovers problems late | Pre-runtime structural triage; generates `perf stat` experiment scripts |
| `llvm-mca` | Instruction-level throughput/latency modeling | No cross-declaration layout, no thread-coherence modeling | Source/IR structure analysis across types and functions |

Faultline operates in the compile-analysis phase. Runtime tools validate whether flagged hazards have measurable impact.

---

## Build

### Requirements

| Dependency | Minimum Version |
|---|---|
| Linux x86-64 | Required |
| LLVM + Clang development libraries | 16 |
| CMake | 3.20 |
| C++ compiler with C++20 support | GCC 12+ or Clang 16+ |

```bash
# Ubuntu / Debian
apt install llvm-18-dev libclang-18-dev clang-18 cmake

# Arch
pacman -S llvm clang cmake
```

### Compile

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

If CMake cannot find LLVM automatically:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/usr/lib/llvm-18
```

The build produces two binaries:

- `build/faultline` — the analyzer
- `build/output_schema_contract_test` — schema contract test suite

---

## Usage

```bash
# Single file, default CLI output
./build/faultline src/engine.cpp -- -std=c++20

# JSON output to stdout
./build/faultline --format=json src/engine.cpp -- -std=c++20

# SARIF output to file
./build/faultline --format=sarif --output=report.sarif src/engine.cpp -- -std=c++20

# Multiple translation units
./build/faultline src/a.cpp src/b.cpp src/c.cpp -- -std=c++20 -I include/

# Filter by severity and evidence tier
./build/faultline --min-severity=High --min-evidence=proven src/engine.cpp -- -std=c++20

# AST-only mode (skip IR emission, faster, lower confidence)
./build/faultline --no-ir src/engine.cpp -- -std=c++20

# Custom config
./build/faultline --config=./faultline.config.yaml src/engine.cpp -- -std=c++20

# Specify linked allocator (affects FL020 severity classification)
./build/faultline --allocator=jemalloc src/engine.cpp -- -std=c++20

# Profile-guided hot-path selection
./build/faultline --perf-profile=perf.data --hotness-threshold=2.0 src/engine.cpp -- -std=c++20
```

Arguments after `--` are passed to the Clang compilation. Source files before `--` are the analysis targets.

---

## Analysis Pipeline

The tool executes a fixed sequence of stages. Each stage is described below with its inputs, outputs, and implementation boundaries.

### Stage 1: AST Analysis

Entry point: `FaultlineASTConsumer::HandleTranslationUnit`.

For each translation unit, walks all top-level declarations and runs 15 registered rules. Each rule implements:

```cpp
void analyze(const clang::Decl *D,
             clang::ASTContext &Ctx,
             const HotPathOracle &Oracle,
             const Config &Cfg,
             std::vector<Diagnostic> &out);
```

Supporting analyses available to rules:

- **CacheLineMap** — Maps struct fields to 64-byte cache line boundaries using `ASTContext::getASTRecordLayout`. Reports straddling fields and per-line field groupings.
- **EscapeAnalysis** — Determines whether a type may be accessed from multiple threads. Uses seven evidence signals: `std::atomic` member fields, mutex/sync primitive members, `std::shared_ptr`/`std::weak_ptr` members, `volatile` members, types passed to `std::thread`/`std::jthread`/`std::async`, types stored in global mutable variables, and types used as `shared_ptr` pointees in global scope. Conservative: assumes escape when uncertain. Not interprocedural dataflow — scans the current TU only.
- **AllocatorTopology** — Classifies allocator contention characteristics based on the `--allocator` flag: glibc (arena-lock), tcmalloc/jemalloc (thread-local cache), mimalloc (pool/slab). Affects FL020 severity.
- **NUMATopology** — Infers NUMA page placement based on first-touch policy analysis: local-init, main-thread, any-thread, interleaved, explicit-bind, or unknown.
- **HotPathOracle** — Classifies functions as hot via four mechanisms:
  1. `[[clang::annotate("faultline_hot")]]` attribute
  2. fnmatch glob patterns in config (`hot_function_patterns`, `hot_file_patterns`)
  3. `perf` profile sample threshold (`--perf-profile`, `--hotness-threshold`)
  4. Transitive marking during AST walk

### Stage 2: IR Refinement (optional, disable with `--no-ir`)

After AST analysis completes, the tool optionally emits and analyzes LLVM IR to confirm or refute AST-level findings.

**IR emission:**

- Compiler resolved from `compile_commands.json` argv[0], with PATH fallback to `clang++`, `clang++-18`, `clang++-17`, `clang++-16`.
- IR emitted via `llvm::sys::ExecuteAndWait`. No shell interpolation.
- Parallelism bounded by `std::counting_semaphore` at `--ir-jobs` (default: `hardware_concurrency()`).
- Jobs grouped into shards of `--ir-batch-size` TUs. Each shard owns its own `LLVMContext`.
- Temp file naming: MD5 of source content + mtime + compile args + tool version + `.d` dependency file (if present). Identical inputs reuse cached IR.
- Subprocess timeout: 120 seconds. Stderr captured per job and logged on failure.

**IR analysis (`IRAnalyzer`):**

Per function, collects: stack allocations (`AllocaInst`, name, size, array flag), heap call sites (direct/indirect, in-loop), atomic operations (load/store/RMW/CmpXchg/fence, ordering, in-loop, source location), basic block count, loop count, indirect vs direct call counts.

**Confidence refinement (`DiagnosticRefiner`):**

Adjusts AST diagnostic confidence using named evidence constants with per-factor floor/ceiling bounds:

| Factor | Delta | Floor | Ceiling |
|---|---|---|---|
| Site-confirmed (exact source line match) | +0.10 | 0.10 | 0.98 |
| Function-confirmed (function match, no line) | +0.05 | 0.10 | 0.95 |
| Optimized away (pattern absent in IR) | −0.20 | 0.30 | — |
| Heap allocation survived inlining | +0.05 | 0.10 | 0.95 |
| Heap allocation eliminated | −0.15 | 0.40 | — |
| Indirect calls confirmed (devirt failed) | +0.10 | 0.10 | 0.98 |
| Fully devirtualized | −0.25 | 0.30 | — |
| Lock/mutex call confirmed in lowered code | +0.05 | 0.10 | 0.95 |
| Stack frame size confirmed | +0.10 | 0.10 | 0.98 |

All adjustments are clamped and recorded in the diagnostic's `escalations` array for traceability.

### Stage 3: Post-Processing

- **Deduplication** — When multiple TUs include the same header, struct-level rules emit duplicate diagnostics. Dedup key: `(ruleID, file, line)` for struct rules; `(ruleID, functionName)` for function rules. Keeps the instance with highest confidence. Merges escalation traces from all instances.
- **Interaction synthesis** — Correlates diagnostics from different rules at the same code site using the `InteractionEligibilityMatrix`. Eligible pairs or triples produce compound hazard findings (FL090) with site-specific evidence.
- **Precision budget** — Per-rule governance: configurable max emissions per TU, minimum confidence floor, severity cap. Rules exceeding their FP rate threshold are auto-demoted.
- **Calibration suppression** — If `--calibration-store` is provided, suppresses diagnostics matching known false-positive feature neighborhoods (Euclidean distance, radius 0.25). Safety rail: Critical or High severity findings with Proven evidence tier are never suppressed.
- **Filtering and sorting** — Suppressed diagnostics, findings below `--min-severity`, and findings below `--min-evidence` are removed. Remaining diagnostics are sorted: Critical first, then by file path, then by line number.

### Stage 4: Hypothesis Engine (optional, activated by `--calibration-store`)

Generates formal experiment designs for runtime validation of flagged hazards.

- **HypothesisConstructor** — Maps each diagnostic to a `LatencyHypothesis` containing: null hypothesis (H0), alternative hypothesis (H1), primary latency metric (p99/p99.9/p99.99), required and optional PMU counter sets, minimum detectable effect, significance level (α = 0.01), target power (1 − β = 0.90), and confound controls.
- **ExperimentSynthesizer** — Generates runnable experiment bundles: treatment/control C++ harnesses, build scripts, Makefile, `perf stat` collection scripts, hypothesis metadata JSON, and a README. Writes to disk.
- **MeasurementPlanGenerator** — Partitions counter sets into hardware-compatible groups (respecting per-group counter limits), generates `perf stat`, `perf c2c`, and `perf record -b` (LBR) collection scripts.
- **CalibrationFeedbackStore** — Ingests experiment results, assigns labels (Positive, Negative, Unlabeled, Excluded), tracks per-rule false-positive rates, and maintains a feature-neighborhood false-positive registry.
- **PMUTraceFeedbackLoop** — Closed-loop learning from production PMU traces. Ingests counter data collected at flagged sites, evaluates against per-hazard-class thresholds, updates Bayesian priors, and feeds labeled records back into the calibration store. Priors persist across runs via `--pmu-priors`.

---

## Rules

15 rules, each targeting a specific microarchitectural hazard class.

| ID | Hazard Class | What It Detects | Scope |
|---|---|---|---|
| FL001 | Cache geometry | Struct spanning multiple 64B cache lines; fields straddling line boundaries | Struct |
| FL002 | False sharing | Mutable fields sharing a cache line in a type with thread-escape evidence | Struct |
| FL010 | Atomic ordering | `seq_cst` ordering where `release`/`acquire` is sufficient on x86-64 TSO | Function (hot) |
| FL011 | Atomic contention | Atomic write sites likely to generate cross-core RFO traffic | Struct |
| FL012 | Lock contention | `std::mutex`, `std::lock_guard`, or similar in a hot function | Function (hot) |
| FL020 | Heap allocation | `operator new`, `operator delete`, `malloc`, `free` in a hot function. Severity adjusted by linked allocator topology. | Function (hot) |
| FL021 | Stack pressure | Function stack frame exceeding configurable threshold (default 2048B) | Function |
| FL030 | Virtual dispatch | Virtual method call or indirect call via vtable in a hot function | Function (hot) |
| FL031 | `std::function` overhead | `std::function` invocation in a hot function (type erasure + indirect call) | Function (hot) |
| FL040 | Global mutable state | Global or namespace-scope mutable variable accessible without thread confinement | Declaration |
| FL041 | Contended queue | Producer/consumer atomic fields (`head`/`tail`) on the same cache line | Struct |
| FL050 | Deep conditional | Conditional nesting depth exceeding threshold (default 4) in a function | Function |
| FL060 | NUMA locality | Shared mutable structure with unfavorable inferred NUMA placement | Struct |
| FL061 | Centralized dispatch | Single dispatcher function routing to many handlers (branch predictor stress) | Function (hot) |
| FL090 | Hazard amplification | Compound hazard: multiple rules fire at the same site, interaction is super-additive | Synthesized |

### Interaction Templates (FL090)

Seven defined interaction templates model compound hazard amplification:

| Template | Components | Mechanism |
|---|---|---|
| IX-001 | CacheGeometry × AtomicContention | Multi-line RFO amplification |
| IX-002 | FalseSharing × AtomicContention | Same-line invalidation + write serialization |
| IX-003 | AtomicOrdering × AtomicContention | Fence serialization + ownership transfer |
| IX-004 | AtomicContention × NUMALocality | Cross-socket RFO traffic |
| IX-005 | LockContention × HeapAllocation | Allocation under lock |
| IX-006 | VirtualDispatch × DeepConditional | Compounding branch misprediction |
| IX-007 | CacheGeometry × AtomicContention × NUMALocality | Full compound: geometry + contention + NUMA |

---

## Diagnostic Model

Every diagnostic carries three orthogonal quality signals:

| Signal | Type | Values | Semantics |
|---|---|---|---|
| Severity | Enum | `Critical`, `High`, `Medium`, `Informational` | Worst-case latency impact if the hazard is exercised |
| Confidence | Float | `[0.0, 1.0]` | Tool's belief that the hazard exists at this site, given available evidence |
| Evidence Tier | Enum | `Proven`, `Likely`, `Speculative` | Strength of the structural or IR-level backing |

Each diagnostic also includes:

- `ruleID` — rule that produced the finding (e.g., `FL002`)
- `location` — file, line, column
- `functionName` — enclosing function (empty for struct-level findings)
- `hardwareReasoning` — explanation of the hardware mechanism
- `structuralEvidence` — measured metrics (sizes, field counts, offsets)
- `mitigation` — specific remediation guidance
- `escalations` — ordered trace of confidence/severity adjustments with reasons

### Output Formats

| Format | Flag | Specification |
|---|---|---|
| CLI | `--format=cli` (default) | Human-readable terminal output |
| JSON | `--format=json` | Machine-readable; includes `metadata` block (tool version, timestamp, config path, IR opt level, source files, compiler paths) and `diagnostics` array |
| SARIF 2.1.0 | `--format=sarif` | Conforms to [SARIF 2.1.0 schema](https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json); includes `invocations`, `artifacts`, and rule descriptors |

JSON and SARIF outputs embed execution metadata for reproducibility. Unknown `--format` values produce a warning on stderr and fall back to CLI.

---

## Configuration

### Config File

Default values are compiled in. Override via `--config=path/to/file.yaml`:

```yaml
# Cache model (x86-64 baseline)
cache_line_bytes: 64
cache_line_span_warn: 64     # FL001 warning threshold (bytes)
cache_line_span_crit: 128    # FL001 critical threshold (bytes)

# Stack frame
stack_frame_warn_bytes: 2048 # FL021 threshold

# Allocation
alloc_size_escalation: 256   # FL020 escalation threshold (bytes)

# Branch depth
branch_depth_warn: 4         # FL050 nesting threshold

# TLB
page_size: 4096

# Output
json_output: false
output_file: ""

# Hot path classification (fnmatch patterns)
hot_function_patterns:
  - "*::onMarketData*"
  - "*::process*"
hot_file_patterns:
  - "*/hot_path/*"
  - "*/critical/*"

# Rule control
disabled_rules: []
```

### CLI Flags

| Flag | Description |
|---|---|
| `--config=<file>` | YAML configuration file path |
| `--format=cli\|json\|sarif` | Output format |
| `--output=<file>` | Write output to file instead of stdout |
| `--min-severity=Informational\|Medium\|High\|Critical` | Minimum severity to emit |
| `--min-evidence=speculative\|likely\|proven` | Minimum evidence tier to emit |
| `--no-ir` | Skip IR emission and analysis (AST-only) |
| `--ir-opt=O0\|O1\|O2` | IR optimization level (default: O0) |
| `--ir-jobs=N` | Max parallel IR emission jobs (default: hardware concurrency) |
| `--ir-batch-size=N` | TUs per IR shard (default: 1) |
| `--no-ir-cache` | Disable incremental IR cache. Recommended for CI. |
| `--allocator=tcmalloc\|jemalloc\|mimalloc` | Linked allocator library (affects FL020) |
| `--perf-profile=<file>` | Perf profile data for hot-path selection |
| `--hotness-threshold=<pct>` | Sample percentage threshold for profile hotness (default: 1.0) |
| `--calibration-store=<path>` | Path to calibration feedback store |
| `--pmu-trace=<file>` | Production PMU trace data (TSV format) for closed-loop learning |
| `--pmu-priors=<file>` | Path to persist/load Bayesian hazard priors across runs |
| `--json` | Deprecated. Use `--format=json`. |
| `--version` | Print tool version and output schema version |

### Hot Path Annotation

Functions can be marked hot in source:

```cpp
[[clang::annotate("faultline_hot")]]
void onMarketData(const Update& u);
```

Or via config patterns:

```yaml
hot_function_patterns:
  - "*::onMarketData*"
  - "*::process*"
hot_file_patterns:
  - "*/hot_path/*"
```

Or via perf profile: functions exceeding `--hotness-threshold` percent of total samples are classified as hot.

---

## Examples

### Cache Line Spanning (FL001)

**Before:**

```cpp
struct OrderBookLevel {
    uint64_t px[8];
    uint64_t qty[8];
    uint64_t flags[4];
};
// sizeof = 160B → spans 3 cache lines
```

**Diagnostic:**

```
[HIGH] FL001 — Cache Line Spanning Struct
  Evidence: sizeof(OrderBookLevel)=160B; lines_spanned=3
```

**After:**

```cpp
struct alignas(64) OrderBookHot {
    uint64_t px[4];
    uint64_t qty[4];
};

struct OrderBookCold {
    uint64_t px[4];
    uint64_t qty[4];
    uint64_t flags[4];
};
```

Hot-path accesses touch one cache line instead of three, reducing L1D pressure and coherence surface.

### False Sharing (FL002)

**Before:**

```cpp
struct Counters {
    std::atomic<uint64_t> head;
    std::atomic<uint64_t> tail;
};
```

**Diagnostic:**

```
[CRITICAL] FL002 — False Sharing Candidate
  Evidence: sizeof=16B; mutable_fields=[head,tail]; atomics=yes; thread_escape=true
```

**After:**

```cpp
struct Counters {
    alignas(64) std::atomic<uint64_t> head;
    alignas(64) std::atomic<uint64_t> tail;
};
```

Separating independent writers onto different cache lines eliminates cross-core ownership transfer (RFO/HITM).

### Overly Strong Atomic Ordering (FL010)

**Before:**

```cpp
[[clang::annotate("faultline_hot")]]
void publish(std::atomic<uint64_t>& seq, uint64_t v) {
    seq.store(v); // implicit seq_cst
}
```

**Diagnostic:**

```
[HIGH] FL010 — Overly Strong Atomic Ordering
  Evidence: ordering=seq_cst; function=publish
```

**After:**

```cpp
[[clang::annotate("faultline_hot")]]
void publish(std::atomic<uint64_t>& seq, uint64_t v) {
    seq.store(v, std::memory_order_release);
}
```

On x86-64 TSO, `release` stores do not require the `MFENCE` or `LOCK`-prefixed instruction that `seq_cst` may emit, reducing serialization in hot loops.

---

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | No findings at or above configured severity/evidence thresholds |
| 1 | Findings emitted |
| 2 | Input parse or compilation error (ClangTool failed; no findings produced) |
| 3 | Tool infrastructure failure (cannot write output file, cannot load config) |

When some TUs fail to parse but others succeed, exit code is 1 (findings from successful parses are emitted) with a warning on stderr.

---

## Validation

### Contract Tests

```bash
./build/output_schema_contract_test
```

Validates: JSON field completeness, severity ordering, confidence bounds `[0.0, 1.0]`, SARIF schema conformance, NaN/Inf guarding, control character escaping, and stress behavior with large diagnostic counts.

### Corpus Regression

```bash
./validation/run.sh --tier1
```

Runs faultline against internal test samples and external corpora. Asserts: no crashes, deterministic output across runs, valid source locations, diagnostic distribution sanity, evidence parseability.

### Ground-Truth Benchmarks

```bash
./validation/run.sh --tier2
```

Runs paired hazardous/fixed microbenchmarks per rule with hardware timing and optional `perf stat` counters. Statistical analysis via paired t-test when scipy is available.

---

## Boundaries and Limitations

These are known limitations of the current implementation. They are documented here so that users can make informed decisions about the tool's applicability to their codebase.

- **Static analysis only.** Faultline does not execute code, attach to processes, or read PMU counters. It identifies structural patterns that correlate with known hardware penalties. Runtime validation is required to confirm impact magnitude.
- **Single-TU escape analysis.** `EscapeAnalysis` inspects structural members and scans publication paths within the current translation unit. It does not perform cross-TU or whole-program interprocedural dataflow analysis. Types that escape through interfaces not visible in the current TU may not be detected.
- **IR refinement is not a lowering proof.** The IR pass confirms or refutes AST-level findings using post-optimization IR. It does not establish a bijective mapping between source sites and lowered instructions. Confidence adjustments are bounded heuristics, not proofs.
- **IR cache invalidation.** Cache keys include source content, mtime, compile args, tool version, and `.d` dependency file contents if present. Header-only changes without a corresponding `.d` file update may not invalidate the cache. Use `--no-ir-cache` in CI pipelines.
- **NUMA analysis is structural.** NUMA placement is inferred from allocation context (global, stack, heap) and first-touch heuristics. Actual page placement depends on runtime thread scheduling and OS policy, which cannot be determined statically.
- **No TSan integration.** Thread-safety analysis relies on structural heuristics, not runtime race detection.
- **Three hazard classes lack hypothesis templates.** `DeepConditional` (FL050), `GlobalState` (FL040), and `CentralizedDispatch` (FL061) have analysis rules but no PMU experiment templates registered in the hypothesis engine. The hypothesis subsystem returns empty results for these classes.

---

## License

See repository for license terms.