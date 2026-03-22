# Architecture

lshaz is a Clang-based static analysis tool that maps C and C++ source-level patterns to microarchitectural latency hazards on Linux x86-64.

## System Layers

The tool operates in three layers:

1. **AST Layer** — Structural analysis via Clang AST. Inspects struct layouts, field mutability, escape analysis, atomic usage, dispatch patterns, allocation sites.
2. **IR Layer** — Optional LLVM IR analysis (`--no-ir` to disable). Confirms or refutes AST findings after compiler optimizations. Detects surviving heap allocations, atomic instructions, indirect calls, stack frame sizes.
3. **Post-Processing** — Deduplication, interaction synthesis, precision budget, calibration feedback, filtering.

## Analysis Pipeline

### Stage 1: AST Analysis

Entry point: `LshazASTConsumer::HandleTranslationUnit`.

For each translation unit, walks all top-level declarations (recursing into namespaces, linkage specs, and nested record types) and runs all registered rules. System headers are skipped. Dependent and invalid declarations are filtered before rule execution.

**TU-level safety:**
- TUs with fatal parse errors are skipped entirely — no diagnostics emitted for partial ASTs. Each failed TU is recorded as a `FailedTU` with both the file path and the verbatim first error message, captured via an `ErrorCapture` forwarding `DiagnosticConsumer` installed in `BeginSourceFileAction`. This enables downstream header fingerprint detection (see Post-Processing).
- Per-TU crash isolation via `llvm::CrashRecoveryContext`. If a TU triggers SIGSEGV/SIGABRT, it is recorded as failed with a crash-specific error message and scanning continues.

**Supporting analyses available to rules:**

- **CacheLineMap** — Maps struct fields to 64-byte cache line boundaries using `ASTContext::getASTRecordLayout`. Reports straddling fields and per-line field groupings. Atomic detection covers `_Atomic`, `std::atomic`, volatile typedefs with "atomic" in the name (e.g. `ngx_atomic_t`), and user-configured opaque wrapper types via `atomic_type_names` (e.g. kernel `atomic_t`, `spinlock_t`). Includes a refcount-only heuristic: structs with exactly one atomic field matching a refcount naming pattern are downgraded (FL001) or suppressed (FL002) to reduce false positives on COW/shared_ptr objects.
- **EscapeAnalysis** — Determines whether a type may be accessed from multiple threads. Uses seven evidence signals: `std::atomic` members, mutex/sync primitive members, `std::shared_ptr`/`std::weak_ptr` members, `volatile` members, types passed to `std::thread`/`std::jthread`/`std::async`, types stored in global mutable variables, and types used as `shared_ptr` pointees in global scope. Conservative: assumes escape when uncertain. **Lifecycle:** instantiated once per TU by `LshazASTConsumer` and injected into all rules via `Rule::analyze(..., EscapeAnalysis&, ...)`. This guarantees each TU gets a fresh analysis with no stale state leaking across TU boundaries. After rule execution, `buildEscapeSummary()` snapshots per-type signals (`TypeEscapeSignals`) keyed by canonical qualified type name into an `EscapeSummary` for cross-TU aggregation (see Parallel Execution).
- **AllocatorTopology** — Classifies allocator contention based on `--allocator` flag: glibc (arena-lock), tcmalloc/jemalloc (thread-local cache), mimalloc (pool/slab). Affects FL020 severity.
- **NUMATopology** — Infers NUMA page placement via first-touch policy analysis: local-init, main-thread, any-thread, interleaved, explicit-bind, or unknown.
- **CallGraph** — Per-TU call graph built by visiting `CallExpr` nodes in function bodies. Maps caller → callee relationships. Used by HotPathOracle for transitive hotness propagation.
- **DataFlowAnalyzer** — Lightweight intra-procedural data-flow analysis. Two-pass AST walk: (1) identifies variable bindings to heap allocations and atomic load results, (2) tracks tainted variables through uses — detecting alloc-escapes (passed to callee, stored to field, returned), alloc-flows-to-loop, and atomic-feeds-branch patterns. Used by FL020 and FL010 for precision escalation.
- **HotPathOracle** — Classifies functions as hot via:
  1. `__attribute__((hot))` or `[[clang::annotate("lshaz_hot")]]` attributes
  2. fnmatch glob patterns in config (`hot_function_patterns`, `hot_file_patterns`)
  3. `perf` profile sample threshold (`--perf-profile`, `--hotness-threshold`)
  4. Transitive propagation via CallGraph: if a hot function calls `f`, then `f` is also marked hot

### Stage 2: IR Refinement

After AST analysis, the tool optionally emits and analyzes LLVM IR to confirm or refute AST-level findings.

**IR emission:**
- Compiler resolved from `compile_commands.json` argv[0], with PATH fallback to `clang++`, `clang++-18`, `clang++-17`, `clang++-16`.
- **GCC-shim:** When the compile_commands.json compiler is GCC, IR emission forces clang/clang++ and strips GCC-only flags (`-Wshadow=compatible-local`, `-Wimplicit-fallthrough=N`, `-Wcast-function-type`, etc.) that clang rejects. This enables IR analysis on GCC-compiled codebases (e.g., PostgreSQL).
- IR emitted via `llvm::sys::ExecuteAndWait`. No shell interpolation.
- Parallelism bounded by `std::counting_semaphore` at `--ir-jobs` (default: `hardware_concurrency()`).
- Jobs grouped into shards of `--ir-batch-size` TUs. Each shard owns its own `LLVMContext`.
- Temp file naming: MD5 of source content + mtime + compile args + tool version + `.d` dependency file. Identical inputs reuse cached IR.
- Subprocess timeout: 120 seconds.

**IR analysis (`IRAnalyzer`):**

Per function, collects: stack allocations (`AllocaInst`, name, size, array flag), heap call sites (direct/indirect, in-loop), atomic operations (load/store/RMW/CmpXchg/fence, ordering, in-loop, source location), basic block count, loop count, indirect vs direct call counts.

**Confidence refinement (`DiagnosticRefiner`):**

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

### Stage 3: Post-Processing

- **Deduplication** — When multiple TUs include the same header, struct-level rules emit duplicates. Dedup key: `(ruleID, file, line)` for most struct rules; `(ruleID, var, type)` for FL040 (global state); `(ruleID, functionName, line)` for function rules. Keeps highest-confidence instance with a deterministic tiebreaker (shortest file path → lexicographic → lowest line). Merges escalation traces from all duplicates.
- **Interaction synthesis** — Correlates diagnostics from different rules at the same code site using the `InteractionEligibilityMatrix`. Eligible pairs or triples produce compound hazard findings (FL091).
- **Precision budget** — Per-rule governance: configurable max emissions per TU, minimum confidence floor, severity cap. Rules exceeding FP rate threshold are auto-demoted.
- **Calibration suppression** — If `--calibration-store` is provided, suppresses diagnostics matching known false-positive feature neighborhoods (Euclidean distance, radius 0.25). Safety rail: Critical/High + Proven evidence never suppressed.
- **Header fingerprint detection (B001)** — After filtering, the pipeline aggregates error messages from all `FailedTU` objects, extracts missing header names via pattern matching (`fatal error: '...' file not found`), and emits a `B001` diagnostic for any header missing in ≥3 TUs. This surfaces systematic build configuration issues (e.g., missing `configure_file()` output) as actionable diagnostics rather than silent TU failures.
- **Filtering and sorting** — Suppressed diagnostics removed. Remaining sorted: Critical first, then by file path, then by line number.

## Latency Model

lshaz assumes the following hardware model:

| Component | Assumption |
|---|---|
| Cache line | 64 bytes |
| L1/L2 | Private per core |
| L3/LLC | Shared |
| Coherence | MESI protocol |
| Memory model | x86-64 TSO |
| Page size | 4KB (configurable) |
| NUMA | First-touch page placement |

The tool models line-level structural exposure. It does not simulate cache sets, associativity, or cycle-accurate timing.

## Parallel Execution

AST analysis supports parallel execution via `--jobs N`:
- Sources are sharded round-robin across N worker processes.
- Each shard runs in a **forked child process** with its own address space. This provides hardware-level isolation from Clang's thread-unsafe global state (`llvm::cl` option tables, `CrashRecoveryContext` signal handlers, `FileManager` stat caches).
- `compDB` is wrapped in `AbsolutePathCompilationDatabase` at load time, which resolves all relative paths (source files, `-I` flags, `-isystem` flags) to absolute.
- Children serialize diagnostics, `FailedTU` objects (file path + error message), and per-shard `EscapeSummary` to temp files via a minimal JSON IPC protocol. The parent reads them back after `waitpid()`, merges escape summaries across all shards into `ScanResult.escapeSummary`, and aggregates `FailedTU` objects for header fingerprint detection.
- After merging, diagnostics are sorted by a stable canonical key `(ruleID, file, line, column, functionName)` before any order-dependent pass (cross-TU suppression, deduplication, precision budget). This guarantees byte-identical output regardless of process count or scheduling order.
- Per-TU crash isolation via `CrashRecoveryContext` within each child. If a child is killed by a signal, all its TUs are recorded as failed.
- **FL040 two-pass architecture:** FL040 uses a MapReduce design to avoid per-TU partial-information verdicts. In the map phase, each shard emits every global-state candidate unconditionally with its per-TU write count (`tu_write_count`) and initializer status (`has_init`). In the reduce phase (post-merge, pre-dedup), the pipeline aggregates write counts per `(var, type)` across all TUs and applies the write-once threshold on the global sum. This guarantees identical classification regardless of shard count or scheduling order. FL040 dedup uses a stable key (`var` + `type`) with a deterministic tiebreaker (shortest file path → lexicographic → lowest line) for canonical location selection. All diagnostic locations are resolved via `getFileLoc()` to map Clang `<scratch space>` token-paste artifacts back to their physical file locations.
- **EscapeAnalysis ownership:** `EscapeAnalysis` is instantiated per-TU inside `LshazASTConsumer::HandleTranslationUnit` and passed by reference to all rules. Rules are stateless singletons — they never cache per-TU analysis state. This dependency injection pattern eliminates a class of non-determinism bugs caused by heap address reuse across TU boundaries in forked child processes.
- **Cross-TU escape aggregation:** Each TU emits an `EscapeSummary` — a map from canonical qualified type name to `TypeEscapeSignals` (atomics, sync primitives, shared ownership, volatile, publication evidence, accessor count). Structural signals (atomics, sync, volatile, shared_ptr) are derivable from the type definition and are identical across TUs that include the same header. Publication signals (global store, thread-creation argument) are TU-specific. In the reduce phase (post-merge, pre-dedup), `applyCrossTUEscapeSuppression` queries the aggregated global `EscapeSummary` by the `type_name` stored in each diagnostic's `structuralEvidence`. Diagnostics for types with no cross-TU escape evidence are suppressed. Proven-tier findings and diagnostics without `type_name` are never suppressed. This replaces the earlier multiplicity-based heuristic that used diagnostic count as a proxy for multi-TU presence.

## Experiment Synthesis Pipeline

`lshaz hyp` and `lshaz exp` form a two-stage pipeline that converts static findings into runnable hardware experiments.

### Stage 1: Hypothesis Construction (`lshaz hyp`)

Each diagnostic is mapped to a `HazardClass` via `HypothesisConstructor::mapRuleToHazardClass`. The `HypothesisTemplateRegistry` provides per-class templates containing:

- **H0/H1** — Null and alternative hypotheses in statistical terms
- **PMU counter set** — Required and optional hardware counters, partitioned into groups that fit the PMU's multiplexing limit
- **Primary metric** — The tail latency percentile under test (p99, p99.9, p99.99)
- **MDE** — Minimum detectable effect (default 5% relative increase)
- **Confound controls** — Turbo boost, C-states, THP, ASLR, CPU governor, interrupt isolation

Evidence tier is inferred from the diagnostic's `structuralEvidence` map: AST-provable layout facts yield `Proven`, concurrency signals yield `Likely`, everything else `Speculative`.

### Stage 2: Experiment Bundle Synthesis (`lshaz exp`)

For each hypothesis, `ExperimentSynthesizer` generates a self-contained experiment directory:

| File | Purpose |
|---|---|
| `src/common.h` | Anti-elision primitives (`lshaz_do_not_optimize`, `lshaz_clobber_memory`), `lfence`-bracketed `rdtsc` |
| `src/treatment.cpp` | Kernel reproducing the structural hazard, parameterized by `structuralEvidence` |
| `src/control.cpp` | Kernel with the hazard removed (aligned, sharded, lock-free, etc.) |
| `src/harness.cpp` | Warmup → measurement loop, core pinning, binary sample output |
| `Makefile` | Separate TU compilation to prevent cross-variant optimization |
| `scripts/run_all.sh` | Environment setup → build → run → PMU collection → teardown |
| `scripts/run_perf_stat.sh` | `perf stat` with counter groups partitioned to fit PMU slots |
| `scripts/run_perf_c2c.sh` | `perf c2c` for false-sharing / contention hazards |
| `scripts/setup_env.sh` | Disable turbo, THP, ASLR, C-states; set performance governor |
| `hypothesis.json` | Machine-readable hypothesis metadata |
| `README.md` | Human-readable experiment description with statistical parameters |

Treatment and control kernels are generated per hazard class. 13 hazard classes have dedicated kernel generators; 3 (CentralizedDispatch, HazardAmplification, SynthesizedInteraction) emit editable stubs. Kernels are parameterized by structural evidence — FL001 uses `sizeof` and `lines_spanned`, FL021 uses `estimated_frame`, FL050 uses `depth`.

**Invariant:** Treatment and control are compiled as separate TUs and linked into a single binary. The harness dispatches via `--variant` at runtime. This prevents the compiler from optimizing across the comparison boundary while keeping measurement infrastructure identical.

## Severity Escalation

Risk severity increases when multiple hazards interact at the same code site:

| Condition | Effect |
|---|---|
| Struct > 128B + thread-escape + atomic writes | Critical |
| Atomic with `seq_cst` + inside tight loop | High |
| Large stack frame + deep call chain | TLB pressure warning |
| Multiple rules fire at same site | FL091 compound interaction |
