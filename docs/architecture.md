# Architecture

lshaz is a Clang-based static analysis tool that maps C++ source-level patterns to microarchitectural latency hazards on Linux x86-64.

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
- TUs with fatal parse errors are skipped entirely — no diagnostics emitted for partial ASTs.
- Per-TU crash isolation via `llvm::CrashRecoveryContext`. If a TU triggers SIGSEGV/SIGABRT, it is recorded as failed and scanning continues.

**Supporting analyses available to rules:**

- **CacheLineMap** — Maps struct fields to 64-byte cache line boundaries using `ASTContext::getASTRecordLayout`. Reports straddling fields and per-line field groupings.
- **EscapeAnalysis** — Determines whether a type may be accessed from multiple threads. Uses seven evidence signals: `std::atomic` members, mutex/sync primitive members, `std::shared_ptr`/`std::weak_ptr` members, `volatile` members, types passed to `std::thread`/`std::jthread`/`std::async`, types stored in global mutable variables, and types used as `shared_ptr` pointees in global scope. Conservative: assumes escape when uncertain. Not interprocedural — scans the current TU only.
- **AllocatorTopology** — Classifies allocator contention based on `--allocator` flag: glibc (arena-lock), tcmalloc/jemalloc (thread-local cache), mimalloc (pool/slab). Affects FL020 severity.
- **NUMATopology** — Infers NUMA page placement via first-touch policy analysis: local-init, main-thread, any-thread, interleaved, explicit-bind, or unknown.
- **HotPathOracle** — Classifies functions as hot via:
  1. `[[clang::annotate("lshaz_hot")]]` attribute
  2. fnmatch glob patterns in config (`hot_function_patterns`, `hot_file_patterns`)
  3. `perf` profile sample threshold (`--perf-profile`, `--hotness-threshold`)
  4. Transitive marking during AST walk

### Stage 2: IR Refinement

After AST analysis, the tool optionally emits and analyzes LLVM IR to confirm or refute AST-level findings.

**IR emission:**
- Compiler resolved from `compile_commands.json` argv[0], with PATH fallback to `clang++`, `clang++-18`, `clang++-17`, `clang++-16`.
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

- **Deduplication** — When multiple TUs include the same header, struct-level rules emit duplicates. Dedup key: `(ruleID, file, line)` for struct rules; `(ruleID, functionName)` for function rules. Keeps highest-confidence instance. Merges escalation traces.
- **Interaction synthesis** — Correlates diagnostics from different rules at the same code site using the `InteractionEligibilityMatrix`. Eligible pairs or triples produce compound hazard findings (FL091).
- **Precision budget** — Per-rule governance: configurable max emissions per TU, minimum confidence floor, severity cap. Rules exceeding FP rate threshold are auto-demoted.
- **Calibration suppression** — If `--calibration-store` is provided, suppresses diagnostics matching known false-positive feature neighborhoods (Euclidean distance, radius 0.25). Safety rail: Critical/High + Proven evidence never suppressed.
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
- Sources are sharded round-robin across worker threads.
- Each shard gets its own `LshazActionFactory`, `HotPathOracle`, and diagnostic vector.
- `compDB` is read-only and shared safely.
- Results are merged after all shards complete.
- Per-shard crash isolation via `CrashRecoveryContext`.

## Severity Escalation

Risk severity increases when multiple hazards interact at the same code site:

| Condition | Effect |
|---|---|
| Struct > 128B + thread-escape + atomic writes | Critical |
| Atomic with `seq_cst` + inside tight loop | High |
| Large stack frame + deep call chain | TLB pressure warning |
| Multiple rules fire at same site | FL091 compound interaction |
