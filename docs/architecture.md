# Architecture

lshaz maps C/C++ source-level patterns to microarchitectural latency hazards.
This document describes the analysis pipeline, the supporting analyses rules
draw on, the evidence model, and the determinism contract. Per-rule detection
logic lives in [rules.md](rules.md).

## System layers

1. **AST layer** — structural analysis via Clang AST: record layouts, field
   mutability, escape analysis, atomic usage, write sites, dispatch patterns,
   allocation sites.
2. **IR layer** (optional; `--no-ir` disables) — re-emits LLVM IR per TU and
   confirms or refutes AST findings after optimization: surviving heap calls,
   atomic instructions, indirect calls, real frame sizes.
3. **Post-processing** — cross-TU aggregation, deduplication, interaction
   synthesis, precision budget, calibration suppression, build-health
   detection, final sort.

## Stage 1: AST analysis

Entry point: `LshazASTConsumer::HandleTranslationUnit`. For each TU, walks all
top-level declarations — recursing into namespaces, linkage specs, and nested
record types — and runs every registered rule. System headers are skipped;
dependent and invalid declarations are filtered before rule execution.

Rules are **stateless singletons** registered via `LSHAZ_REGISTER_RULE`. All
per-TU state lives in the analyses injected into `Rule::analyze` — never on
the rule object (see [Determinism](#determinism)).

**TU-level safety:**

- TUs with fatal parse errors are skipped entirely; no diagnostics are emitted
  from partial ASTs. Each failure is recorded as a `FailedTU` carrying the
  file path and the verbatim first error message, captured by an
  `ErrorCapture` diagnostic consumer. These feed header-fingerprint detection
  (B001, below).
- Per-TU crash isolation via `llvm::CrashRecoveryContext`: a TU that raises
  SIGSEGV/SIGABRT is recorded as failed and scanning continues.

### Supporting analyses

**CacheLineMap** (`src/analysis/CacheLineMap.cpp`) — exact field-to-line
mapping from `ASTRecordLayout`, including base subobjects and nested records.
Key semantics:

- *Bucketing.* When the record's alignment is below the line size, the base
  address can sit at any realizable shift; each field is bucketed into the
  union of lines it could occupy under any shift. Bucket contents are
  therefore an over-approximation for sub-line-aligned records and exact for
  line-aligned ones.
- *Pair co-residency.* Shared-line pairs are **not** derived from bucket
  co-membership alone (fields whose shift ranges overlap in line index may
  never coexist at the same shift). A pair requires a realizable common
  shift placing both fields on one line — checked over all shifts in
  record-alignment steps; degenerates to the exact same-line test at
  alignment ≥ line size.
- *Straddlers.* The per-field `straddles` flag is geometric (spans a boundary
  under some shift). `straddlingFields()` — the API behind split load/store
  penalty escalations — additionally requires an access granule wider than
  one byte: byte arrays span lines but cannot split a single access.
- *Layout-intent signals.* `isCacheLineAligned()` (record alignment ≥ line)
  and `hasTrailingLinePad()` (trailing byte-array pad reaching an exact line
  multiple) feed the deliberate-layout demotion contract in FL001/FL002/FL090.
- *Atomic detection* covers `_Atomic`, `std::atomic`, volatile typedefs with
  "atomic" in the name, and user-configured wrapper types
  (`atomic_type_names`).
- *Refcount heuristic.* A record whose only atomic matches a refcount naming
  pattern is downgraded (FL001) or suppressed (FL002) — COW/`shared_ptr`
  control blocks do not false-share.

**EscapeAnalysis** (`src/analysis/EscapeAnalysis.cpp`) — decides whether a
type may be accessed from multiple threads and quantifies expected contention.

- *Escape signals* (seven): atomic members, sync-primitive members
  (`std::mutex` family + POSIX types), `shared_ptr`/`weak_ptr` members,
  volatile members, publication to `std::thread`/`std::jthread`/`std::async`,
  storage in a non-`thread_local` mutable global, and global-scope
  `shared_ptr` pointees. Conservative: uncertainty means escape.
- *Write-site collection* (one traversal over all TU function bodies):
  - **Global write counts** per `VarDecl`, across all write forms — plain
    assignment, `++`/`--`, member writes through the global, C11/GNU atomic
    builtins, `__sync_*`, and non-const `std::atomic` mutating methods. Feeds
    FL040 and write-once analysis.
  - **Field write evidence** per `FieldDecl`: write-site count and the set of
    writer functions. Constructor member-init lists are excluded —
    initialization is not contention. Feeds FL002's pair grading
    (`pairHasDistinctWriters`: the union of two fields' writers has ≥2
    members).
- *Lifecycle.* Instantiated fresh per TU inside `HandleTranslationUnit` and
  passed by reference into every rule. After rule execution,
  `buildEscapeSummary()` snapshots per-type signals keyed by canonical
  qualified name for cross-TU aggregation.

**AllocatorTopology** — classifies allocator contention from `--allocator`:
glibc (arena lock), tcmalloc/jemalloc (thread-local cache), mimalloc
(pool/slab). Shapes FL020 severity.

**NUMATopology** — infers page placement under first-touch: local-init,
main-thread, any-thread, interleaved, explicit-bind, unknown. Feeds FL060.

**CallGraph** — per-TU caller→callee map from `CallExpr` visits. Used by
HotPathOracle for transitive hotness.

**DataFlowAnalyzer** — intra-procedural, two passes: bind variables to heap
allocations and atomic loads, then track uses — alloc-escapes,
alloc-flows-to-loop, atomic-feeds-branch (CAS retry / spin-wait signature).
Escalation input to FL010 and FL020.

**HotPathOracle** — classifies functions hot via, in order:
`__attribute__((hot))` / `[[clang::annotate("lshaz_hot")]]`; fnmatch globs
from config (`hot_function_patterns`, `hot_file_patterns`); perf profile
samples above `hotness_threshold_pct`; and transitive propagation over the
call graph (a hot caller marks its callees hot). Lookups are keyed by
canonical declaration.

## Stage 2: IR refinement

The IR pass re-compiles each TU to LLVM IR and adjusts AST-finding confidence
against post-optimization reality. TUs that failed AST parsing are skipped
individually; one broken TU does not disable refinement for the rest.

**Emission:** compiler resolved from `compile_commands.json` (the entry's
argv[0] is dropped, not re-executed), with PATH fallback to
`clang++`/`clang++-18`/`-17`/`-16`. When the recorded compiler is GCC,
emission substitutes clang and strips GCC-only flags. Subprocesses run via
`llvm::sys::ExecuteAndWait` (no shell), bounded by `--ir-jobs`, 120s timeout,
sharded per `--ir-batch-size` with one `LLVMContext` per shard. IR artifacts
are content-addressed (MD5 of source + mtime + args + tool version); identical
inputs reuse the cache unless `--no-ir-cache`.

**Analysis (`IRAnalyzer`):** per function — stack allocations (name, size),
heap call sites (direct/indirect, in-loop), atomic operations (kind, ordering,
in-loop, source location), block/loop counts, indirect vs direct calls.

**Refinement (`DiagnosticRefiner`):** matches IR functions to diagnostics by
demangled name (component-boundary match, deterministic rank-based pick among
overloads) and applies bounded confidence deltas:

| Factor | Delta |
|---|---|
| Site-confirmed (source line match) | +0.10 |
| Function-confirmed (no line match) | +0.05 |
| Pattern absent in optimized IR | −0.20 |
| Heap allocation survived inlining | +0.05 |
| Heap allocation eliminated | −0.15 |
| Indirect calls confirmed (devirtualization failed) | +0.10 |
| Fully devirtualized | −0.25 |
| Lock call confirmed in lowered code | +0.05 |
| Stack frame size confirmed | +0.10 |

Every adjustment appends an "IR confirmed"/"IR refinement" line to the
diagnostic's escalation trace — refinement is visible, never silent.

## Stage 3: Post-processing

In execution order:

1. **Canonical sort** of merged diagnostics (see Determinism).
2. **FL040 reduce** — sums per-TU write counts per `(var, type)` and applies
   the write-once threshold on the global sum.
3. **Cross-TU escape suppression** — per-TU `EscapeSummary` maps are merged;
   diagnostics whose `type_name` shows no escape evidence in any TU are
   suppressed. Runs before dedup so all duplicate instances are reclassified
   consistently. Proven-tier findings and diagnostics without `type_name` are
   never suppressed.
4. **Deduplication** — headers included by many TUs produce one finding per
   TU. Keys: `(ruleID, file, line)` for struct-level rules;
   `(ruleID, var, type)` for FL040 (the same global appears at different
   header paths); `(ruleID, functionName, line)` for function rules. The
   survivor is the **highest-confidence** instance (ties: better evidence
   tier, then shortest path → lexicographic → lowest line/column → content
   order). Escalation traces from all duplicates are merged, sorted, and
   annotated with the TU count. Because FL002 encodes write evidence into
   confidence, the TU that observes the writers decides the canonical
   verdict.
5. **Interaction synthesis (FL091)** — joins diagnostics sharing an entity
   key: `file:line`, `type:` + type name, or `fn:` + function. Eligible
   pairs/triples per the `InteractionEligibilityMatrix` produce compound
   findings; severity derives from the (post-demotion) parents. One compound
   per (template, participant set).
6. **Precision budget** — per-rule governance: max emissions per TU,
   confidence floors, severity caps.
7. **Calibration suppression** — with `--calibration-store`, findings whose
   10-dimension structural feature vector falls within Euclidean radius 0.25
   of a pattern with ≥3 experimentally refuted instances are suppressed.
   Safety rail: Critical/High findings at Proven tier are never suppressed. A
   store path that exists but cannot be parsed is a hard error (exit 3) —
   scanning with silently disabled calibration would misreport.
8. **Header fingerprint (B001)** — aggregates `FailedTU` error text; a header
   missing in ≥3 TUs becomes a single B001 diagnostic naming the header,
   converting systematic build breakage into one actionable finding.
9. **Filter and final sort** — suppressed findings drop; output orders by
   severity (Critical first), then file, then line, with a total-order
   content tiebreaker.

## Evidence model

Every diagnostic carries three orthogonal signals (see
[output-formats.md](output-formats.md)): severity (worst-case impact),
confidence ∈ [0,1] (belief the hazard is real here), and evidence tier
(`Proven` — layout-guaranteed; `Likely` — strong structural signals;
`Speculative`). Two grading principles apply tool-wide:

- **Claims are downgraded to what the evidence supports.** Sub-line-aligned
  records cannot prove co-residency → `Likely`, not `Proven`. No observed
  writers in the TU → "structural evidence only," capped severity.
- **Mitigation intent is respected.** Explicit line alignment or pad-to-line
  layout caps FL001/FL002/FL090 at Medium with the reason stated. Compounds
  never outrank their mitigation-adjusted components.

## Determinism

Output is **byte-identical regardless of `--jobs` count or scheduling**. This
is a hard invariant with specific machinery behind it:

- Parallel AST analysis shards sources round-robin across **forked child
  processes** (not threads) — hardware-level isolation from Clang's
  thread-unsafe globals. Children serialize diagnostics, `FailedTU`s, and
  `EscapeSummary` over a JSON IPC protocol; the parent merges after
  `waitpid()`.
- Merged diagnostics are sorted by the canonical key
  `(ruleID, file, line, column, functionName)` **before any order-dependent
  pass**. Key collisions (e.g., two TUs defining distinct same-line symbols
  via macro pasting — the jemalloc `je_`-prefix pattern) fall through to
  `diagnosticContentLess`, a total order over severity, confidence, tier,
  function, title, evidence, escalations, and mitigation. No comparison ends
  in "equal" for distinct content.
- Rules never cache per-TU state; `EscapeAnalysis` is constructed per TU.
  Heap-address reuse across TUs in forked children has caused real
  non-determinism; dependency injection is the fix, not discipline.
- Cross-TU aggregation is map/reduce (FL040 write counts, escape summaries):
  children emit facts, the parent computes verdicts. No per-TU partial
  verdicts.
- Locations are resolved via `getFileLoc()` so Clang `<scratch space>`
  token-paste artifacts map back to physical files.

The only run-varying output field is `metadata.timestamp`.

## Latency model

| Component | Assumption |
|---|---|
| Cache line | 64 bytes (`cache_line_bytes`) |
| L1/L2 | private per core |
| L3/LLC | shared |
| Coherence | MESI |
| Memory model | x86-64 TSO (`--target-arch arm64` switches ordering costs) |
| Page size | 4KB (`page_size`) |
| NUMA | first-touch placement |

The tool models line-level structural exposure; it does not simulate sets,
associativity, or cycle timing. Runtime impact claims are delegated to the
experiment pipeline.

## Experiment pipeline

`scan → hyp → exp → build/run → feedback → scan` closes the loop between
static findings and hardware measurements. See
[hypothesis-engine.md](hypothesis-engine.md) for the full contract. In brief:

- **`lshaz hyp`** maps each diagnostic to a falsifiable hypothesis: H0/H1,
  primary tail-latency metric, PMU counter groups partitioned to hardware
  limits, minimum detectable effect, and confound controls. All hazard
  classes have hypothesis templates.
- **`lshaz exp`** synthesizes self-contained experiment bundles: treatment
  and control kernels parameterized by the diagnostic's structural evidence,
  compiled as separate TUs into one binary dispatched by `--variant` (the
  compiler cannot optimize across the comparison boundary); a measurement
  harness with `lfence`-bracketed `rdtsc`; an `analyze` tool that bootstraps
  the percentile CI of the relative p99.9 effect; PMU collection scripts with
  guarded per-variant passes and teardown-on-failure; and `hypothesis.json`
  embedding the structural features calibration requires. 13 hazard classes
  have dedicated kernel generators; CentralizedDispatch, HazardAmplification,
  and SynthesizedInteraction emit editable stubs.
- **`lshaz feedback`** ingests binary sample files and the recorded
  environment (`results/env.json`), runs Welch's t-test, computes achieved
  power (two-sample z at the achieved sample sizes), and writes a verdict
  into the versioned calibration store (atomic temp+rename). Quality gates:
  labels below 0.60 quality demote to unlabeled; refutations require power
  ≥ 0.80; environment penalties for missing confound controls (turbo −0.15,
  governor −0.10, pinning −0.20). Bundles without structural features are
  refused.

Refuted patterns suppress structurally similar findings on subsequent scans
(post-processing step 7). PMU trace feedback (`--pmu-trace`, `--pmu-priors`)
provides a parallel ingestion path from production `perf stat` data with
Bayesian per-class priors.
