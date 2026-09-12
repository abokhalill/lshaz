# Architecture

lshaz maps C/C++ source-level patterns to microarchitectural latency hazards.
This document describes the analysis pipeline, the supporting analyses rules
draw on, the evidence model, and the determinism contract. Per-rule detection
logic lives in [rules.md](rules.md).

## System layers

1. **AST layer**. Structural analysis via Clang AST: record layouts, field
   mutability, escape analysis, atomic usage, write sites, dispatch patterns,
   allocation sites.
2. **IR layer** (optional; `--no-ir` disables), re-emits LLVM IR per TU and
   confirms or refutes AST findings after optimization: surviving heap calls,
   atomic instructions, indirect calls, real frame sizes.
3. **Post-processing**. Cross-TU aggregation, deduplication, interaction
   synthesis, precision budget, calibration suppression, build-health
   detection, final sort.

## Stage 1: AST analysis

Entry point: `LshazASTConsumer::HandleTranslationUnit`. For each TU, walks all
top-level declarations. Recursing into namespaces, linkage specs, and nested
record types, and runs every registered rule. System headers are skipped;
dependent and invalid declarations are filtered before rule execution.

Rules are **stateless singletons** registered via `LSHAZ_REGISTER_RULE`. All
per-TU state lives in the analyses injected into `Rule::analyze`, never on
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

**CacheLineMap** (`src/analysis/cache_line.cpp`), exact field-to-line
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
  shift placing both fields on one line, checked over all shifts in
  record-alignment steps; degenerates to the exact same-line test once
  alignment reaches the line size.
- *Straddlers.* The per-field `straddles` flag is geometric: it spans a
  boundary under some shift. `straddlingFields()` is stricter and backs the
  split load/store escalations, additionally requiring an access granule wider
  than one byte, since byte arrays span lines but cannot split a single
  access.
- *Layout-intent signals.* `isCacheLineAligned()` (record alignment at or
  above the line) and `hasTrailingLinePad()` (trailing byte-array pad reaching
  an exact line multiple) feed the deliberate-layout demotion contract in
  FL001/FL002/FL090.
- *Atomic detection* covers `_Atomic`, `std::atomic`, volatile typedefs with
  "atomic" in the name, and user-configured wrapper types
  (`atomic_type_names`).
- *Refcount heuristic.* A record whose only atomic matches a refcount naming
  pattern is downgraded (FL001) or suppressed (FL002), COW/`shared_ptr`
  control blocks do not false-share.

**EscapeAnalysis** (`src/analysis/escape.cpp`), decides whether a
type may be accessed from multiple threads and quantifies expected contention.

- *Escape signals* (eight): atomic members, sync-primitive members
  (`std::mutex` family plus POSIX types), `shared_ptr` / `weak_ptr` members,
  volatile members, publication to `std::thread` / `std::jthread` /
  `std::async`, storage in a non-`thread_local` mutable global, global-scope
  `shared_ptr` pointees, and **direct thread writers**, meaning a record
  written from two or more functions one of which is spawned as a thread. That
  last signal exists because publication requires an address to cross a thread
  boundary, and a file-scope object written directly from two thread bodies
  never does. Conservative throughout: uncertainty means escape.

  Every member-type predicate peels array extents first. A field declared
  `_Atomic uint64_t c[N]` has field type `ArrayType(element)`, so without
  peeling the atomic, sync and volatile checks all see an array and nothing
  else.

- *Sharing route*. Escape means "threads can reach this type." False sharing
  needs the stronger "two cores can reach the **same object**," which
  `EscapeVerdict::hasSharingRoute` states once so that rules stop
  re-deriving it and disagreeing:

  ```
  hasSharingRoute = hasPublication                       // address crossed a thread boundary
                  || hasThreadWriters                    // >=2 writers, one thread-borne
                  || (hasGlobalInstance && anyWriterOnThread)
  ```

  `hasGlobalInstance`, meaning a file-scope instance of the type exists, is
  tracked separately from `hasPublication`: conflating them makes every global
  look published. Type queries here use `getAsRecordDecl`, since
  `getAsCXXRecordDecl` returns null for a C struct and would disable the
  signal on C entirely.

- *Standing versus handed-over writes*, the discriminator a writer count
  cannot express. `g_stats.hits++` reaches a fixed object every thread can
  name; `io->len = n` operates on whatever the caller passed in, and a queue
  hands each request to one owner at a time. `recordWrite` classifies each
  field write by walking its base expression to the root declaration: global
  storage means a standing access, a parameter means the object arrived from
  elsewhere.

- *Pool roles*. Contention needs two **cores**, not two functions. A thread
  entry spawned inside a loop, or from more than one site, runs on several
  threads at once, so a single writer function already puts two cores on the
  line. The loop usually sits around a spawner wrapper rather than the
  `pthread_create` itself, so multiplicity is read one level out through
  spawner resolution.
- *Write-site collection* (one traversal over all TU function bodies):
  - **Global write counts** per `VarDecl`, across all write forms, plain
    assignment, `++`/`--`, member writes through the global, C11/GNU atomic
    builtins, `__sync_*`, and non-const `std::atomic` mutating methods. Feeds
    FL040 and write-once analysis.
  - **Field write evidence** per `FieldDecl`: write-site count and the set of
    writer functions. Constructor member-init lists are excluded,
    initialization is not contention. Feeds FL002's pair grading
    (`pairHasDistinctWriters`: the union of two fields' writers has two or
    more members; for an intra-array self-pair that reduces to "this array is
    written from two or more functions", which is the right question).
    Array subscripts are peeled, so a write to `arr[i]` is a write to the
    field `arr`; without that every element write of a striped counter
    resolves to nothing and the array reads as never written.
- *Lifecycle.* Instantiated fresh per TU inside `HandleTranslationUnit` and
  passed by reference into every rule. After rule execution,
  `buildEscapeSummary()` snapshots per-type signals keyed by canonical
  qualified name for cross-TU aggregation.

**AllocatorTopology**. Classifies allocator contention from `--allocator`:
glibc (arena lock), tcmalloc/jemalloc (thread-local cache), mimalloc
(pool/slab). Shapes FL020 severity.

**NUMATopology**. Infers page placement under first-touch: local-init,
main-thread, any-thread, interleaved, explicit-bind, unknown. Feeds FL060.

**CallGraph**. Per-TU caller→callee map from `CallExpr` visits. Used by
HotPathOracle for transitive hotness. The same walk detects thread-entry
arguments (`pthread_create`, `thrd_create`, `std::thread`/`std::jthread`,
`std::async`) and snapshots name-keyed edges for the thread-role reduce.

**Thread-role attribution** (`ThreadRoleSummary`), per-TU facts (entries,
name-keyed call edges, field-writer names) piggyback the CallGraph and
EscapeAnalysis traversals, merge across TUs beside the escape summary, and
reduce on the parent to per-function MAIN/WORKER masks by BFS from `main()`
and the observed entries (config globs seed roots that function-pointer
dispatch hides). Verdicts exist only post-merge. Consumers: FL002/FL090
confidence escalation when a flagged pair's writers attribute to provably
disjoint roles (any unknown or mixed-role writer defeats it), and the FL092
precedent join.

**DataFlowAnalyzer**. Intra-procedural, two passes: bind variables to heap
allocations and atomic loads, then track uses, alloc-escapes,
alloc-flows-to-loop, atomic-feeds-branch (CAS retry / spin-wait signature).
Escalation input to FL010 and FL020.

**HotPathOracle**. Classifies functions hot and records *how*, because the
strength of the signal bounds the finding's severity. Sources, strongest
first (`HotnessSource`):

| Source | Established by | Ceiling |
|---|---|---|
| `Profiled` | perf samples above `hotness_threshold_pct` | none |
| `Declared` | `__attribute__((hot))`, `[[clang::annotate("lshaz_hot")]]`, config globs, or transitive propagation from such a root | none |
| `InferredDeep` | nested loops or recursion on a path from an entry | one grade below the assigned severity |
| `InferredShallow` | one loop level from an entry | two grades below |
| `None` | nothing | rule does not fire |

`record()` keeps the strongest source, so an inference can never downgrade an
explicit signal.

**Structural inference** (`inferFromCodeShape`, enabled by `infer_hot_paths`)
exists because an unconfigured scan otherwise leaves every hot-path rule
inert: with no profile and no configured patterns, nothing in a real codebase
is hot. Repetition is what makes a cache miss steady-state, and a loop is
where repetition is written down:

```
seeds:     thread entry points (from CallGraph) and main
relax:     depth(callee) = max(depth(caller) + loopDepth(call site))
recursion: self-edge counts as one level
bound:     kMaxDepth = 4, so cycles settle rather than diverge
grade:     own loop nesting >= 2 sharpens by one level
```

No project symbol appears anywhere in the inference, so it cannot overfit to
one codebase.

> **A function's own loop nesting is not a seed.** It establishes cost per
> call, not call frequency, and the two are independent. Seeding on it marks
> every initializer hot, since setup code is full of loops, and once half a
> codebase grades hot the label means nothing.

Inference is per-TU. A function looped over from another translation unit is
invisible to it, so a library scanned without its application has thin
coverage. Reported explicitly rather than left to look like a clean result.

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

**Analysis (`IRAnalyzer`):** per function, stack allocations (name, size),
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
diagnostic's escalation trace, refinement is visible, never silent.

## Stage 3: Post-processing

The order below is load-bearing and is declared nowhere in code: it is the
call order inside `ScanPipeline::run`. A stage reading a verdict an earlier
stage sets must stay after it, and several do. When adding one, record here
what it consumes and what it produces, because this is the only place the
dependencies are written down.

1. **Canonical sort** of merged diagnostics (see Determinism).
2. **FL040 reduce**. Sums per-TU write and loop-write counts per
   `(var, type)` and grades severity on the global aggregate (write
   pressure, not site count; see [rules.md](rules.md#fl040-centralized-mutable-global-state)).
3. **Cross-TU escape suppression**. Per-TU `EscapeSummary` maps are merged;
   diagnostics whose `type_name` shows no escape evidence in any TU are
   suppressed. Runs before dedup so all duplicate instances are reclassified
   consistently. Proven-tier findings and diagnostics without `type_name` are
   never suppressed.
4. **Sharing-route verdict** (`applySharingRouteVerdict`). Demotes
   co-located fields that no route actually shares. Reads the merged escape
   summary, so it must follow the merge and precede dedup for the same reason
   escape suppression does.
5. **Thread-role attribution** (`computeThreadRoles`, then
   `applyThreadRoleEscalation`). BFS over the merged call graph from `main`
   and the thread entries; escalates findings whose writers hold provably
   disjoint roles. Needs the whole graph, so it cannot run per TU.
6. **Global hotness** (`inferGlobalHotness`). Confirms or drops the
   `Candidate` marks the map phase left. Withdrawable hot-path findings die
   here, so it must precede anything that grades on severity.
7. **Allocator vocabulary closure** (`inferAllocatorVocabulary`,
   `inferLockVocabulary`, `inferMappingVocabulary`). Runs in the prepass
   reduce, before any rule, since pass two consumes the derived names.
8. **Affinity and paging respect** (`detectAffinityManagement` /
   `applyAffinityRespect`, `detectPagingManagement` / `applyPagingRespect`).
   Each detect/apply pair must stay adjacent and in that order.
9. **Deduplication**. Headers included by many TUs produce one finding per
   TU. Keys: `(ruleID, file, line)` for struct-level rules;
   `(ruleID, var, type)` for FL040 (the same global appears at different
   header paths); `(ruleID, functionName, line)` for function rules. The
   survivor is the **highest-confidence** instance (ties: better evidence
   tier, then shortest path → lexicographic → lowest line/column → content
   order). Escalation traces from all duplicates are merged, sorted, and
   annotated with the TU count. Because FL002 encodes write evidence into
   confidence, the TU that observes the writers decides the canonical
   verdict.
10. **Interaction synthesis (FL091)**, joins diagnostics sharing an entity
   key: `file:line`, `type:` + type name, or `fn:` + function. Eligible
   pairs/triples per the `InteractionEligibilityMatrix` produce compound
   findings; severity derives from the (post-demotion) parents. One compound
   per (template, participant set). Followed by the **FL092 precedent
   join** (see [rules.md](rules.md#fl092-unapplied-in-tree-mitigation)).
   The thread-role reduce and the FL002/FL090 disjoint-writer escalation
   run earlier, between cross-TU escape suppression and dedup, so every
   duplicate instance is escalated consistently before the canonical
   survivor is chosen.
11. **Unapplied-mitigation synthesis** (FL092) and **precision budget**. Per-rule governance: max emissions per TU,
   confidence floors, severity caps.
12. **Calibration suppression**, then **PMU trace feedback**, with `--calibration-store`, findings whose
   10-dimension structural feature vector falls within Euclidean radius 0.25
   of a pattern with three or more experimentally refuted instances are
   suppressed.
   Safety rail: Critical/High findings at Proven tier are never suppressed. A
   store path that exists but cannot be parsed is a hard error (exit 3),
   scanning with silently disabled calibration would misreport.
13. **Mechanism-claim invariant gate**. Clamps any finding outranking the
    claims it established. Must remain last among the grading stages: a stage
    added after it reintroduces the violation it exists to catch.
14. **Header fingerprint (B001)**. Aggregates `FailedTU` error text; a header
   missing in three or more TUs becomes a single B001 diagnostic naming it,
   converting systematic build breakage into one actionable finding.
15. **Filter and final sort**. Suppressed findings drop; output orders by
   severity (Critical first), then file, then line, with a total-order
   content tiebreaker.

## Evidence model

Every diagnostic carries four signals (see
[output-formats.md](output-formats.md)): **severity**, the worst-case impact;
**confidence** in [0,1], the belief that the hazard is real at this site;
**evidence tier**, one of `proven` (layout-guaranteed), `likely` (strong
structural signals) or `speculative`; and **mechanism claims**.

### Mechanism claims

A rule does not assert a hazard as an opaque verdict. It decomposes its
hardware argument into claims, each naming an effect, the precondition that
effect requires, how that precondition was decided, and the severity it can
support:

```cpp
enum class ClaimState { Unknown, Established, Refuted };

struct MechanismClaim {
    std::string effect;        // what the hardware does
    std::string precondition;  // what must hold for it to happen
    ClaimState  state;
    Severity    supports;
    bool        gating;
    std::string observation;   // what settled it
};
```

**Three states, because two cannot say what the analyzer knows.** Unknown is
where a pass leaves a condition it could not see, and it stays recoverable: a
later phase, a profile or a measurement may settle it. Refuted is a verdict,
and it retires the finding. Collapsing them means an evidence source that
looked for a condition and found it absent has no way to say so except by
lowering a number until some threshold elsewhere deletes the finding, which is
deletion by coincidence rather than by reason.

Only a source that looked for absence may write Refuted. A rule's own
predicate coming out false is Unknown (`claimFrom`), because not observing a
condition is not disproving it.

`Diagnostic::severitySupportedByClaims()` combines the survivors, and the
pipeline clamps each finding's severity to the result:

```
result = min( max(established ordinary claims), min(all gating claims) )
```

**Ordinary claims are alternatives; gating claims are conjuncts.** Any one
established mechanism can carry a finding, so ordinary claims combine with
`max`. A gating claim caps instead. Hotness is the canonical one: no mechanism
costs anything in code that never runs. Folding a gating claim into the `max`
makes it a no-op.

`Diagnostic::refutedPrecondition()` decides withdrawal. A refuted gate is a
necessary condition known false; refuting every alternative leaves the finding
asserting no mechanism at all. Either withdraws it, naming the observation
that did it, and the scan reports the count so evidence disagreeing with the
analysis stays distinguishable from the analysis finding nothing.

`scan_test` gates the contract shut: every emitted finding must declare its
claims, severity may never outrank an established one, and no finding may
reach the output still carrying a refuted gate.

### Grading principles

- **Claims are downgraded to what the evidence supports.** A sub-line-aligned
  record cannot prove co-residency, so it grades `likely` rather than
  `proven`. No observed writers in the TU reports as structural evidence only,
  at capped severity.
- **Mitigation intent is respected.** Explicit line alignment or pad-to-line
  layout caps FL001/FL002/FL090 at Medium with the reason stated. Compounds
  never outrank their mitigation-adjusted components.
- **A claim being constant is not a defect.** A rule's own entry condition is
  legitimately always true and supports only the floor grade. What matters is
  that the claim is *computed* from the finding, which no static gate can
  verify for you.

## Determinism

Output is **byte-identical regardless of `--jobs` count or scheduling**. This
is a hard invariant with specific machinery behind it:

- Parallel AST analysis shards sources round-robin across **forked child
  processes** (not threads), hardware-level isolation from Clang's
  thread-unsafe globals. Children serialize diagnostics, `FailedTU`s, and
  `EscapeSummary` over a JSON IPC protocol; the parent merges after
  `waitpid()`.
- Merged diagnostics are sorted by the canonical key
  `(ruleID, file, line, column, functionName)` **before any order-dependent
  pass**. Collisions, which macro pasting produces when two TUs define
  distinct same-line symbols, fall through to `diagnosticContentLess`: a total
  order over severity, confidence, tier, function, title, evidence,
  escalations and mitigation. No comparison ends in "equal" for distinct
  content.
- Rules never cache per-TU state, and `EscapeAnalysis` is constructed per TU.
  A rule member written during `analyze` leaks across TUs in an order the
  scheduler picks, and heap-address reuse in forked children makes that
  observable. Dependency injection is the fix, not discipline.
- Cross-TU aggregation is map/reduce (FL040 write counts, escape summaries):
  children emit facts, the parent computes verdicts. No per-TU partial
  verdicts.
- Locations are resolved via `getFileLoc()` so Clang `<scratch space>`
  token-paste artifacts map back to physical files.
- The per-shard memory cap derives from **total** system memory, not
  available. Available memory fluctuates with ambient load, which would make
  output depend on what else the machine was doing: a safety valve must not
  breach the invariant it protects.

The only run-varying output field is `metadata.timestamp`.

### Shard accounting

A shard is accounted for in exactly one way: its IPC parsed, or every
translation unit it owned marked failed with a reason. Anything else converts
a lost shard into silently missing coverage that reads identically to a clean
scan.

Four paths would otherwise drop a shard while the scan exits 0: `fork()`
failure, a child whose IPC write failed, a signalled child whose partial IPC
still parses, and unparseable IPC. Each reports. Records are written one per
TU and flushed as each completes, so a shard that dies mid-way surrenders
only the translation unit it died on rather than everything it had
finished.

`LSHAZ_FAULT_KILL_SHARD=<shard>[:<n>]` kills a shard deterministically, before
any TU or after `n` of them. The realistic trigger, the OOM killer, cannot be
summoned on demand, and a silent-failure guard that cannot be made to fail is
not a guard.

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

### Cost scopes

A mechanism does not have one cost. A counter reports events; a throughput A/B
reports the latency that reached the critical path; the conversion between
them is itself part of the model and is itself estimated. So every `CostTerm`
declares a `TermRole`:

| Role | Meaning |
|---|---|
| `event_rate` | hardware events per unit of the target's work |
| `conversion` | turns events into cycles that are actually exposed |
| `correction` | a residual learned from a previous measurement |

`CostEstimate::cyclesPerOp` is the product of everything, so it is exposed
latency. `eventsPerOp()` drops the conversions, which is what a counter can be
compared against, and drops corrections so last round's answer is not applied
to the measurement producing the next one.

The role is declared where the term is built and read where the comparison
happens. Those are different files, so keying on the term's *name* instead
means a rename silently changes which quantity the machine is being asked
about, with nothing to catch it.

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
  power (two-sample z at the achieved sample sizes), and writes a verdict into
  the versioned calibration store by atomic temp and rename. Quality gates:
  labels below 0.60 quality demote to unlabeled, refutations require power at
  or above 0.80, and missing confound controls carry environment penalties
  (turbo −0.15, governor −0.10, pinning −0.20). A bundle without structural
  features is refused.

Refuted patterns suppress structurally similar findings on subsequent scans,
at the calibration-suppression stage above. PMU trace feedback
(`--pmu-trace`, `--pmu-priors`) is a parallel ingestion path from production
`perf stat` data with Bayesian per-class priors.
