# Developer Guide

## Requirements

| Dependency | Version |
|---|---|
| Linux x86-64 | required |
| LLVM + Clang development libraries | ≥16; 18 preferred (CI builds against 18) |
| CMake | ≥3.20 |
| C++20 compiler | GCC 13/14 or Clang 17/18 (the CI matrix) |

```bash
# Ubuntu / Debian
apt install llvm-18-dev libclang-18-dev clang-18 cmake

# Arch
pacman -S llvm clang cmake
```

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

If CMake cannot find LLVM:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/usr/lib/llvm-18
```

### Build outputs

| Binary | Purpose |
|---|---|
| `build/lshaz` | The analyzer |
| `build/analysis_ground_truth_test` | Layout / cache-line / escape ground truth (needs full Clang link) |
| `build/output_contract_test` | JSON / SARIF / CLI output contracts |
| `build/pipeline_unit_test` | Pipeline, IPC, escape summary, cross-TU suppression |
| `build/scan_e2e_test` | End-to-end scan behavior |

## Testing

Four hand-rolled harnesses (own `main()`, no framework, no arguments — each
runs its full suite; narrow a run by editing the harness's `main()`):

```bash
./build/analysis_ground_truth_test   # 88 tests
./build/output_contract_test         # 55 tests
./build/pipeline_unit_test           # 73 tests
./build/scan_e2e_test                # 71 tests
```

**All four must pass before committing.** CI
(`.github/workflows/ci.yml`) builds a gcc-13/14 × clang-17/18 matrix against
LLVM 18 with Ninja + ccache and runs the three suites that do not need a full
Clang link.

When changing analysis semantics, validate against a real corpus as well: a
full scan of a pinned OSS tree before and after the change, with every count
or severity delta attributed to the change that caused it. Determinism is part
of the bar — `md5sum` over timestamp-stripped JSON from `--jobs 1` and
`--jobs N` must match.

## Codebase layout

```
src/
  main.cpp                     # flat strcmp subcommand dispatch
  cli/                         # one file per subcommand
    ScanCommand.cpp            #   scan (incl. single-file mode)
    InitCommand.cpp            #   init — build-system detection, compile_commands.json
    DiffCommand.cpp            #   diff — scan comparison / CI gate
    FixCommand.cpp             #   fix — mechanical remediation
    ExplainCommand.cpp         #   explain — rule mechanisms
    HypCommand.cpp             #   hyp — hypothesis construction
    ExpCommand.cpp             #   exp — experiment synthesis
    FeedbackCommand.cpp        #   feedback — verdict ingestion, statistics
    ScanResultParser.cpp       #   scan-JSON parser shared by hyp/exp
  analysis/
    LshazASTConsumer.cpp       # TU walk, rule dispatch, inline suppression
    LshazAction.cpp            # FrontendAction + factory
    CacheLineMap.cpp           # field→line mapping, pair co-residency, straddle semantics
    EscapeAnalysis.cpp         # escape signals, global/field write collection
    StructLayoutVisitor.cpp    # recursive layout walker
    AllocatorTopology.cpp      # allocator contention classes
    NUMATopology.cpp           # first-touch placement inference
    CallGraph.cpp              # per-TU call graph
    DataFlowAnalyzer.cpp       # intra-procedural taint (heap, atomic-feeds-branch)
  rules/                       # one file per FL0xx rule, stateless singletons
  pipeline/
    ScanPipeline.cpp           # orchestration: fork shards, IPC, merge, post-processing
    CompileDBResolver.cpp      # compile_commands.json discovery
    AbsolutePathCompilationDatabase.cpp
    RepoProvider.cpp           # remote URL cloning
    SourceFilter.cpp           # include/exclude globs
  core/
    DiagnosticDedup.cpp        # cross-TU dedup, survivor selection
    DiagnosticInteraction.cpp  # FL091 entity-keyed synthesis
    Diagnostic.cpp             # diagnosticContentLess total order
    HotPathOracle.cpp          # hotness classification
    RuleRegistry.cpp           # LSHAZ_REGISTER_RULE machinery
    Config.cpp                 # YAML config
  ir/
    IRAnalyzer.cpp             # LLVM IR facts per function
    DiagnosticRefiner.cpp      # confidence deltas from IR evidence
  hypothesis/
    HypothesisConstructor.cpp  # diagnostic → LatencyHypothesis
    HypothesisTemplate.cpp     # per-hazard-class templates
    ExperimentSynthesizer.cpp  # kernel + bundle generation
    MeasurementPlan.cpp        # PMU grouping, env setup scripts
    CalibrationFeedback.cpp    # versioned store, label quality
    PMUTraceFeedback.cpp       # production PMU ingestion
    InteractionModel.cpp       # FL091 eligibility matrix
  output/                      # JSON / SARIF / CLI / clang-tidy formatters

include/lshaz/                 # public headers mirroring src/ structure
test/fixtures/                 # scan fixtures for the e2e suite
docs/                          # this documentation
```

## Adding a rule

1. Create `src/rules/FLXXX_YourRule.cpp` implementing the `Rule` interface:

   ```cpp
   class FLXXX_YourRule : public Rule {
   public:
       std::string_view getID() const override { return "FLXXX"; }
       std::string_view getTitle() const override { return "Your Rule Title"; }
       Severity getBaseSeverity() const override { return Severity::High; }
       std::string_view getHardwareMechanism() const override { return "..."; }
       void analyze(const clang::Decl *D, clang::ASTContext &Ctx,
                    const HotPathOracle &Oracle, const Config &Cfg,
                    EscapeAnalysis &Escape,
                    std::vector<Diagnostic> &out) override;
   };
   ```

2. Register with `LSHAZ_REGISTER_RULE(FLXXX_YourRule)` at the bottom of the
   file.
3. Add the `.cpp` to `LSHAZ_SOURCES` in `CMakeLists.txt` (the list is
   explicit, not globbed).
4. Add fixtures under `test/fixtures/` and extend `scan_e2e_test`.

Constraints that are not optional:

- **Mechanism or it does not ship.** The rule must map to cache, coherence,
  store buffer, TLB, branch predictor, NUMA, or allocator.
- **Stateless rules.** All per-TU state comes from the injected analyses.
  Caching analysis state on the rule object has caused real non-determinism
  under forked parallelism.
- **Cross-TU logic is map/reduce.** Emit per-TU facts; let the pipeline
  compute the global verdict (see FL040). Never emit a per-TU partial
  verdict.
- **Determinism is part of review.** Byte-identical output across `--jobs`
  values, verified on a real corpus, not just the suites.
