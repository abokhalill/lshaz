# Developer Guide

## Requirements

| Dependency | Version |
|---|---|
| Linux x86-64 | required |
| LLVM + Clang development libraries | >=16; 18 preferred (CI builds against 18) |
| CMake | >=3.20 |
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
| `build/analysis_test` | Layout / cache-line / escape ground truth (needs full Clang link) |
| `build/output_test` | JSON / SARIF / CLI output contracts |
| `build/pipeline_test` | Pipeline, IPC, escape summary, cross-TU suppression |
| `build/scan_test` | End-to-end scan behavior, registry coverage gate |

## Testing

Four hand-rolled harnesses. Each owns its `main()`, takes no arguments, and
runs its full suite; narrow a run by editing that `main()`.

```bash
./build/analysis_test
./build/output_test
./build/pipeline_test
./build/scan_test
```

**All four must pass before committing.** CI (`.github/workflows/ci.yml`)
builds a gcc-13/14 by clang-17/18 matrix against LLVM 18 with Ninja and
ccache, then runs all four.

Do not add a test framework. The absence of one is a decision: these
harnesses link against Clang, and a dependency that also links against it is
a version constraint the project does not want.

When changing analysis semantics, validate against a real corpus as well: a
full scan of a pinned OSS tree before and after the change, with every count
or severity delta attributed to the change that caused it. Determinism is part
of the bar. `md5sum` over timestamp-stripped JSON from `--jobs 1` and
`--jobs N` must match.

## Codebase layout

```
src/
  main.cpp                     # flat strcmp subcommand dispatch
  cli/                         # one file per subcommand
    scan.cpp            #   scan (incl. single-file mode)
    init.cpp            #   init. Build-system detection, compile_commands.json
    diff.cpp            #   diff, scan comparison / CI gate
    fix.cpp             #   fix, mechanical remediation
    explain.cpp         #   explain, rule mechanisms
    hyp.cpp             #   hyp, hypothesis construction
    exp.cpp             #   exp, experiment synthesis
    feedback.cpp        #   feedback, verdict ingestion, statistics
    observe.cpp         #   observe, hardware profile ingestion
    result_parser.cpp       #   scan-JSON parser shared by hyp/exp
  analysis/
    ast_consumer.cpp       # TU walk, rule dispatch, inline suppression
    action.cpp            # FrontendAction + factory
    cache_line.cpp           # field-to-line mapping, pair co-residency, straddle semantics
    escape.cpp         # escape signals, global/field write collection
    struct_layout.cpp    # recursive layout walker
    allocator.cpp      # allocator contention classes
    numa.cpp           # first-touch placement inference
    call_graph.cpp              # per-TU call graph
    data_flow.cpp       # intra-procedural taint (heap, atomic-feeds-branch)
  rules/                       # one file per FL0xx rule, stateless singletons
  pipeline/
    scan_pipeline.cpp           # orchestration: fork shards, IPC, merge, post-processing
    compile_db.cpp      # compile_commands.json discovery
    abs_path_db.cpp
    repo.cpp           # remote URL cloning
    filter.cpp           # include/exclude globs
  core/
    dedup.cpp        # cross-TU dedup, survivor selection
    interaction.cpp  # FL091 entity-keyed synthesis
    diagnostic.cpp             # diagnosticContentLess total order
    hot_path.cpp          # hotness classification
    registry.cpp           # LSHAZ_REGISTER_RULE machinery
    config.cpp                 # YAML config
  ir/
    ir_analyzer.cpp             # LLVM IR facts per function
    refiner.cpp      # confidence deltas from IR evidence
  hypothesis/
    hypothesis.cpp  # diagnostic to LatencyHypothesis
    template.cpp     # per-hazard-class templates
    experiment.cpp  # kernel + bundle generation
    measurement.cpp        # PMU grouping, env setup scripts
    calibration.cpp    # versioned store, label quality
    pmu_trace.cpp       # production PMU ingestion
    interaction.cpp       # FL091 eligibility matrix
  output/                      # JSON / SARIF / CLI / clang-tidy formatters

include/lshaz/                 # public headers mirroring src/ structure
test/fixtures/                 # scan fixtures for the e2e suite
tools/
  lshaz-tidy                   # clang-tidy-format wrapper for CI
  precision_sample.py          # blind, seeded precision adjudication worksheets
  wattr/                       # runtime write-attribution, joins a trace to a scan
docs/                          # this documentation
```

## Adding a rule

1. Create `src/rules/flXXX.cpp` implementing the `Rule` interface:

   ```cpp
   class FLXXX_YourRule : public Rule {
   public:
       std::string_view getID() const override { return "FLXXX"; }
       std::string_view getTitle() const override { return "Your Rule Title"; }
       Severity getBaseSeverity() const override { return Severity::High; }
       std::string_view getHardwareMechanism() const override { return "..."; }
       void analyze(const clang::Decl *D, clang::ASTContext &Ctx,
                    const HotPathOracle &Oracle, const Config &Cfg,
                    const EscapeAnalysis &Escape,
                    std::vector<Diagnostic> &out) override;
   };
   ```

   Two optional virtuals decide when the rule fires, and they are not the
   same question. `requiresHotPath()` bounds severity by how well hotness was
   evidenced. `withdrawnWhenNotHot()` says the finding only exists because
   hotness was believed, so the reduce phase may delete it once the merged
   call graph disagrees. Setting the second on a rule that reports regardless
   deletes its findings for the wrong reason.

2. Register with `LSHAZ_REGISTER_RULE(FLXXX_YourRule)` at the bottom of the
   file.
3. Add the `.cpp` to `LSHAZ_SOURCES` in `CMakeLists.txt` (the list is
   explicit, not globbed).
4. Add fixtures under `test/fixtures/` and extend `scan_test`.
5. Give the rule a known-positive case in `test/fixtures/hft_core` or
   `test/fixtures/canary`. `scan_test` enumerates the registry through
   `explain --list` and fails any registered rule that fires on neither. A
   rule that stops firing produces output identical to a clean scan, so that
   gate is the only thing between a refactor and silent recall loss.

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
