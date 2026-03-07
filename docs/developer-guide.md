# Developer Guide

## Requirements

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

### Build Outputs

| Binary | Purpose |
|---|---|
| `build/lshaz` | The analyzer |
| `build/output_contract_test` | Output schema contract tests |
| `build/pipeline_unit_test` | Pipeline unit tests |
| `build/scan_e2e_test` | End-to-end scan tests |

## Testing

170 tests across three suites:

```bash
./build/output_contract_test   # 55 tests — JSON, SARIF, CLI output contracts
./build/pipeline_unit_test     # 44 tests — pipeline correctness
./build/scan_e2e_test          # 71 tests — end-to-end scan behavior
```

All tests must pass before committing.

## Validation Harness

The `validation/` directory contains a ground-truth validation harness:

### Tier 1: Corpus Regression

```bash
./validation/run.sh --tier1
```

Runs lshaz against internal test samples and external open-source C++ codebases. Asserts:
- No crashes
- Deterministic output across runs
- Valid source locations
- Diagnostic distribution sanity
- Evidence parseability

### Tier 2: Ground Truth Microbenchmarks

```bash
./validation/run.sh --tier2
```

Paired hazardous/fixed microbenchmarks per rule with hardware timing and optional `perf stat` counters. Statistical analysis via paired t-test when scipy is available.

## Architecture

The codebase is organized as:

```
src/
  main.cpp                     # Entry point, subcommand dispatch
  cli/
    ScanCommand.cpp            # lshaz scan implementation
    ExplainCommand.cpp         # lshaz explain implementation
  analysis/
    LshazASTConsumer.cpp       # AST traversal, rule dispatch, suppression
    LshazAction.cpp            # Clang FrontendAction + factory
    CacheLineMap.cpp           # Cache line mapping for struct fields
    EscapeAnalysis.cpp         # Thread-escape heuristics
    StructLayoutVisitor.cpp    # Recursive struct layout walker
    AllocatorTopology.cpp      # Allocator classification
    NUMATopology.cpp           # NUMA placement inference
  rules/
    FL001_CacheLineSpanning.cpp
    FL002_FalseSharing.cpp
    ...                        # One file per rule
  pipeline/
    ScanPipeline.cpp           # Orchestration: AST + IR + post-processing
    CompileDBResolver.cpp      # compile_commands.json discovery/generation
    RepoProvider.cpp           # Git clone for remote URLs
    SourceFilter.cpp           # Glob-based source filtering
  ir/
    IRAnalyzer.cpp             # LLVM IR analysis
    DiagnosticRefiner.cpp      # Confidence adjustment from IR evidence
  hypothesis/
    HypothesisConstructor.cpp  # Hypothesis formalization
    ExperimentSynthesizer.cpp  # Experiment bundle generation
    MeasurementPlan.cpp        # PMU counter grouping
    CalibrationFeedback.cpp    # Feedback store
    PMUTraceFeedback.cpp       # Closed-loop PMU learning
    InteractionModel.cpp       # FL091 interaction synthesis
  output/
    JSONOutput.cpp             # JSON formatter
    SARIFOutput.cpp            # SARIF 2.1.0 formatter
    CLIOutput.cpp              # Terminal formatter

include/lshaz/
  core/                        # Diagnostic, Rule, Config, Severity, Version
  analysis/                    # CacheLineMap, EscapeAnalysis, LayoutSafety, etc.
  pipeline/                    # ScanPipeline, ScanRequest, ScanResult
  output/                      # OutputFormatter interface
  ir/                          # IRAnalyzer, DiagnosticRefiner
  hypothesis/                  # Hypothesis engine interfaces

test/fixtures/hft_core/        # Test fixture files
```

## Adding a New Rule

1. Create `src/rules/FLXXX_YourRule.cpp`
2. Implement the `Rule` interface:
   ```cpp
   class FLXXX_YourRule : public Rule {
   public:
       std::string_view getID() const override { return "FLXXX"; }
       std::string_view getTitle() const override { return "Your Rule Title"; }
       Severity getBaseSeverity() const override { return Severity::High; }
       std::string_view getHardwareMechanism() const override { return "..."; }
       void analyze(const clang::Decl *D, clang::ASTContext &Ctx,
                    const HotPathOracle &Oracle, const Config &Cfg,
                    std::vector<Diagnostic> &out) override;
   };
   ```
3. Register with `LSHAZ_REGISTER_RULE(FLXXX_YourRule)` at the bottom of the file
4. Add the `.cpp` to `CMakeLists.txt` `LSHAZ_SOURCES`
5. Add test fixtures and update `scan_e2e_test`

Rules must map to a concrete hardware mechanism. If it cannot be tied to cache, coherence, store buffer, TLB, branch predictor, NUMA, or allocator — it does not belong.

## Commit Discipline

- Each commit must be logically atomic and traceable to a specific change
- All 170 tests must pass before pushing
- No batching of unrelated changes
- Prefer minimal upstream fixes over downstream workarounds
