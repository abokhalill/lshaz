# Configuration Reference

This document is the authoritative reference for the config file, every CLI
subcommand and its flags, hot-path annotation, and inline suppression.

## Config file

lshaz autodiscovers `lshaz.config.yaml` in the project root. Override with
`--config <path>`. All keys are optional; values below are the defaults unless
annotated.

```yaml
# Cache model (x86-64 baseline)
cache_line_bytes: 64
cache_line_span_warn: 64      # FL001 warning threshold (bytes)
cache_line_span_crit: 128     # FL001 critical threshold (bytes)

# Stack frame
stack_frame_warn_bytes: 2048  # FL021 threshold

# Allocation
alloc_size_escalation: 256    # FL020 escalation threshold (bytes)

# Branch depth
branch_depth_warn: 4          # FL050 nesting threshold

# TLB
page_size: 4096

# Output
json_output: false
output_file: ""

# Hot-path classification (fnmatch patterns; see Hot Path Annotation)
hot_function_patterns: []     # e.g. ["*::onMarketData*", "hnsw_*"]
hot_file_patterns: []         # e.g. ["*/hot_path/*"]

# Perf-profile hotness (used with --perf-profile)
perf_profile_path: ""
hotness_threshold_pct: 1.0    # sample % above which a function is hot

# Target model
target_arch: "x86-64"         # x86-64 | arm64 | arm64-apple
linked_allocator: ""          # tcmalloc | jemalloc | mimalloc

# Rule control
disabled_rules: []

# Opaque atomic wrapper type names.
# Struct/typedef names treated as atomic even without _Atomic or std::atomic.
# Required for codebases that wrap atomics in plain structs; without this,
# those fields are invisible to atomic detection (FL002/FL010/FL011/FL090).
atomic_type_names:
  - atomic_t          # Linux kernel
  - atomic64_t
  - atomic_long_t
  - refcount_t
  - raw_spinlock_t
  - spinlock_t
  - seqcount_t
  - seqcount_spinlock_t
```

> `hotness_threshold_pct` and `perf_profile_path` are config-file keys, not
> CLI flags. The CLI accepts `--perf-profile <path>` as a per-run override.

---

## `lshaz scan`

```
lshaz scan <path> [options]
lshaz scan <file.cpp> [options] -- <compiler-flags>     # single-file mode
lshaz scan <git-url> [options]                          # remote repository
```

`<path>` is a project root or an explicit `compile_commands.json`. In
single-file mode, arguments after `--` go to Clang verbatim. Remote URLs are
cloned to a temp directory; build-system execution on clones requires
`--trust-build-system`.

| Short | Long | Description |
|---|---|---|
| `-C` | `--compile-db <path>` | Explicit path to `compile_commands.json` |
| `-c` | `--config <path>` | Path to `lshaz.config.yaml` |
| `-f` | `--format <cli\|json\|sarif\|tidy>` | Output format (default: `cli`) |
| `-o` | `--output <path>` | Write output to file instead of stdout |
| `-s` | `--min-severity <level>` | `Informational`, `Medium`, `High`, `Critical` |
| `-e` | `--min-evidence <tier>` | `speculative`, `likely`, `proven` |
| `-I` | `--include <pattern>` | Only analyze files matching pattern (repeatable) |
| `-X` | `--exclude <pattern>` | Skip files matching pattern (repeatable) |
| `-n` | `--max-files <N>` | Maximum translation units to analyze |
| `-j` | `--jobs <N>` | Parallel AST worker **processes** (default: nproc). Output is byte-identical for any value. |
| `-r` | `--rule <ID>` | Run only the specified rule (repeatable) |
| `-a` | `--target-arch <arch>` | `x86-64` (default), `arm64`, `arm64-apple` |
| `-w` | `--watch` | Re-scan on file changes (`--watch-interval <N>`, default 2s) |
| | `--no-ir` | Disable the LLVM IR refinement pass |
| | `--ir-opt <O0\|O1\|O2>` | IR optimization level (default: `O0`) |
| | `--ir-jobs <N>` | Max parallel IR emission jobs (default: nproc) |
| | `--ir-batch-size <N>` | TUs per IR shard (default: 1) |
| | `--no-ir-cache` | Disable the content-addressed IR cache (recommended in CI) |
| | `--perf-profile <path>` | Perf profile for hot-path selection |
| | `--allocator <name>` | `tcmalloc`, `jemalloc`, `mimalloc` — shapes FL020 |
| | `--calibration-store <path>` | Calibration feedback store (JSON). Absent file = empty store; unparseable file = exit 3. |
| | `--pmu-trace <file>` | Production PMU trace ingestion |
| | `--pmu-priors <file>` | Persist/load Bayesian hazard priors |
| | `--trust-build-system` | Allow cmake/meson/bear execution on cloned repos |
| | `--changed-files <path>` | Incremental mode: only scan TUs affected by the listed files (one per line). Header changes trigger a conservative full scan. |
| `-h` | `--help` | Show help |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean — no diagnostics |
| 1 | Findings emitted |
| 2 | Parse errors — one or more TUs failed to compile (and no findings) |
| 3 | Fatal — infrastructure failure: bad arguments, missing files, unreadable calibration store |

When some TUs fail and findings are still emitted, the exit code is 1.

---

## Hot path annotation

> Rules FL010, FL011, FL012, FL020, FL030, FL031, FL050, and FL061 fire only
> on functions classified hot. Without a hotness signal they emit nothing.
> Structural rules (FL001, FL002, FL021, FL040, FL041, FL060, FL090) do not
> require one.

Four signals, any of which marks a function hot:

**1. Source annotation:**

```cpp
__attribute__((hot))                     // GCC/Clang attribute (recommended)
void onMarketData(const Update& u);

[[clang::annotate("lshaz_hot")]]         // lshaz-specific annotation
void processOrder(const Order& o);
```

**2. Config patterns** (fnmatch, matched against qualified names / file
paths):

```yaml
hot_function_patterns: ["*::onMarketData*", "hnsw_*"]
hot_file_patterns: ["*/hot_path/*"]
```

**3. Perf profile:** with `--perf-profile <path>`, functions above
`hotness_threshold_pct` percent of total samples are hot.

**4. Transitive propagation:** callees of hot functions are hot, propagated
through the per-TU call graph.

---

## Inline suppression

```cpp
// lshaz-suppress FL001,FL002
struct LegacyLayout { ... };     // FL001 and FL002 suppressed here

struct Another { ... };  // lshaz-suppress    (all rules suppressed)
```

The comment must be on the diagnostic's line or the line immediately above.
Comma-separated rule IDs, or bare `lshaz-suppress` for all rules.

---

## `lshaz init`

```
lshaz init [path] [options]
```

Detects the build system (CMake, Meson, Make via `bear`), generates
`compile_commands.json`, and writes a starter `lshaz.config.yaml`.

For CMake/Meson projects only the **configure** step runs by default — no
project dependencies need to be installed, and the compilation database is
used even if configure exits non-zero. Use `--build` when the project
generates headers (`configure_file()`, `custom_target()`) that TUs include.
Make projects require a real build under `bear`, so dependencies must be
installed.

After generating or discovering the database, init probes a random sample of
TUs with `clang -fsyntax-only` and reports missing headers with the specific
error message.

| Short | Long | Description |
|---|---|---|
| | `[path]` | Project root (default: current directory) |
| `-b` | `--build` | Run a full build after configure (for generated headers) |
| `-f` | `--force` | Regenerate `compile_commands.json` even if present |
| | `--no-config` | Skip `lshaz.config.yaml` generation |

---

## `lshaz diff`

```
lshaz diff <before.json> <after.json>
```

Compares two JSON scan results: metadata deltas (TU counts, failures), per-rule
and per-severity distribution shifts, and new / resolved / unchanged findings.
Diff key: `(ruleID, file, line)`. Remote-scan temp paths are normalized
automatically.

Exit 0 when no new findings; exit 1 on regressions — usable directly as a CI
gate:

```bash
lshaz scan . -f json -o before.json
# ... apply changes ...
lshaz scan . -f json -o after.json
lshaz diff before.json after.json
```

---

## `lshaz fix`

```
lshaz fix <path> [options]
lshaz fix <file.cpp> [options] -- <compiler-flags>
```

Mechanical auto-remediation for fixable diagnostics. Currently: FL001
(`alignas(64)` on cache-line-spanning structs).

| Short | Long | Description |
|---|---|---|
| `-C` | `--compile-db <path>` | Path to `compile_commands.json` |
| `-c` | `--config <path>` | Path to `lshaz.config.yaml` |
| `-n` | `--dry-run` | Show patches without modifying files |
| `-r` | `--rules <list>` | Comma-separated rules to fix (default: `FL001`) |

---

## `lshaz hyp`

```
lshaz hyp <scan-result.json> [options]
```

Constructs formal latency hypotheses from scan diagnostics. Input is scan JSON
(`lshaz scan -f json`); hypothesis JSON is an output artifact and is rejected
as input.

| Flag | Description |
|---|---|
| `-o, --output <file>` | Write hypothesis JSON (default: stdout) |
| `--rule <id>` | Only hypothesize for one rule |
| `--min-conf <f>` | Minimum confidence threshold (default: 0.0) |

---

## `lshaz exp`

```
lshaz exp <scan-result.json> [options]
```

Synthesizes runnable experiment bundles (treatment/control kernels,
measurement harness, analysis tool, PMU scripts). Input is scan JSON, same as
`hyp`; passing hypothesis JSON fails with an actionable error. Bundle contents
and statistical design: [hypothesis-engine.md](hypothesis-engine.md).

| Flag | Description |
|---|---|
| `-o, --output <dir>` | Output directory (default: `./experiments`) |
| `--rule <id>` | Only generate for one rule |
| `--min-conf <f>` | Minimum confidence threshold (default: 0.5) |
| `--sku <name>` | CPU SKU family (default: `generic`) |
| `--dry-run` | Show what would be generated without writing |

---

## `lshaz feedback`

```
lshaz feedback <experiment-dir> [options]
```

Ingests one experiment's results into the calibration store: reads
`hypothesis.json`, `results/{treatment,control}_samples.bin`, and
`results/env.json`; computes the verdict and achieved power; persists the
store atomically (temp file + rename). Bundles without structural features
(pre-feature experiment output) are refused. Quality gates are described in
[hypothesis-engine.md](hypothesis-engine.md#feedback-and-quality-gates).

| Flag | Description |
|---|---|
| `--store <path>` | Calibration store path (required) |
| `--alpha <f>` | Significance level (default: 0.01) |
| `--json` | Emit the verdict as JSON |

Full loop:

```bash
lshaz scan . -f json -o scan.json
lshaz exp scan.json -o experiments
cd experiments/H-FL002-*/ && make && scripts/run_all.sh && cd ../..
lshaz feedback experiments/H-FL002-*/ --store calibration.json
lshaz scan . --calibration-store calibration.json
```

---

## `lshaz explain`

```
lshaz explain FL002        # hardware mechanism + mitigation for one rule
lshaz explain --list       # all rules with base severities
```

## `lshaz version`

Prints the tool version (`version`, `--version`, or `-v`).
