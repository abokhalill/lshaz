# Configuration Reference

## Config File

lshaz autodiscovers `lshaz.config.yaml` in the project root. Override with `--config <path>`.

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

# Opaque atomic wrapper type names.
# Struct/typedef names treated as atomic even without _Atomic or volatile.
# Required for codebases that wrap atomics in plain structs (Linux kernel,
# FreeBSD, PostgreSQL).
atomic_type_names:
  - atomic_t
  - atomic64_t
  - atomic_long_t
  - refcount_t
  - raw_spinlock_t
  - spinlock_t
  - seqcount_t
  - seqcount_spinlock_t
```

---

## Scan CLI Options

```
lshaz scan <path> [options]
```

| Short | Long | Description |
|---|---|---|
| `-C` | `--compile-db <path>` | Explicit path to `compile_commands.json` |
| `-c` | `--config <path>` | Path to `lshaz.config.yaml` |
| `-f` | `--format <cli\|json\|sarif\|tidy>` | Output format (default: `cli`). `tidy` emits clang-tidy-compatible diagnostics. |
| `-o` | `--output <path>` | Write output to file instead of stdout |
| `-s` | `--min-severity <level>` | Minimum severity: `Informational`, `Medium`, `High`, `Critical` |
| `-e` | `--min-evidence <tier>` | Minimum evidence tier: `speculative`, `likely`, `proven` |
| `-I` | `--include <pattern>` | Only analyze files matching pattern (repeatable) |
| `-X` | `--exclude <pattern>` | Skip files matching pattern (repeatable) |
| `-n` | `--max-files <N>` | Maximum translation units to analyze |
| `-j` | `--jobs <N>` | Parallel AST analysis worker processes (default: nproc). Uses fork-based isolation, not threads. |
| `-r` | `--rule <ID>` | Run only the specified rule (repeatable). Disables all other rules. |
| `-a` | `--target-arch <arch>` | Target architecture: `x86-64` (default), `arm64`, `arm64-apple` |
| `-w` | `--watch` | Watch mode: re-scan on file changes |
| | `--no-ir` | Disable LLVM IR analysis pass |
| | `--ir-opt <O0\|O1\|O2>` | IR optimization level (default: O0) |
| | `--ir-jobs <N>` | Max parallel IR emission jobs (default: nproc) |
| | `--ir-batch-size <N>` | TUs per IR shard (default: 1) |
| | `--no-ir-cache` | Disable incremental IR cache. Recommended for CI. |
| | `--perf-profile <path>` | Perf profile data for hot-path selection |
| | `--hotness-threshold <pct>` | Sample percentage threshold for profile hotness (default: 1.0) |
| | `--allocator <name>` | Linked allocator: `tcmalloc`, `jemalloc`, `mimalloc` (affects FL020) |
| | `--calibration-store <path>` | Path to calibration feedback store |
| | `--pmu-trace <file>` | Production PMU trace data for closed-loop learning |
| | `--pmu-priors <file>` | Persist/load Bayesian hazard priors across runs |
| | `--watch-interval <N>` | Seconds between watch polls (default: 2) |
| | `--trust-build-system` | Allow cmake/meson/bear execution on cloned remote repos |
| | `--changed-files <path>` | Incremental mode: only scan TUs affected by files listed in `<path>` (one per line). Header changes trigger full scan conservatively. |
| `-h` | `--help` | Show help with exit code reference |

---

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Clean — no diagnostics |
| 1 | Findings — diagnostics emitted |
| 2 | Parse errors — one or more TUs failed to compile |
| 3 | Fatal — infrastructure failure (bad arguments, missing files) |

When some TUs fail to parse but others succeed, exit code is 1 if findings are emitted, 2 if only parse errors occurred.

---

## Hot Path Annotation

> **Important:** Rules FL010, FL011, FL012, FL020, FL030, FL031, FL050, and FL061 only fire on functions classified as hot. Without any hot-path signal, these rules produce no diagnostics. Structural rules (FL001, FL002, FL021, FL040, FL041, FL060, FL090) do not require hot-path classification.

Functions can be marked hot in four ways:

**1. Source annotation:**

```cpp
// GCC/Clang standard attribute (recommended)
__attribute__((hot))
void onMarketData(const Update& u);

// lshaz-specific annotation
[[clang::annotate("lshaz_hot")]]
void processOrder(const Order& o);
```

**2. Config patterns:**

```yaml
hot_function_patterns:
  - "*::onMarketData*"
  - "*::process*"
hot_file_patterns:
  - "*/hot_path/*"
```

**3. Perf profile:** Functions exceeding `--hotness-threshold` percent of total samples are classified as hot.

**4. Transitive propagation:** If a hot function calls `f`, then `f` is also marked hot via the per-TU CallGraph. This propagates transitively.

---

## Inline Suppression

Suppress diagnostics at specific code sites:

```cpp
// lshaz-suppress FL001,FL002
struct LegacyLayout {
    // FL001 and FL002 suppressed for this struct
};

struct AnotherLayout {  // lshaz-suppress
    // All rules suppressed for this struct
};
```

The comment must appear on the diagnostic's line or the line immediately above it. Accepts comma-separated rule IDs, or bare `lshaz-suppress` to suppress all rules.

---

## Init CLI Options

```
lshaz init [path] [options]
```

Detects the build system (CMake, Meson, Make/Bear), generates `compile_commands.json`, and writes a starter `lshaz.config.yaml`.

For CMake and Meson projects, only the **configure step** runs by default — no project dependencies need to be installed. CMake often writes `compile_commands.json` even when `find_package` fails late, and lshaz will use it regardless of configure exit code. Use `--build` when the project uses `configure_file()` or `custom_target()` to generate headers that TUs depend on.

For Make projects, `bear` intercepts a real build, so dependencies must be installed.

After generating or discovering `compile_commands.json`, init probes a random sample of TUs with `clang -fsyntax-only` to detect missing headers early. Failures are reported with the specific error message.

| Short | Long | Description |
|---|---|---|
| | `[path]` | Project root (default: current directory) |
| `-b` | `--build` | Run a full build after configure (for generated headers) |
| `-f` | `--force` | Regenerate `compile_commands.json` even if it exists |
| | `--no-config` | Skip `lshaz.config.yaml` generation |
| `-h` | `--help` | Show help |

---

## Diff CLI Options

```
lshaz diff <before.json> <after.json>
```

Compares two JSON scan results and reports:

- **Metadata delta** — TU counts, failed TU counts, regression warnings
- **Rule distribution shifts** — per-rule count changes
- **Severity distribution shifts** — per-severity count changes
- **New findings** — present in after but not before
- **Resolved findings** — present in before but not after
- **Unchanged findings** — present in both

Exit code 0 if no new findings, 1 if regressions introduced.

Diff key: `(ruleID, file, line)`.

**CI usage:**

```bash
lshaz scan . -f json -o before.json
# ... apply changes ...
lshaz scan . -f json -o after.json
lshaz diff before.json after.json
```

---

## Fix Subcommand

```
lshaz fix <path> [options]
lshaz fix <file.cpp> [options] -- <compiler-flags>
```

Applies mechanical auto-remediation for fixable diagnostics. Currently supports:

| Rule | Fix |
|---|---|
| FL001 | Adds `alignas(64)` to cache-line-spanning structs |

| Short | Long | Description |
|---|---|---|
| `-C` | `--compile-db <path>` | Path to `compile_commands.json` |
| `-c` | `--config <path>` | Path to `lshaz.config.yaml` |
| `-n` | `--dry-run` | Show patches without modifying files |
| `-r` | `--rules <list>` | Comma-separated rules to fix (default: `FL001`) |
| `-h` | `--help` | Show help |

**Example:**

```bash
# Preview fixes
lshaz fix . -n

# Apply fixes to a single file
lshaz fix src/engine.cpp -- -std=c++20
```

---

## Hyp CLI Options

```
lshaz hyp <scan-result.json> [options]
```

Constructs formal latency hypotheses from scan diagnostics. Input must be a scan result JSON file (the output of `lshaz scan --format json`). Hypothesis JSON (the output of this command) is **not** accepted as input.

| Flag | Description |
|---|---|
| `-o, --output <file>` | Write hypothesis JSON to file (default: stdout) |
| `--rule <id>` | Only hypothesize for a specific rule ID |
| `--min-conf <f>` | Minimum confidence threshold (default: 0.0) |
| `--help` | Show help |

**Example:**

```bash
lshaz hyp scan.json --output hypotheses.json
lshaz hyp scan.json --rule FL002 --min-conf 0.7 -o out.json
```

---

## Exp CLI Options

```
lshaz exp <scan-result.json> [options]
```

Synthesizes runnable experiment bundles from scan diagnostics. Input must be a scan result JSON file — **not** hypothesis JSON. If hypothesis JSON is passed, the command fails with an actionable error message.

Each experiment is a self-contained directory with `src/treatment.cpp` (reproduces the hazard), `src/control.cpp` (hazard removed), a measurement harness, Makefile, PMU collection scripts, and environment setup/teardown. Treatment and control are compiled as separate TUs and linked into a single binary — the compiler cannot optimize across the comparison boundary.

13 hazard classes have dedicated kernel generators parameterized by structural evidence (e.g., `sizeof`, `estimated_frame`, `depth`). 3 emit editable stubs.

| Flag | Description |
|---|---|
| `-o, --output <dir>` | Output directory (default: `./experiments`) |
| `--rule <id>` | Only generate for a specific rule ID |
| `--min-conf <f>` | Minimum confidence threshold (default: 0.5) |
| `--sku <name>` | CPU SKU family (default: `generic`) |
| `--dry-run` | Show what would be generated without writing |
| `--help` | Show help |

Generated experiment scripts require `perf` access. `run_all.sh` includes a preflight check for `perf_event_paranoid` and fails fast with instructions if access is restricted.

**Example:**

```bash
# Generate all experiments above 0.5 confidence
lshaz exp scan.json -o ./experiments

# Preview FL002 experiments without writing
lshaz exp scan.json --dry-run --rule FL002

# Build and run a single experiment
cd experiments/H-FL002-*/
make && ./experiment --variant treatment && ./experiment --variant control
```

---

## Single-File Mode

Analyze individual source files with explicit compiler flags:

```bash
lshaz scan src/engine.cpp -- -std=c++20
lshaz scan src/engine.cpp -f json -- -std=c++20 -I include
lshaz scan src/engine.cpp --no-ir -- -std=c++20
```

Arguments after `--` are passed to Clang. The source file before `--` is the analysis target.
