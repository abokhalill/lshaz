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
```

---

## Scan CLI Options

```
lshaz scan <path> [options]
```

| Flag | Description |
|---|---|
| `--compile-db <path>` | Explicit path to `compile_commands.json` |
| `--config <path>` | Path to `lshaz.config.yaml` |
| `--format <cli\|json\|sarif\|tidy>` | Output format (default: `cli`). `tidy` emits clang-tidy-compatible diagnostics. |
| `--output <path>` | Write output to file instead of stdout |
| `--min-severity <level>` | Minimum severity: `Informational`, `Medium`, `High`, `Critical` |
| `--min-evidence <tier>` | Minimum evidence tier: `speculative`, `likely`, `proven` |
| `--include <pattern>` | Only analyze files matching pattern (repeatable) |
| `--exclude <pattern>` | Skip files matching pattern (repeatable) |
| `--max-files <N>` | Maximum translation units to analyze |
| `--jobs <N>` | Parallel AST analysis worker processes (default: hardware_concurrency). Uses fork-based isolation, not threads. |
| `--no-ir` | Disable LLVM IR analysis pass |
| `--ir-opt <O0\|O1\|O2>` | IR optimization level (default: O0) |
| `--ir-jobs <N>` | Max parallel IR emission jobs (default: hardware_concurrency) |
| `--ir-batch-size <N>` | TUs per IR shard (default: 1) |
| `--no-ir-cache` | Disable incremental IR cache. Recommended for CI. |
| `--perf-profile <path>` | Perf profile data for hot-path selection |
| `--hotness-threshold <pct>` | Sample percentage threshold for profile hotness (default: 1.0) |
| `--allocator <name>` | Linked allocator: `tcmalloc`, `jemalloc`, `mimalloc` (affects FL020) |
| `--calibration-store <path>` | Path to calibration feedback store |
| `--pmu-trace <file>` | Production PMU trace data for closed-loop learning |
| `--pmu-priors <file>` | Persist/load Bayesian hazard priors across runs |
| `--watch` | Watch mode: re-scan on file changes |
| `--watch-interval <N>` | Seconds between watch polls (default: 2) |
| `--trust-build-system` | Allow cmake/meson/bear execution on cloned remote repos |
| `--changed-files <path>` | Incremental mode: only scan TUs affected by files listed in `<path>` (one per line). Header changes trigger full scan conservatively. |
| `--rule <ID>` | Run only the specified rule (repeatable). Disables all other rules. Use for per-rule CI gating. |
| `--target-arch <arch>` | Target architecture: `x86-64` (default, 64B lines, TSO), `arm64` (64B lines, weak ordering), `arm64-apple` (128B lines, weak ordering). Affects cache model, FL010 severity/reasoning, and mitigation text. |
| `--help` | Show help with exit code reference |

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

| Flag | Description |
|---|---|
| `[path]` | Project root (default: current directory) |
| `--no-config` | Skip `lshaz.config.yaml` generation |
| `--force` | Regenerate `compile_commands.json` even if it exists |
| `--help` | Show help |

---

## Diff CLI Options

```
lshaz diff <before.json> <after.json>
```

Compares two JSON scan results and reports new and resolved findings. Exit code 0 if no new findings, 1 if regressions introduced.

Diff key: `(ruleID, file, line)`.

**CI usage:**

```bash
lshaz scan . --format json --output before.json
# ... apply changes ...
lshaz scan . --format json --output after.json
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

| Flag | Description |
|---|---|
| `--dry-run` | Show patches without modifying files |
| `--rules <list>` | Comma-separated rules to fix (default: `FL001`) |
| `--compile-db <path>` | Path to `compile_commands.json` |
| `--config <path>` | Path to `lshaz.config.yaml` |

**Example:**

```bash
# Preview fixes
lshaz fix . --dry-run

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

| Flag | Description |
|---|---|
| `-o, --output <dir>` | Output directory (default: `./experiments`) |
| `--rule <id>` | Only generate for a specific rule ID |
| `--min-conf <f>` | Minimum confidence threshold (default: 0.5) |
| `--sku <name>` | CPU SKU family (default: `generic`) |
| `--dry-run` | Show what would be generated without writing |
| `--help` | Show help |

Generated experiment scripts require `perf` access. `run_all.sh` includes a preflight check for `perf_event_paranoid` and fails fast with instructions if access is restricted. See [hypothesis-engine.md](hypothesis-engine.md#perf-access-requirements) for details.

**Example:**

```bash
lshaz exp scan.json --output ./experiments
lshaz exp scan.json --dry-run --rule FL002
```

---

## Single-File Mode

Analyze individual source files with explicit compiler flags:

```bash
lshaz scan src/engine.cpp -- -std=c++20
lshaz scan src/engine.cpp --format json -- -std=c++20 -I include
lshaz scan src/engine.cpp --no-ir -- -std=c++20
```

Arguments after `--` are passed to Clang. The source file before `--` is the analysis target.
