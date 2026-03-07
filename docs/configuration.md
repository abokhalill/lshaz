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
| `--format <cli\|json\|sarif>` | Output format (default: `cli`) |
| `--output <path>` | Write output to file instead of stdout |
| `--min-severity <level>` | Minimum severity: `Informational`, `Medium`, `High`, `Critical` |
| `--min-evidence <tier>` | Minimum evidence tier: `speculative`, `likely`, `proven` |
| `--include <pattern>` | Only analyze files matching pattern (repeatable) |
| `--exclude <pattern>` | Skip files matching pattern (repeatable) |
| `--max-files <N>` | Maximum translation units to analyze |
| `--jobs <N>` | Parallel AST analysis threads (default: hardware_concurrency) |
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

Functions can be marked hot in three ways:

**1. Source annotation:**

```cpp
[[clang::annotate("lshaz_hot")]]
void onMarketData(const Update& u);
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

## Legacy CLI

The original Clang-tooling interface remains available but is **deprecated since 0.2.0** and will be **removed in 0.4.0**:

```bash
./build/lshaz src/engine.cpp -- -std=c++20
./build/lshaz --format=json src/engine.cpp -- -std=c++20
./build/lshaz --no-ir src/engine.cpp -- -std=c++20
```

Arguments after `--` are passed to Clang. Source files before `--` are the analysis targets. Use `lshaz scan` instead.
