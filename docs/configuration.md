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
alloc_size_escalation: 1032   # FL020 escalation, glibc tcache_max (bytes)

# Branch depth
branch_depth_warn: 4          # FL050 nesting threshold

# TLB
page_size: 4096

# Output
json_output: false
output_file: ""

# Hot-path classification (fnmatch patterns; see Hot Path Annotation)
infer_hot_paths: true         # derive hotness from loop depth when nothing
                              # else supplies it; inferred hotness caps
                              # severity (see architecture.md)
hot_function_patterns: []     # e.g. ["*::onMarketData*", "hnsw_*"]
hot_file_patterns: []         # e.g. ["*/hot_path/*"]

# Perf-profile hotness (used with --perf-profile)
perf_profile_path: ""
hotness_threshold_pct: 1.0    # sample % above which a function is hot

# Vendored code. Third-party trees are skipped by default: their hazards are
# not yours to fix, and they dominate finding counts.
skip_vendored: true           # a separate switch because LLVM's YAML reader
                              # silently ignores an empty sequence, so an
                              # empty vendor_path_patterns cannot mean "off"
vendor_path_patterns: []      # defaults cover deps/, third_party/, vendor/

# Thread-role attribution (fnmatch; see architecture.md)
thread_entry_patterns: []     # worker roots when function-pointer dispatch
                              # breaks call-graph reachability
main_function_patterns: []    # additional main-thread roots
relax_function_patterns: []   # FL013: project-specific cpu_relax()/pause()
thread_index_patterns: []     # FL003: project spellings of a thread-slot
                              # subscript, e.g. ["slot"]
allocator_function_patterns: []  # FL020: project allocator wrappers, e.g.
                                 # ["z*alloc", "zfree"]. Without these the
                                 # rule sees no allocation in a codebase that
                                 # wraps libc, which is most of them.

mapping_function_patterns: []    # FL070: large-mapping wrappers, "name" or
                                 # "name:N" with N the zero-based size
                                 # parameter (default 0). A 4MB mapping one
                                 # call deep is invisible otherwise. The index
                                 # is explicit because ngx_memalign takes
                                 # (alignment, size, log) and guessing the
                                 # first integer would grade the alignment.

lock_function_patterns: []       # FL012: project lock wrappers, e.g.
unlock_function_patterns: []     # ["ngx_shmtx_lock"] / ["ngx_shmtx_unlock"],
                                 # or LWLockAcquire/LWLockRelease. nginx takes
                                 # 48 of its 50 locks through a wrapper, so
                                 # without these the rule sees 4% of that tree.
                                 # Acquire and release are separate lists
                                 # because nesting depth is a count: inferring
                                 # the release side from the spelling
                                 # desynchronizes it on the first wrapper that
                                 # does not say "unlock".

# Deployment topology. coherence_domains is the number of last-level-cache
# domains, which is NOT socket count: a Ryzen 9 5950X is one socket and one
# NUMA node with two CCDs, and cross-CCD sharing does not decay with write
# spacing. 0 (unknown) makes FL002 decline to demote sparse sharing rather
# than assume the favourable topology. Set 1 only when both writers provably
# share an LLC.
coherence_domains: 0
numa_sockets: 0

# Target model
target_arch: "x86-64"         # x86-64 | arm64 | arm64-apple
linked_allocator: ""          # tcmalloc | jemalloc | mimalloc

# Rule control
disabled_rules: []

# Thread-role attribution roots (fnmatch globs against function names).
# Thread entries are auto-detected at pthread_create/thrd_create/
# std::thread/std::async call sites; these patterns add worker roots that
# function-pointer dispatch hides (job queues, event-loop handler tables),
# and main patterns extend the main-role seed beyond main(). Feeds the
# FL002/FL090 cross-thread escalation and the FL092 precedent join.
# thread_entry_patterns:
#   - "ioThread*"
# main_function_patterns: []

# FL013 relax immunity for bespoke backoff/wait vocabularies (fnmatch
# on plain or qualified function names). The standard universe (pause,
# yield, umwait, C++20 atomic::wait, epoll/poll/select, DPDK rte_*) is
# built in.
# relax_function_patterns:
#   - "folly::detail::Sleeper::*"
#   - "*::backoff"

# SMT/Hyper-Threading enabled on the deployment target (default true).
# Reported in FL013's evidence and nothing else. It used to move that rule a
# severity notch on the sibling-starvation clause, until sync_cost measured
# 0.0% sibling recovery on Coffee Lake and again on Zen 3.
# smt_enabled: true

# FL003 cost model: L1 data cache size the padding footprint is weighed
# against, and the write-frequency roots that decide whether padding is
# worth its footprint. Hot comes from the hot-path oracle; these name the
# slower tiers and outrank it, since a file glob cannot separate a
# per-connection routine from the per-command path in the same file.
# l1d_size_bytes: 32768
# dispatch_path_patterns: ["createClient", "*AcceptHandler"]
# tick_path_patterns: ["*Cron", "beforeSleep"]

# Opaque atomic wrapper type names.
# Struct/typedef names treated as atomic even without _Atomic or std::atomic.
# Required for codebases that wrap atomics in plain structs; without this,
# those fields are invisible to the layout and escape analyses and so to
# FL001, FL002, FL013, FL041 and FL090. FL010 and FL011 do not consult it:
# they key on the operation (AtomicExpr, __sync_*, std::atomic members), which
# a wrapper's own body still performs.
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
| | `--memory-limit-mb <N>` | Per-shard address-space cap (`RLIMIT_AS`). Default derives from **total** memory divided by jobs, so the value cannot vary with ambient load. A shard that exceeds it fails loudly and names the knob, rather than the OOM killer taking the host down. |
| | `--include-vendored` | Analyze `deps/`, `third_party/`, `vendor/` trees, which are skipped by default. |
| `-r` | `--rule <ID>` | Run only the specified rule (repeatable) |
| `-a` | `--target-arch <arch>` | `x86-64` (default), `arm64`, `arm64-apple` |
| `-w` | `--watch` | Re-scan on file changes (`--watch-interval <N>`, default 2s) |
| | `--no-ir` | Disable the LLVM IR refinement pass |
| | `--ir-opt <O0\|O1\|O2>` | IR optimization level (default: `O2`) |
| | `--ir-jobs <N>` | Max parallel IR emission jobs (default: nproc) |
| | `--ir-batch-size <N>` | TUs per IR shard (default: 1) |
| | `--no-ir-cache` | Disable the content-addressed IR cache (recommended in CI) |
| | `--perf-profile <path>` | Perf profile for hot-path selection |
| | `--allocator <name>` | `tcmalloc`, `jemalloc`, `mimalloc`, shapes FL020 |
| | `--calibration-store <path>` | Calibration feedback store (JSON). Absent file = empty store; unparseable file = exit 3. |
| | `--pmu-trace <file>` | Production PMU trace ingestion |
| | `--pmu-priors <file>` | Persist/load Bayesian hazard priors |
| | `--trust-build-system` | Allow cmake/meson/bear execution on cloned repos |
| | `--changed-files <path>` | Incremental mode: only scan TUs affected by the listed files (one per line). Header changes trigger a conservative full scan. |
| `-h` | `--help` | Show help |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean, no diagnostics |
| 1 | Findings emitted |
| 2 | Parse errors. One or more TUs failed to compile (and no findings) |
| 3 | Fatal. Infrastructure failure: bad arguments, missing files, unreadable calibration store |

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

For CMake/Meson projects only the **configure** step runs by default, no
project dependencies need to be installed, and the compilation database is
used even if configure exits non-zero. Use `--build` when the project
generates headers (`configure_file()`, `custom_target()`) that TUs include.
Make projects require a real build under `bear`, so dependencies must be
installed.

### `init` runs the project's own build commands

Generating a compilation database means configuring and, for Make projects,
building. `init` therefore executes commands from the project it is pointed at:
the configure script, the generator, and the compiler invocations `bear`
observes. `scan` then re-executes the compiler command recorded for each TU.
This is inherent to `compile_commands.json` and is how every tool built on it
works, but it is worth stating plainly, because it means **`lshaz init` on an
untrusted repository is equivalent to building that repository.**

The shipped CI templates run `scan`, not `init`, and expect a committed
compilation database for this reason. If you wire `init` into a workflow that
runs on pull requests, a fork PR can then run arbitrary build commands on your
runner. Use a container or a self-hosted runner you are willing to lose, or
require the database to be committed.

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

Exit 0 when no new findings; exit 1 on regressions, usable directly as a CI
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

## `lshaz observe`

Corrects the cost model from a hardware profile. Where `feedback` labels the
finding it was measured on, `observe` corrects the mechanism, so one
measurement moves every future scan composing the same terms.

```bash
lshaz observe --profile <c2c.txt> --findings <scan.json> [options]
```

| Flag | Description |
|---|---|
| `--profile <path>` | Text of `perf c2c report --stdio --full-symbols` |
| `--findings <path>` | A scan's JSON output |
| `--ops <n>` | Operations the target completed in the profiled window |
| `--hitm-events <n>` | Counted coherence transfers in the same window |
| `--sample-period <n>` | The record's fixed sample period, if it used one |
| `--config <path>` | Reads machine, workload and store path from a config |
| `--machine <name>`, `--workload <name>` | Override the config's keys |
| `--store <path>` | Calibration store to read and write |
| `--write` | Append the observation. Default is report only. |
| `--top <n>` | Unexplained lines to list (default 10) |

Findings join to measured traffic at cache-line granularity: a finding
matches a line when both of its role sets are represented on it. That tests
the claim the finding makes. Matching on either name alone matched 178 call
sites for one redis finding and measured the program rather than the hazard.

`perf c2c` records at a frequency, so its sample counts carry no absolute
scale. Without `--hitm-events` from a counted run or `--sample-period` from a
fixed-period one, the command reports the ranking and stores nothing rather
than scaling a sampled total by a guess. A counted total comes from any
coherence-transfer event the target machine's PMU exposes, read with
`perf stat` over the same window.

Two terms are divided back out before a residual is taken. `exposed_share` is
the model's estimate of how much of a transfer the machine hides behind other
outstanding misses, and a profiler counts the transfer without saying whether
its latency reached the critical path. `calibration` is the previous round's
own correction, and measuring against an already-corrected prediction applies
it twice.

The reverse direction is reported too: measured lines that join to no
finding, ranked by traffic. That is the tool's own recall gap, addressed.

Full loop:

```bash
lshaz scan . -f json -o scan.json --config lshaz.config.yaml
perf c2c record --all-user --ldlat=5 -p $PID -- sleep 20
perf c2c report --stdio --full-symbols > profile.txt
lshaz observe --profile profile.txt --findings scan.json \
    --config lshaz.config.yaml --ops $OPS --hitm-events $HITM --write
lshaz scan . -f json -o scan.json --config lshaz.config.yaml
```

---

## `lshaz explain`

```
lshaz explain FL002        # hardware mechanism + mitigation for one rule
lshaz explain --list       # all rules with base severities
```

## `lshaz version`

Prints the tool version (`version`, `--version`, or `-v`).
