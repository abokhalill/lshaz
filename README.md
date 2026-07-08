# lshaz

[![CI](https://github.com/abokhalill/lshaz/actions/workflows/ci.yml/badge.svg)](https://github.com/abokhalill/lshaz/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20x86--64-blue)]()

lshaz is a Clang/LLVM-based static analyzer that detects microarchitectural
latency hazards in C and C++ at compile time: false sharing, cache-line
spanning, atomic-ordering waste, allocator serialization, virtual dispatch
cost, and NUMA-unfriendly layout.

Every diagnostic maps to a concrete hardware mechanism. That is, cache geometry, MESI
coherence, store buffer, TLB, branch predictor, NUMA, or allocator. A finding
that cannot be tied to one of those mechanisms is not emitted.

## Why

`perf` finds these problems after they ship. lshaz finds the structural
patterns that cause them before the code runs: struct layouts whose atomic
fields share a cache line, `seq_cst` operations where x86-64 TSO makes
`release` free, heap allocations inside hot loops, and global counters written
from many call sites.

lshaz is not a linter, and it does not stop at pattern matching:

- **Evidence-graded findings.** Every diagnostic carries a severity
  (worst-case impact), a confidence (belief the hazard is real at this site),
  and an evidence tier (`Proven`/`Likely`/`Speculative`). Layout claims are
  only `Proven` when the alignment guarantees them.
- **Write-evidence analysis.** A shared-line atomic pair is graded by whether
  both fields are actually written, from distinct functions. Geometry alone
  cannot distinguish parallel writers from an init-only pattern.
- **Mitigation awareness.** Explicit cache-line alignment and pad-to-line
  idioms are recognized as author intent; findings on deliberately laid-out
  structs are demoted, not repeated at full severity.
- **C parity.** C11 `_Atomic` operations, GNU `__atomic_*`/`__sync_*`
  builtins, and opaque atomic wrappers (kernel `atomic_t`, nginx
  `ngx_atomic_t`) are first-class citizens alongside `std::atomic`.
- **A falsification loop.** `lshaz hyp` / `exp` / `feedback` turn findings
  into runnable measurement experiments whose verdicts feed back into scan
  calibration.

## Install

Linux x86-64 and WSL2. Requires LLVM/Clang development libraries.

```bash
curl -sL https://raw.githubusercontent.com/abokhalill/lshaz/main/install.sh | bash
```

Or build from source:

```bash
apt install llvm-18-dev libclang-18-dev clang-18 cmake    # Ubuntu/Debian
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

## Usage

**Set up a project** (one time — generates `compile_commands.json`):

```bash
lshaz init /path/to/project
```

**Scan it:**

```bash
lshaz scan /path/to/project
```

lshaz finds `compile_commands.json`, analyzes every translation unit in
parallel (fork-isolated worker processes), and prints diagnostics. Output is
byte-identical regardless of `--jobs` count. You can also scan a remote repo
directly:

```bash
lshaz scan https://github.com/abseil/abseil-cpp
```

**Filter output:**

```bash
lshaz scan . --min-severity Critical              # only critical findings
lshaz scan . --rule FL002                         # only false sharing
lshaz scan . --format json --output results.json  # machine-readable
```

**Compare two scans:**

```bash
lshaz diff before.json after.json
```

**Understand a finding:**

```bash
lshaz explain FL002
```

**Validate a finding on hardware:**

```bash
lshaz scan . -f json -o scan.json
lshaz exp scan.json -o experiments          # synthesize treatment/control kernels
cd experiments/H-FL002-*/ && make && scripts/run_all.sh
lshaz feedback experiments/H-FL002-*/ --store calibration.json
lshaz scan . --calibration-store calibration.json   # refuted patterns suppressed
```

All CLI flags, output formats (JSON, SARIF, clang-tidy), inline suppression,
and config options: [docs/configuration.md](docs/configuration.md).

## Example Output

```
lshaz: 157/157 TU(s) parsed, 246 diagnostic(s)

[CRITICAL] FL002 — False Sharing Candidate
  src/core/thread_identity.h:142
  Evidence: sizeof=352B; atomic_pairs_same_line=3; thread_escape=true
  Hardware: MESI invalidation ping-pong across cores. Each write forces
            invalidation in all other cores' L1/L2, triggering RFO traffic.
  Mitigation: Separate independent atomic fields onto different cache lines.

[HIGH] FL001 — Cache Line Spanning Struct
  src/alloc/alloc_list.h:79
  Evidence: sizeof=280B; lines_spanned=5; straddling_fields=1
  Hardware: Struct occupies 280B across 5 cache lines. 1 field straddles
            a line boundary (split load/store penalty).
```

## Rules

| ID | Hazard | Base severity |
|---|---|---|
| FL001 | Cache line spanning struct | High |
| FL002 | False sharing candidate | Critical |
| FL010 | Overly strong atomic ordering | High |
| FL011 | Atomic contention hotspot | Critical |
| FL012 | Lock in hot path | Critical |
| FL020 | Heap allocation in hot path | Critical |
| FL021 | Large stack frame | Medium |
| FL030 | Virtual dispatch in hot path | High |
| FL031 | `std::function` in hot path | High |
| FL040 | Centralized mutable global state | High |
| FL041 | Contended queue pattern | High |
| FL050 | Deep conditional tree | Medium |
| FL060 | NUMA-unfriendly shared structure | High |
| FL061 | Centralized dispatcher bottleneck | High |
| FL090 | Hazard amplification (compound) | Critical |
| FL091 | Synthesized interaction | Derived from components |

Base severity is a starting point: rules escalate on aggravating evidence
(in-loop writes, multi-writer confirmation) and demote on mitigating evidence
(deliberate cache-line layout, no observed writers). Per-rule detection logic:
[docs/rules.md](docs/rules.md), or `lshaz explain <ID>`.

## CI Integration

Ready-to-use GitHub Actions workflows in `.github/workflows/`:

| Workflow | File | What it does |
|---|---|---|
| PR Check | [`lshaz-pr.yml`](.github/workflows/lshaz-pr.yml) | Scans baseline + PR head, diffs findings, gates merge on regressions, posts PR comment |
| Code Scanning | [`lshaz-sarif.yml`](.github/workflows/lshaz-sarif.yml) | Uploads SARIF to GitHub Security tab on push/PR/schedule |

Copy these into any project that has `compile_commands.json` (run `lshaz init`
first).

## Limitations

- **Static analysis only.** lshaz identifies structural risk; it does not
  measure runtime impact. The `hyp`/`exp`/`feedback` loop exists precisely to
  close that gap with hardware measurements.
- **Write evidence is per-TU.** Field write sites are collected within each
  translation unit. Cross-TU, the instance with the strongest evidence wins
  deduplication, and type-level escape signals are aggregated across all TUs;
  but a writer invisible to every scanned TU (e.g., in a non-scanned library)
  is not seen.
- **Hot-path rules need a signal.** FL010, FL011, FL012, FL020, FL030, FL031,
  FL050, and FL061 fire only on functions classified hot (attribute, config
  pattern, perf profile, or transitive call-graph propagation). Structural
  rules (FL001, FL002, FL021, FL040, FL041, FL060, FL090) need no hot-path
  signal.
- **Opaque atomic wrappers need config.** Codebases that wrap atomics in plain
  structs (Linux kernel `atomic_t`, `spinlock_t`) require `atomic_type_names`
  in the config; without it those fields are invisible to atomic detection.
  See [docs/configuration.md](docs/configuration.md).
- **x86-64 defaults.** 64-byte cache lines and TSO are assumed. Use
  `--target-arch arm64` or `--target-arch arm64-apple` for ARM64 — severity
  models differ (e.g., `seq_cst` loads are free on x86-64 TSO but cost `LDAR`
  on ARM64).

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Pipeline stages, supporting analyses, evidence model, determinism contract, parallel execution |
| [docs/rules.md](docs/rules.md) | All rules: hardware mechanisms, detection logic, severity ladders, mitigations |
| [docs/configuration.md](docs/configuration.md) | Config file reference, all CLI subcommands and flags, hot-path annotation, inline suppression |
| [docs/output-formats.md](docs/output-formats.md) | JSON schema, SARIF conformance, diagnostic model, determinism guarantees |
| [docs/hypothesis-engine.md](docs/hypothesis-engine.md) | Hypothesis generation, experiment synthesis, statistical analysis, calibration loop |
| [docs/developer-guide.md](docs/developer-guide.md) | Building, testing, codebase layout, adding rules |

## License

Apache 2.0 — see [LICENSE](LICENSE).
