# lshaz

[![CI](https://github.com/abokhalill/lshaz/actions/workflows/ci.yml/badge.svg)](https://github.com/abokhalill/lshaz/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20x86--64-blue)]()

Static analysis tool that detects microarchitectural latency hazards in C and C++. That includes false sharing, cache-line contention, atomic ordering waste, and allocator serialization. All before code ever runs.

## Why

`perf` finds problems after they ship. lshaz finds the structural patterns that cause them at compile time: struct layouts that span cache lines, atomics that trigger cross-core invalidation storms, heap allocations in hot loops, virtual dispatch that defeats branch prediction.

It is not a linter. Every diagnostic maps to a specific hardware mechanism on x86-64.

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

That's it. lshaz finds `compile_commands.json`, parses every translation unit in parallel, and prints diagnostics to the terminal. You can also scan a remote repo directly:

```bash
lshaz scan https://github.com/abseil/abseil-cpp
```

**Filter output:**

```bash
lshaz scan . --min-severity Critical          # only critical findings
lshaz scan . --rule FL002                     # only false sharing
lshaz scan . --format json --output results.json  # machine-readable
```

**Compare two scans** (CI gating — exits non-zero on regressions):

```bash
lshaz diff before.json after.json
```

**Understand a finding:**

```bash
lshaz explain FL002
```

All CLI flags, output formats (JSON, SARIF, clang-tidy), inline suppression, and config file options are in [docs/configuration.md](docs/configuration.md).

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

| ID | Hazard | Severity |
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
| FL091 | Synthesized interaction | Varies |

See [docs/rules.md](docs/rules.md) for hardware mechanisms, detection logic, and mitigations. Run `lshaz explain <ID>` for any rule.

## CI Integration

Ready-to-use GitHub Actions workflows in `.github/workflows/`:

| Workflow | File | What it does |
|---|---|---|
| PR Check | [`lshaz-pr.yml`](.github/workflows/lshaz-pr.yml) | Scans baseline + PR head, diffs findings, gates merge on regressions, posts PR comment |
| Code Scanning | [`lshaz-sarif.yml`](.github/workflows/lshaz-sarif.yml) | Uploads SARIF to GitHub Security tab on push/PR/schedule |

Copy these into any project that has `compile_commands.json` (run `lshaz init` first).

## Limitations

- **Static analysis only** — identifies structural risk, does not measure runtime impact. Use `perf` to validate.
- **Single-TU scope** — escape analysis does not cross translation unit boundaries.
- **Hot-path rules need a signal** — FL010–FL061 only fire on functions marked hot (via attribute, config pattern, or `--perf-profile`). Structural rules (FL001, FL002, FL021, FL040, FL041, FL060, FL090) work without any hot-path signal.
- **Opaque atomic wrappers need config** — codebases that wrap atomics in plain structs (Linux kernel `atomic_t`, `spinlock_t`) require `atomic_type_names` in the config. Without it, those fields are invisible to atomic detection. See [docs/configuration.md](docs/configuration.md).
- **x86-64 default** — assumes 64-byte cache lines and TSO. Use `--target-arch arm64` or `--target-arch arm64-apple` for ARM64.

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Pipeline stages, analysis layers, latency model, parallel execution |
| [docs/rules.md](docs/rules.md) | All rules: hardware mechanisms, detection logic, examples, mitigations |
| [docs/configuration.md](docs/configuration.md) | Config file reference, all CLI flags, hot path annotation, inline suppression |
| [docs/output-formats.md](docs/output-formats.md) | JSON schema, SARIF conformance, diagnostic model, parse failure reporting |
| [docs/hypothesis-engine.md](docs/hypothesis-engine.md) | Hypothesis generation, experiment synthesis, perf access, calibration loop |
| [docs/developer-guide.md](docs/developer-guide.md) | Building, testing, validation harness, adding rules, codebase layout |

## License

Apache 2.0 — see [LICENSE](LICENSE).