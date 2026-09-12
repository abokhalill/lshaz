# lshaz

[![CI](https://github.com/abokhalill/lshaz/actions/workflows/ci.yml/badge.svg)](https://github.com/abokhalill/lshaz/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20x86--64-blue)]()

Find cache-line and concurrency performance hazards in C and C++ **before**
you run the code.

`perf` tells you your program is slow on a machine that reproduces the load.
lshaz reads your source and points at the struct whose two hot counters share
a cache line, the `seq_cst` that could be `release`, the `malloc` inside your
inner loop.

```
$ lshaz scan .
lshaz: 172/172 TU(s) parsed, 41 diagnostic(s)
lshaz: coverage 16947 function(s), 20526 record(s), 170 hot

[CRITICAL] FL002, False Sharing Candidate
  src/connection.h:214  (struct ConnPool)
  Two independently-written fields share cache line 0. Each write by one
  core invalidates the line in every other core's L1/L2, forcing an RFO
  round trip on the next access from those cores.
  Evidence: sizeof=352B; atomic_pairs_same_line=3; thread_escape=true
  Fix: separate the fields onto different cache lines with alignas(64).
```

Every finding names a specific hardware mechanism: cache geometry, MESI
coherence, the store buffer, the TLB, NUMA, or the allocator. A rule that
can't name one doesn't fire.

## Install

Linux x86-64, including WSL2.

```bash
curl -sL https://raw.githubusercontent.com/abokhalill/lshaz/main/install.sh | bash
```

<details>
<summary>Build from source</summary>

```bash
apt install llvm-18-dev libclang-18-dev clang-18 cmake   # Ubuntu/Debian
cmake --preset default
cmake --build build -j$(nproc)
```

Use the preset. Under WSL an inherited Windows `PATH` can make CMake pick a
MinGW compiler, which then reports every LLVM header as missing; the preset
pins the host toolchain and configure fails fast if it can't.
</details>

## Quickstart

```bash
lshaz init .        # one time: generates compile_commands.json
lshaz scan .
```

That's it. lshaz finds your compile database, analyzes every translation unit
in parallel, and prints what it found.

A few things you'll probably want next:

```bash
lshaz scan . --min-severity Critical         # just the loud ones
lshaz scan . --rule FL002                    # just false sharing
lshaz scan . -f json -o out.json             # machine-readable
lshaz explain FL002                          # what is this rule, really?
lshaz diff before.json after.json            # did my change help?
```

You can point it at a URL instead of a path, and it'll clone and scan:

```bash
lshaz scan https://github.com/abseil/abseil-cpp
```

Exit codes: `0` clean, `1` findings, `2` some files failed to compile,
`3` something was wrong with the invocation. **Exit `2` matters**, a file
that didn't compile wasn't analyzed, so its hazards are missing from the
report, not missing from your code.

## What it looks for

| ID | Hazard |
|---|---|
| FL001 | Struct spans more cache lines than it needs to |
| FL002 | Two threads write different fields of the same cache line |
| FL003 | Per-thread array slots packed several to a line |
| FL004 | A loop that reads every per-thread slot other cores own |
| FL005 | A store that rewrites a value that was already there |
| FL006 | One field written by one thread and read by another |
| FL010 | `seq_cst` where a weaker ordering is free |
| FL011 | Atomic hammered from a hot path |
| FL012 | Lock in a hot path |
| FL013 | Spin-wait with no `pause` |
| FL014 | Atomic on an address nothing proved aligned |
| FL020 | Heap allocation in a hot path |
| FL021 | Stack frame big enough to blow L1d |
| FL030 | Virtual dispatch in a hot path |
| FL031 | `std::function` in a hot path |
| FL040 | Global mutable state written from everywhere |
| FL041 | Queue head and tail on one line |
| FL050 | Deep branch tree in a hot path |
| FL060 | Shared structure that will hurt on multi-socket |
| FL061 | Everything funnels through one dispatcher |
| FL070 | Access pattern that thrashes the TLB |
| FL090 | Several of the above on one struct, compounding |
| FL091 | Two eligible hazards landing on the same entity |
| FL092 | A struct missing the line-isolation idiom the tree uses elsewhere |
| C002 | A loop-invariant load the compiler declined to hoist |

Plus `B001`, which isn't a hazard: it means the scan itself was unsound,
usually a project that needs building first, so a clean result next to it
means nothing.

`lshaz explain <ID>` gives you the mechanism and the fix for any of them.

## How much should you trust a finding?

A finding says **the preconditions for a hazard are present in your source**.
It does not say the hazard costs you anything on your workload. That depends
on how close together in time the accesses land: coherence cost collapses once
writes are more than a few hundred nanoseconds apart within a socket, so
software doing anything substantial per operation rarely reaches it.

So lshaz grades rather than just reports. Each finding carries a severity, a
confidence, and the specific hardware claims behind it, and **severity is
capped by what those claims actually establish**. A rule can't call something
Critical on a mechanism it never demonstrated. Hot-path rules are additionally
capped by how well "this runs often" was established: a real perf profile
lifts the cap, an inference from loop structure doesn't.

Read Critical as *worth measuring*, not *known to be slow*.

For measuring, `tools/wattr/` records which threads actually wrote which cache
line at runtime and joins that against a scan. That confirms the sharing is
real. Whether it costs anything is a separate question with a much higher bar,
and a heavily written shared counter can produce no measurable coherence
traffic at all if the writes never land close enough together.

## Good to know

- **Output is byte-identical regardless of `--jobs`**, which is what makes
  `lshaz diff` usable as a CI gate.
- **Third-party trees are skipped** by default. `--include-vendored` if you
  want them.
- **Codebases that hide atomics behind a typedef** (`atomic_t`,
  `ngx_atomic_t`) need those names in `atomic_type_names`, or lshaz can't see
  the fields are atomic at all.
- **x86-64 is the default model** (64-byte lines, TSO). `--target-arch arm64`
  changes the severity model, since a `seq_cst` load is free under TSO and
  costs `LDAR` on ARM64.
- **Scanning a library on its own** gives thin hot-path coverage, there's no
  application to infer hot paths from. lshaz tells you when this happens.

## CI

Drop-in GitHub Actions in `.github/workflows/`: [`lshaz-pr.yml`](.github/workflows/lshaz-pr.yml)
gates merges on new findings, [`lshaz-sarif.yml`](.github/workflows/lshaz-sarif.yml)
feeds the Security tab.

## Going deeper

| | |
|---|---|
| [Architecture](docs/architecture.md) | How the pipeline works, the evidence model, why output is deterministic |
| [Rules](docs/rules.md) | Every rule: mechanism, detection logic, severity ladder, fix |
| [Configuration](docs/configuration.md) | Every flag and config key, hot-path annotation, suppression |
| [Output formats](docs/output-formats.md) | JSON schema, SARIF, how to consume findings |
| [Hypothesis engine](docs/hypothesis-engine.md) | Turning findings into runnable experiments |
| [Developer guide](docs/developer-guide.md) | Building, testing, adding a rule |

## License

Apache 2.0, see [LICENSE](LICENSE).
