# lshaz

[![CI](https://github.com/abokhalill/lshaz/actions/workflows/ci.yml/badge.svg)](https://github.com/abokhalill/lshaz/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20x86--64-blue)]()

Find cache-line and concurrency performance hazards in C and C++ **before** you
run the code.

`perf` tells you a program is slow, on a machine that reproduces the load.
lshaz reads your source and points at the struct whose two hot counters share a
cache line, the `seq_cst` that could be `release`, the `malloc` inside an inner
loop.

```
$ lshaz scan .
lshaz: [points_to] 51144 constraint(s) -> 2496 object(s); 90% of accesses resolved
lshaz: 172/172 TU(s) parsed, 41 diagnostic(s)
lshaz: coverage 16947 function(s), 20526 record(s), 43% hot

src/connection.h:214:8: [Critical] FL002, False Sharing Candidate
  Hardware: Struct 'ConnPool' (352B, 6 line(s)): 3 mutable field pair(s) share
  cache line(s) with thread-escape evidence. Concurrent writes to co-located
  fields trigger MESI invalidation per write.
  Evidence: atomic_pairs_same_line=3; global_instances=g_pool; sizeof=352B;
  thread_escape=true; +5 more (--format json)
  Mitigation: Pad independently-written fields to separate 64B cache lines with
  alignas(64). Consider per-thread/per-core replicas.
  Evidence tier: likely
  Escalation: object-level sharing: 'g_pool' is reached by more than one thread role

lshaz: 41 finding(s)  Critical 4  High 11  Medium 26
lshaz: by rule   FL002 9  FL040 8  FL061 7  FL006 5  FL020 4  (+6 more)
lshaz: by file   src/connection.h 12  src/server.c 9  src/rdb.c 6  (+14 more)
```

Every finding names a specific hardware mechanism: cache geometry, MESI
coherence, the store buffer, the TLB, NUMA, or the allocator. A rule that
cannot name one does not ship.

## Install

Linux x86-64, including WSL2.

```bash
curl -sL https://raw.githubusercontent.com/abokhalill/lshaz/main/install.sh | bash
```

Installs to `~/.local/bin` and sets up shell completions for bash, zsh and fish.

<details>
<summary>Build from source</summary>

```bash
apt install llvm-18-dev libclang-18-dev clang-18 cmake   # Ubuntu/Debian
cmake --preset default
cmake --build build -j$(nproc)
sudo cmake --install build          # optional, system-wide
```

Use the preset. Under WSL an inherited Windows `PATH` can make CMake pick a
MinGW compiler, which then reports every LLVM header as missing; the preset
pins the host toolchain and fails configuration immediately if it cannot.
</details>

## Quickstart

```bash
lshaz init .        # one time: generates compile_commands.json
lshaz scan .
```

lshaz finds your compile database, analyzes every translation unit in parallel,
and prints what it found. If there is no compile database it tells you so and
names the command that creates one.

What you will most likely want next:

```bash
lshaz scan . --min-severity Critical    # only the loud ones
lshaz scan . --rule FL002               # only false sharing
lshaz scan . -f tidy                    # one line per finding, editor-friendly
lshaz scan . -f json -o out.json        # complete record, every field
lshaz explain FL002                     # what this rule is, and why
lshaz diff before.json after.json       # did the change help?
```

Point it at a URL instead of a path and it clones, then scans:

```bash
lshaz scan https://github.com/abseil/abseil-cpp
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean, nothing reported |
| `1` | Findings reported |
| `2` | Some translation units failed to compile |
| `3` | The invocation was wrong, or the scan could not run |

**Exit `2` matters.** A file that did not compile was not analyzed, so its
hazards are missing from the report, not missing from your code.

## The mental model

lshaz answers one question: **does this source contain the preconditions for a
known hardware latency hazard?**

It reasons about three things, and keeping them separate is the whole design.

**Structure** is what the code says. Field offsets, cache-line residency, atomic
ordering, allocation sites. This part is close to certain.

**Reachability** is who touches what. lshaz solves whole-program points-to
across every translation unit, so it distinguishes two globals of the same type
from one global two threads share, and it names the object a finding is about instead of only its type. Scans report how much of this they resolved.

**Cost** is what it would actually take from you, and is the weakest link.
It depends on how close together in time the accesses land. Coherence cost
collapses once writes are more than a few hundred nanoseconds apart within a
socket, so software doing anything substantial per operation rarely reaches it.

**Read Critical as *worth measuring*, not *known to be slow*.**

To measure, `tools/wattr/` records which threads actually wrote which cache line
at runtime and joins that against a scan. That confirms the sharing is real.
Whether it costs anything is a separate story.

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

`B001` is not a hazard. It means the scan itself was unsound, usually a project
that needed building first, so a clean result beside it means nothing.

`lshaz explain <ID>` gives the mechanism and the fix for any of them, and
`lshaz explain --list` prints them all.

## Good to know

- **Output is byte-identical regardless of `--jobs`.** That is what makes
  `lshaz diff` usable as a CI gate.
- **Third-party trees are skipped** by default. Use `--include-vendored` to
  include them.
- **Atomics hidden behind a typedef** (`atomic_t`, `ngx_atomic_t`) must be named
  in `atomic_type_names`, or lshaz cannot tell those fields are atomic. The same
  applies to allocators reached through a wrapper, via
  `allocator_function_patterns`. 
- **x86-64 is the default model** (64-byte lines, TSO). `--target-arch arm64`
  changes the grading, since a `seq_cst` load is free under TSO and costs `LDAR`
  on ARM64.
- **Scanning a library on its own** gives thin hot-path coverage: there is no
  application to infer hot paths from. lshaz reports when this happens.

## CI

Drop-in GitHub Actions in `.github/workflows/`:
[`lshaz-pr.yml`](.github/workflows/lshaz-pr.yml) gates merges on new findings,
[`lshaz-sarif.yml`](.github/workflows/lshaz-sarif.yml) feeds the Security tab.

## Going deeper

| | |
|---|---|
| [Architecture](docs/architecture.md) | The pipeline, the evidence model, why output is deterministic |
| [Rules](docs/rules.md) | Every rule: mechanism, detection logic, severity ladder, fix |
| [Configuration](docs/configuration.md) | Every flag and config key, hot-path annotation, suppression |
| [Output formats](docs/output-formats.md) | JSON schema, SARIF, how to consume findings |
| [Hypothesis engine](docs/hypothesis-engine.md) | Turning findings into runnable experiments |
| [Developer guide](docs/developer-guide.md) | Building, testing, adding a rule |

## License

Apache 2.0, see [LICENSE](LICENSE).
