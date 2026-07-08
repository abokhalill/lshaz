# Rules Reference

lshaz ships 16 rules. Each targets one microarchitectural hazard class, and
each must map to a concrete hardware mechanism — cache, coherence, store
buffer, TLB, branch predictor, NUMA, or allocator.

This document states, per rule: what fires it, what raises or lowers its
severity, and why the hardware cares. `lshaz explain <ID>` prints the same
mechanism and mitigation text the diagnostics carry.

## Rule Index

| ID | Hazard class | Fires on | Scope | Hot-path gate |
|---|---|---|---|---|
| FL001 | Cache geometry | Struct spanning multiple cache lines; wide fields straddling line boundaries | Struct | No |
| FL002 | False sharing | Independently writable fields co-resident on one cache line, in a thread-escaping type | Struct | No |
| FL010 | Atomic ordering | `seq_cst` where a weaker ordering is sufficient on the target architecture | Function | Yes |
| FL011 | Atomic contention | Atomic write sites generating cross-core RFO traffic | Function | Yes |
| FL012 | Lock contention | Mutex/spinlock acquisition in a hot function | Function | Yes |
| FL020 | Heap allocation | Allocation in a hot function; severity shaped by allocator topology | Function | Yes |
| FL021 | Stack pressure | Stack frame exceeding threshold (default 2048B) | Function | No |
| FL030 | Virtual dispatch | Virtual/indirect call in a hot function, not devirtualized in IR | Function | Yes |
| FL031 | `std::function` | Type-erased invocation in a hot function | Function | Yes |
| FL040 | Global state | Global/namespace-scope mutable variable written from multiple sites | Variable | No |
| FL041 | Contended queue | Atomic head/tail-named index pair on one cache line | Struct | No |
| FL050 | Deep conditional | Conditional nesting beyond threshold (default 4) | Function | Yes |
| FL060 | NUMA locality | Shared mutable structure with unfavorable inferred page placement | Struct | No |
| FL061 | Centralized dispatch | Single dispatcher routing to many handlers | Function | Yes |
| FL090 | Hazard amplification | Compound: multi-line footprint + atomics + thread escape on one struct | Struct | No |
| FL091 | Synthesized interaction | Two or three eligible hazards joined at one entity | Synthesized | No |

Hot-path classification is described in
[configuration.md](configuration.md#hot-path-annotation). Rules with a
hot-path gate emit nothing without a hotness signal.

## Shared contracts

Three behaviors apply across rules and are documented once:

### Atomic operation coverage

Atomic detection is language-complete. The following all count as atomic
operations (FL010, FL011) and as writes (FL002 write evidence, FL040 write
counts):

- `std::atomic<T>` / `std::atomic_ref<T>` methods and operators
- C11 `_Atomic` lvalue operations: `++`, `--`, `=`, compound assignment
  (implicit `seq_cst`)
- `__c11_atomic_*` and `__atomic_*` builtins (the ordering argument is
  evaluated when constant; runtime-variable orderings are skipped as
  unprovable, not guessed)
- `__sync_*` legacy builtins (full-barrier semantics)
- Opaque wrapper types named in `atomic_type_names` config (kernel
  `atomic_t`, nginx `ngx_atomic_t`), plus volatile typedefs with "atomic" in
  the name

### Deliberate-layout demotion (FL001, FL002, FL090)

Two layout idioms are recognized as evidence the author already reasons in
cache lines:

1. Record alignment ≥ cache line size (unreachable without an explicit
   attribute), or
2. A trailing byte-array pad that brings the record to an exact line multiple
   (the `used_memory_entry` idiom).

Either signal caps the finding at **Medium**. The finding is still reported —
single-writer discipline is an assumption the analyzer cannot verify — and the
demotion reason is stated in the escalation trace. FL041 is deliberately
exempt: head/tail naming implies producer/consumer roles, where an aligned
struct with unpadded indices is precisely the bug.

### Pair co-residency

Two fields form a shared-line pair only if a realizable base alignment can
place both on one cache line. For records aligned below the line size, the
analyzer checks every realizable base shift (multiples of the record
alignment); for line-aligned records this degenerates to the exact same-line
test. Fields more than a line apart never pair, regardless of alignment. Pair
escalation text distinguishes the two cases: "guaranteed cross-core
invalidation" (exact layout) versus "co-location depends on allocation
alignment" (sub-line alignment).

---

## Structural cache risks

### FL001 — Cache Line Spanning Struct

**Base severity:** High &nbsp;|&nbsp; **Scope:** struct &nbsp;|&nbsp; **Gate:** none

**Hardware mechanism:** L1/L2 footprint expansion and eviction probability.
Under multi-core writes, every occupied line is a coherence unit — a 5-line
struct can generate 5× the invalidation traffic of a packed one.

**Detection:** Record layout is mapped field-by-field onto 64-byte lines using
`ASTRecordLayout` (exact offsets, including base subobjects and nested
records). Fires when the record spans multiple lines past the configured
thresholds (`cache_line_span_warn` / `cache_line_span_crit`).

**Escalations:**
- Fields that straddle a line boundary with an access granule wider than one
  byte (a split load/store costs two line accesses). Byte arrays — pads,
  buffers — span lines geometrically but cannot split a single access, and are
  not reported as straddlers.
- Atomic or mutable fields with thread-escape evidence.

**Demotions:** deliberate-layout contract (above) when the record contains
atomics.

**Mitigation:** Split hot/cold fields. AoS → SoA. `alignas(64)` where the
sharing analysis (FL002) justifies it.

### FL002 — False Sharing Candidate

**Base severity:** Critical &nbsp;|&nbsp; **Scope:** struct &nbsp;|&nbsp; **Gate:** none

**Hardware mechanism:** MESI invalidation ping-pong. When two cores write
distinct fields on one line, each write forces a Request-For-Ownership that
invalidates the line in every other core's private cache. Independent data,
serialized by geometry.

**Detection:** Requires all of:
1. Thread-escape evidence for the type (atomics, sync primitives, publication
   to threads/globals — see [architecture.md](architecture.md)),
2. At least one mutable co-resident pair (per the pair co-residency contract),
3. At least one atomic field in the record.

Refcount-only records (a single atomic whose name matches a refcount pattern,
sharing lines only with immutable data) are suppressed — COW/`shared_ptr`
control blocks do not false-share.

**Severity and confidence ladder:**

| Evidence | Severity | Confidence |
|---|---|---|
| Atomic pair, line-aligned record | Critical | 0.88 (`Proven`) |
| Atomic pair, sub-line alignment | Critical | 0.80 (`Likely`) |
| Atomics present, no atomic pair | High | 0.68 |
| Mutable pairs only | High | 0.55 |

**Write-evidence grading** (applied on top of the ladder): geometry cannot
distinguish parallel writers from an init-only pattern, so the analyzer
collects per-field write sites within the TU, attributed to the enclosing
function (constructor member-init lists excluded — initialization is not
contention):

- Both fields of a pair written, from **distinct functions**: +0.06
  confidence (cap 0.95), writer counts stated in the escalation.
- Both written by a single function, or only one side written: unchanged —
  the init-pattern signature must not boost.
- **No observed writes** to any co-resident pair: Critical caps at High,
  −0.08 confidence, stated as "structural evidence only". Writers in another
  TU carry their own instance of the finding, which outranks this one at
  cross-TU deduplication.

**Demotions:** deliberate-layout contract.

**Mitigation:** Pad independently written fields to separate lines
(`alignas(64)`); per-thread or per-core replicas for counters.

```cpp
// Before: head and tail share a line; every producer write
// invalidates every consumer's cached copy.
struct Counters {
    std::atomic<uint64_t> head;
    std::atomic<uint64_t> tail;
};

// After: one line each.
struct Counters {
    alignas(64) std::atomic<uint64_t> head;
    alignas(64) std::atomic<uint64_t> tail;
};
```

---

## Synchronization risks

### FL010 — Overly Strong Atomic Ordering

**Base severity:** High &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** hot path

**Hardware mechanism:** On x86-64 TSO, a `seq_cst` store lowers to `XCHG` (or
`MOV`+`MFENCE`) — a full store-buffer drain. A `release` store is a plain
`MOV`: free. On ARM64, `seq_cst` costs real barriers (`DMB ISH`) on every
operation class, including loads (`LDAR`).

**Detection:** All atomic operation forms (see shared contract) whose
effective ordering is `seq_cst` — including implicit `seq_cst` from
argument-less `store()`, C11 `_Atomic` operators, and `__sync_*` builtins.
The ordering argument participates only when it is a genuine
`memory_order` enum or a constant that evaluates to one; runtime-variable
orderings are skipped.

**Severity by operation class:**

| Target | Store | RMW | Load |
|---|---|---|---|
| x86-64 | High (0.85) | Medium (0.55) | not reported (free under TSO) |
| ARM64 | Critical (0.90) | High (0.80) | High (0.80) |

**Escalations:** inside a loop (store → Critical 0.92: sustained store-buffer
drain per iteration); data-flow evidence that an atomic load feeds a branch
(CAS retry / spin-wait pattern).

**Mitigation:** `release` for publication stores, `acquire` for consumption
loads, `relaxed` for counters with no ordering role. State the invariant that
makes the weaker order correct.

### FL011 — Atomic Contention Hotspot

**Base severity:** Critical &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** hot path

**Hardware mechanism:** Every atomic RMW takes exclusive line ownership. N
cores incrementing one counter serialize on line ownership transfer —
throughput collapses to coherence latency, not core count.

**Detection:** Atomic **write** sites (all forms; loads and pure fences
excluded) in hot functions, on data with thread-escape evidence. The owning
record's qualified name is captured into the diagnostic's `type_name`
evidence, which joins FL011 findings to struct-level findings during FL091
synthesis.

FL011 is function-level (write sites); FL002 is struct-level (layout). A
struct can trigger FL002 without FL011 when no hot function writes its
atomics, and vice versa.

**Escalations:** multiple atomic writes per loop iteration; adjacent atomics
in the same struct.

**Mitigation:** Shard per-core and aggregate on read. Batch updates. A
contended counter is a design smell, not a tuning knob.

### FL012 — Lock in Hot Path

**Base severity:** Critical &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** hot path

**Hardware mechanism:** The lock word itself is a contended cache line (the
acquire is an atomic RMW); blocking adds kernel transitions; convoys form when
hold time exceeds arrival interval.

**Detection:** `std::mutex` / `std::lock_guard` / POSIX mutex/spinlock
acquisition in a hot function.

**Escalations:** nested locks; acquisition inside a loop.

**Mitigation:** Single-writer designs, partitioned state, lock-free structures
where the invariants allow.

---

## Memory allocation risks

### FL020 — Heap Allocation in Hot Path

**Base severity:** Critical &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** hot path

**Hardware mechanism:** Allocator metadata contention (arena locks under
glibc), TLB pressure from page-granular growth, and page faults on first
touch. Severity is shaped by `--allocator`: glibc arena-lock contention rates
Critical; thread-cached allocators (tcmalloc/jemalloc/mimalloc) demote the
lock component but keep the TLB/fault component.

**Detection:** `new`/`delete`, `malloc`/`free`, growth-capable containers, and
allocation-prone type-erasure (`std::function`, `std::shared_ptr`) in hot
functions. IR-confirmed when the IR pass is enabled: an allocation the
optimizer eliminated is demoted rather than reported on faith.

**Escalations:** allocation inside a loop; size above `alloc_size_escalation`
(default 256B); data-flow evidence the pointer escapes (passed out, stored to
a field, returned) or flows into a loop body.

**Mitigation:** Preallocate; arena/slab allocators; object pools.

### FL021 — Large Stack Frame

**Base severity:** Medium &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** none

**Hardware mechanism:** A frame that spans multiple 4KB pages costs TLB
entries and evicts L1D lines on every call/return cycle through it.

**Detection:** Estimated frame size above `stack_frame_warn_bytes` (default
2048B). IR-confirmed against the real frame layout when available.

**Escalations:** deep call chains; recursion.

**Mitigation:** Move large buffers to heap, static, or thread-local storage.

---

## Dispatch risks

### FL030 — Virtual Dispatch in Hot Path

**Base severity:** High &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** hot path

**Hardware mechanism:** Indirect branch misprediction costs a pipeline flush
(~15–20 cycles); polymorphic call sites pressure the BTB.

**Detection:** Virtual calls in hot functions. The IR pass is decisive here:
calls the optimizer devirtualized are strongly demoted (−0.25 confidence);
surviving indirect calls are confirmed (+0.10).

**Mitigation:** CRTP, `std::variant` + visitation, or sealed hierarchies that
enable devirtualization.

### FL031 — std::function in Hot Path

**Base severity:** High &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** hot path

**Hardware mechanism:** Type erasure means indirect dispatch, an inlining
barrier, and a possible heap allocation for large captures.

**Detection:** `std::function` invocation in hot functions; IR confirms
whether the indirect call survived.

**Mitigation:** Template on the callable; `auto` lambdas; function pointers
for stateless callbacks.

---

## Structural design risks

### FL040 — Centralized Mutable Global State

**Base severity:** High (Critical when atomic) &nbsp;|&nbsp; **Scope:** variable &nbsp;|&nbsp; **Gate:** none

**Hardware mechanism:** One global written by many threads is one contended
cache line for the whole process — plus guaranteed remote-node access for all
but one socket under NUMA.

**Detection:** Global or namespace-scope mutable variables. Write sites are
counted per TU across **all** write forms (plain assignment, `++`/`--`,
member writes through the global, and every atomic form — an `atomicIncr`
macro expanding to `__atomic_add_fetch` counts), with loop context recorded
per site.

**Severity grades on write pressure, not site count** — write rate is what
coherence sees:

| Evidence (global aggregate) | Verdict |
|---|---|
| Atomic + any in-loop write, or ≥4 flat sites | Critical |
| Atomic + 2–3 flat sites (start/stop lifecycle signature) | High |
| Plain type, multiple sites | High |
| Plain type, single in-loop site (one write path; concurrent writers would be a data race) | Informational |
| At most one flat write total (write-once: configuration, not contention) | Informational |

A single site inside a loop is never write-once — one *site* is not one
*write*.

**Cross-TU aggregation:** FL040 is map/reduce. Each TU emits candidates
unconditionally with per-TU write and loop-write counts; the pipeline sums
globally before grading. Verdicts are therefore identical regardless of
shard count.

**Mitigation:** Per-thread/per-core partitions with read-time aggregation;
dependency injection over ambient state.

### FL041 — Contended Queue Pattern

**Base severity:** High (Critical when the pair is confirmed) &nbsp;|&nbsp; **Scope:** struct &nbsp;|&nbsp; **Gate:** none

**Hardware mechanism:** In an SPSC/MPMC ring, producers own `head` and
consumers own `tail`. On one line, every enqueue invalidates every consumer's
cached `tail` and vice versa — the queue serializes on coherence instead of
running concurrently.

**Detection:** Atomic fields whose names match head/tail/producer/consumer
index conventions, co-resident on one line (pair co-residency contract).
Line-aligned records rate `Proven` (0.82); sub-line alignment rates `Likely`
(0.76).

**Not demoted by deliberate layout** — an aligned queue struct whose indices
still share a line is the bug this rule exists to catch.

**Mitigation:** Pad each index to its own line; per-core queues.

---

## Branching risks

### FL050 — Deep Conditional Tree in Hot Path

**Base severity:** Medium &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** hot path

**Hardware mechanism:** Nested data-dependent branches multiply misprediction
probability and fragment the instruction stream (I-cache/BTB pressure).

**Detection:** Conditional nesting depth above `branch_depth_warn`
(default 4) in hot functions.

**Mitigation:** Table-driven dispatch; flatten to early returns; precompute
decision outcomes.

---

## NUMA risks

### FL060 — NUMA-Unfriendly Shared Structure

**Base severity:** High &nbsp;|&nbsp; **Scope:** struct &nbsp;|&nbsp; **Gate:** none

**Hardware mechanism:** Cross-socket access adds ~100–300ns per miss. Pages
are placed by first touch; a structure initialized on one node and written
from all nodes is remote for every other socket.

**Detection:** Shared mutable structures (≥256B) with thread-escape evidence
and unfavorable placement inference (`NUMATopology`: local-init, main-thread,
any-thread, interleaved, explicit-bind, unknown).

**Mitigation:** First-touch-aware initialization; per-socket replication;
explicit binding.

### FL061 — Centralized Dispatcher Bottleneck

**Base severity:** High &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** hot path

**Hardware mechanism:** A single dispatch site routing to many targets is a
worst case for indirect branch prediction — the BTB entry is retrained on
every target change.

**Detection:** High fan-out dispatcher functions in hot paths.

**Mitigation:** Partition dispatch tables; compile-time routing where the
message set is closed.

---

## Compound risks

### FL090 — Hazard Amplification

**Base severity:** Critical &nbsp;|&nbsp; **Scope:** struct &nbsp;|&nbsp; **Gate:** none

**Hardware mechanism:** Latency multipliers interact super-additively on a
single structure: per-line RFO ownership transfer × multi-line footprint ×
cross-core sharing.

**Detection:** Requires all three signals on one record: spans ≥3 cache
lines, contains atomic fields, and has thread-escape evidence. Confidence is
`0.70 + 0.18 × contention` from the escape verdict. Escalations enumerate the
per-line atomic distribution, wide-granule straddlers, and mutable write
surface.

**Demotions:** deliberate-layout contract — the compound never outranks its
mitigation-adjusted components (FL001/FL002 demote → FL090 demotes with
them).

### FL091 — Synthesized Interaction

**Severity:** derived &nbsp;|&nbsp; **Scope:** synthesized in post-processing

FL091 findings are not emitted by a rule; the pipeline joins existing
diagnostics that share an **entity** — the same `file:line` site, the same
`type_name` (this is how a struct-level FL002 joins a function-level FL011
that writes that struct's fields), or the same function.

Pairs take `max(parent severities)` — a demoted parent demotes the compound —
and `min(parent confidences) × (1 + interaction threshold)`, capped at 1.0.
Triples rate Critical. One compound is emitted per (template, participant
set), regardless of how many entity keys the participants share.

Seven interaction templates:

| Template | Components | Mechanism |
|---|---|---|
| IX-001 | CacheGeometry × AtomicContention | Multi-line RFO amplification |
| IX-002 | FalseSharing × AtomicContention | Same-line invalidation + write serialization |
| IX-003 | AtomicOrdering × AtomicContention | Fence serialization + ownership transfer |
| IX-004 | AtomicContention × NUMALocality | Cross-socket RFO traffic |
| IX-005 | LockContention × HeapAllocation | Allocation under lock |
| IX-006 | VirtualDispatch × DeepConditional | Compounding branch misprediction |
| IX-007 | CacheGeometry × AtomicContention × NUMALocality | Full compound: geometry + contention + NUMA |

---

## Querying rules from the CLI

```bash
lshaz explain --list     # all rules with base severities
lshaz explain FL002      # mechanism + mitigation for one rule
```
