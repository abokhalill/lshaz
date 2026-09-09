# Rules Reference

lshaz ships 23 rules. Each targets one microarchitectural hazard class, and
each must map to a concrete hardware mechanism, cache, coherence, store
buffer, TLB, branch predictor, NUMA, or allocator.

This document states, per rule: what fires it, what raises or lowers its
severity, and why the hardware cares. `lshaz explain <ID>` prints the same
mechanism and mitigation text the diagnostics carry.

## Rule Index

| ID | Hazard class | Fires on | Scope | Hot-path gate |
|---|---|---|---|---|
| FL001 | Cache geometry | Struct spanning multiple cache lines; wide fields straddling line boundaries | Struct | No |
| FL002 | False sharing | Independently writable fields co-resident on one cache line, in a thread-escaping type | Struct | No |
| FL003 | Per-thread array false sharing | Array slots written under a thread-identity index, packed multiple per cache line | Array | No |
| FL004 | Aggregation sweep | Loop reading every per-thread slot of an array other cores own | Array | No |
| FL005 | Redundant shared store | Unconditional store of a coarsened value into a file-scope object | Store site | Yes |
| FL010 | Atomic ordering | `seq_cst` where a weaker ordering is sufficient on the target architecture | Function | Yes |
| FL011 | Atomic contention | Atomic write sites generating cross-core RFO traffic | Function | Yes |
| FL012 | Lock contention | Mutex/spinlock acquisition in a hot function | Function | Yes |
| FL013 | Spin-wait without pause | Tight atomic/volatile poll loop lacking pause/yield/backoff | Function | Yes |
| FL014 | Misaligned atomic | Atomic through a pointer cast the source never proved aligned | Function | No |
| FL020 | Heap allocation | Allocation in a hot function; severity shaped by allocator topology | Function | Yes |
| FL021 | Stack pressure | Stack frame exceeding threshold (default 2048B) | Function | No |
| FL030 | Virtual dispatch | Virtual/indirect call in a hot function, not devirtualized in IR | Function | Yes |
| FL031 | `std::function` | Type-erased invocation in a hot function | Function | Yes |
| FL040 | Global state | Global/namespace-scope mutable variable written from multiple sites | Variable | No |
| FL041 | Contended queue | Atomic head/tail-named index pair on one cache line | Struct | No |
| FL050 | Deep conditional | Conditional nesting beyond threshold (default 4) | Function | Yes |
| FL060 | NUMA locality | Shared mutable structure with unfavorable inferred page placement | Struct | No |
| FL061 | Centralized dispatch | Single dispatcher routing to many handlers | Function | Yes |
| FL070 | TLB pressure | ≥2MB hot-referenced global without hugepage alignment; large map/alloc without hugepage provision | Mixed | Partial |
| FL090 | Hazard amplification | Compound: multi-line footprint + atomics + thread escape on one struct | Struct | No |
| FL091 | Synthesized interaction | Two or three eligible hazards joined at one entity | Synthesized | No |
| FL092 | Unapplied in-tree mitigation | Attributed FL002/FL090 on a struct without the line-isolation idiom the codebase applies elsewhere | Synthesized | No |

Hot-path classification is described in
[configuration.md](configuration.md#hot-path-annotation). Rules with a
hot-path gate emit nothing without a hotness signal.

## Shared contracts

These behaviors apply across rules and are documented once.

### Mechanism claims bound severity

No rule asserts a hazard as an opaque verdict. Each decomposes its hardware
argument into claims. An `effect`, the `precondition` that effect requires,
whether that precondition was `established`, and the severity it `supports`.
The pipeline clamps every finding to what its claims establish, so a rule
cannot grade Critical on a mechanism it never showed.

Ordinary claims are **alternatives** and combine with `max`: any one
established mechanism carries the finding. A **gating** claim is a conjunct
and caps the result instead. Hotness is the canonical gating claim, since no
mechanism costs anything in code that never runs.

`scan_test` fails if any emitted finding omits its claims, or if a
severity outranks an established one.

### Hot-path gating caps severity

A rule marked "Yes" in the hot-path column fires only on functions with a
hotness signal, and the strength of that signal bounds the grade:

| Hotness source | Ceiling |
|---|---|
| Perf profile, or declared (`__attribute__((hot))`, config glob) | none |
| Inferred from nested loops or recursion | one grade below |
| Inferred from a single loop level | two grades below |

Inferred hotness establishes *shape*, not execution. It justifies looking, not
a grade implying measured cost.

### Sharing needs a route to the same object

Escape means threads can reach the *type*. False sharing needs two cores
reaching the same *object*, which is stricter:

```
hasSharingRoute = hasPublication || hasThreadWriters
                || (hasGlobalInstance && anyWriterOnThread)
```

Rules also distinguish **standing** writes (`g_stats.hits++`, a fixed object
every thread can name) from **handed-over** writes (`io->len = n`, whatever
the caller passed in). A queue hands each request to one owner at a time, so
a per-request object is never falsely shared however many functions write it.
Writer counts cannot express this difference; the base-expression root can.

### Contention needs two cores, not two functions

A thread entry spawned inside a loop, or from more than one call site, runs on
several threads at once. One writer function is then sufficient for two cores
to contend, so rules do not require two distinct writer functions when a pool
role is involved. That requirement rejected the commonest thread-pool shape.

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

Either signal caps the finding at **Medium**. The finding is still reported,
single-writer discipline is an assumption the analyzer cannot verify, and the
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

### FL001, Cache Line Spanning Struct

**Base severity:** High &nbsp;|&nbsp; **Scope:** struct &nbsp;|&nbsp; **Gate:** none

**Hardware mechanism:** L1/L2 footprint expansion and eviction probability.
Under multi-core writes, every occupied line is a coherence unit, a 5-line
struct can generate 5× the invalidation traffic of a packed one.

**Detection:** Record layout is mapped field-by-field onto 64-byte lines using
`ASTRecordLayout` (exact offsets, including base subobjects and nested
records). Fires when the record spans multiple lines past the configured
thresholds (`cache_line_span_warn` / `cache_line_span_crit`).

**Escalations:**
- Fields that straddle a line boundary with an access granule wider than one
  byte (a split load/store costs two line accesses). Byte arrays, pads,
  buffers. Span lines geometrically but cannot split a single access, and are
  not reported as straddlers.
- Atomic or mutable fields with thread-escape evidence.

**Demotions:** deliberate-layout contract (above) when the record contains
atomics.

**Mitigation:** Split hot/cold fields. AoS → SoA. `alignas(64)` where the
sharing analysis (FL002) justifies it.

### FL002, False Sharing Candidate

**Base severity:** Critical &nbsp;|&nbsp; **Scope:** struct &nbsp;|&nbsp; **Gate:** none

**Hardware mechanism:** MESI invalidation ping-pong. When two cores write
distinct fields on one line, each write forces a Request-For-Ownership that
invalidates the line in every other core's private cache. Independent data,
serialized by geometry.

**Detection:** Requires all of:
1. Thread-escape evidence for the type (atomics, sync primitives, publication
   to threads/globals, or a record written from ≥2 functions one of which is
   spawned as a thread. See [architecture.md](architecture.md)),
2. At least one mutable co-resident pair (per the pair co-residency contract),
3. Concurrency evidence: either an atomic field, or proven distinct writer
   functions for the pair.

**Atomicity is not the gate.** Striped and role-partitioned fields guarantee
single-writer-per-slot, so the dominant false-sharing idiom is deliberately
non-atomic, no data race, pure coherence traffic. An atomicity precondition
scored zero on exactly that shape. A non-atomic record keeps the severity, since
the mechanism and cost are identical, and takes a lower confidence, since
concurrent execution of the writers is not proven.

A pair may be **intra-array**. Two elements of one array on one line. An array
is a single `FieldDecl`, so pairing distinct decls alone can never express it.
Because co-residency is not contention (padding arrays share lines by
construction and are never written), an intra-array pair additionally requires
distinct writers reaching the array.

Two records are reported but demoted, never suppressed:

- **Refcount-only**. A single atomic whose name matches a refcount pattern,
  sharing lines only with immutable data. COW/`shared_ptr` control blocks do
  not false-share.
- **Self-guarded**. A record carrying its own sync primitive with no atomics.
  A mutex co-located with the data it guards is a deliberate, benign layout:
  writes under that lock are already serialized. Per-field lock coverage is not
  provable here, so the finding is marked rather than dropped.

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
function (constructor member-init lists excluded, initialization is not
contention):

- Both fields of a pair written, from **distinct functions**: +0.06
  confidence (cap 0.95), writer counts stated in the escalation.
- Both written by a single function, or only one side written: unchanged,
  the init-pattern signature must not boost.
- **No observed writes** to any co-resident pair: Critical caps at High,
  −0.08 confidence, stated as "structural evidence only". Writers in another
  TU carry their own instance of the finding, which outranks this one at
  cross-TU deduplication.

**Cross-TU pairs.** Write evidence above is per-TU, so a store compiled apart
from the read beside it is invisible to it: redis stores `redisCommand::calls`
in `server.c` while `db.c` reads the key specs on the same line. The reduce
phase re-forms the co-residency test from serialized field offsets and joins it
against the merged per-field writer and reader sets, adding the pair as
evidence on the existing finding, or emitting one where no TU held both halves.
The pair must clear the sharing-route verdict first, so a type nothing shows a
thread reaching is not reported on this path.

Ranked by mechanism, not by field order. A neighbour that is read somewhere
and written nowhere in the merged program outranks everything: two writers
trade the line and each pays once per alternation, while one writer against N
reading cores costs N re-fetches per store with nothing coming back, and the
fix is unambiguous because moving a field nothing writes can break nothing.
Measured as memcached's worst line, `slabclass[3].size` set once in
`slabs_init` and read by `slabs_clsid` on every allocation, taking 93.6% of
that line's HITM. Below it, a write/write pair outranks a plain read/write
one, then the count of non-overlapping functions.

The never-written claim carries two conjuncts. The neighbour must be a plain
scalar, because a mutex or an array is routinely mutated through its address
with no assignment anywhere, so "no writer" would be a statement about the
tracker rather than the program; without it `LIBEVENT_THREAD::ion_lock` was
reported with a mitigation telling the reader to relocate a live
`pthread_mutex_t`. And some writer of the stored field must be confirmed hot
over the merged graph, since co-location with a field written twice at startup
costs nothing however widely the neighbour is read. On a 572-field
record the alphabetically first pairs say nothing. Bitfields are excluded, a
bitfield's exported extent is its declared type's rather than the bits it owns,
so every bitfield in a storage unit would pair with its neighbours, and no
padding reaches a shared word anyway.

**Demotions:** deliberate-layout contract, and a density conjunct. Contended-RMW
cost decays with inter-write spacing only while both writers sit under one
last-level cache: measured collapsing to zero by ~119ns within a CCD, and flat
at ~51ns from 2.2ns out to 122us across two CCDs of a Ryzen 9 5950X, which is
one socket and one NUMA node. Socket count is therefore the wrong predicate on
any chiplet part, and `coherence_domains` is the right one. Unknown declines to
demote.

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

### FL003, Per-Thread Array False Sharing

**Base severity:** High &nbsp;|&nbsp; **Scope:** array (struct member or file-static) &nbsp;|&nbsp; **Gate:** none

**Hardware mechanism:** an array of `N` slots with element size `S < 64`
packs `⌊64/S⌋` slots per cache line. When slot `i` is written by one core
and slot `j` on the same line by another, each write takes the line in
Modified state and invalidates the other core's copy, a full RFO per
update, on a line neither core needs the rest of.

**Detection gate is index provenance, not element atomicity.** Striping
makes each slot single-writer, so per-thread arrays are routinely plain
scalars; requiring atomic elements would miss the cleanest instances of
the pattern. A slot write counts as *striped* only when its subscript is
thread-derived:

- `thread_local` storage class on the index variable, the value *is* the
  thread's identity; no heuristic involved
- a narrow identifier set (`tid`, `thread_index`, `*_tid`, `sched_getcpu`, …),
  extended per project by `thread_index_patterns`. The set stays narrow
  because the generic spellings are ambiguous: adding `slot` to redis finds
  the two real per-thread arrays in the HNSW module and three cluster
  hash-slot arrays that have nothing to do with threads.

**Whose identity the subscript names decides the grade.** `arr[tid]`,
`arr[sched_getcpu()]` and a `thread_local` index name the thread executing
the write. `arr[c->tid]` reads the id out of an object the caller handed in,
so it names that object's *owner*, and a single thread can drive every slot:
redis writes `io_threads_clients_num[c->tid]` only from the main thread. When
every subscript is an owner id and the writer-role join has not established
two roles, the finding caps at Medium, loses 0.15 confidence, and carries
`index_identity: owner`. It is demoted rather than dropped, since a worker
that stamps itself into the object first makes the owner id its own.

Loop-induction subscripts classify as **aggregation sweeps**, bulk resets
and total-summing loops are single-threaded traversals and never count as
multi-thread evidence.

Detection covers C11/GNU atomic builtins (which Clang models as
`AtomicExpr`, a distinct node from `CallExpr`), C++ atomic member calls,
compound assignment, and increment/decrement. Pointer aliases
(`T *p = &arr[K]`) retarget subscripts onto the underlying array.

**Severity ladder:**

| Evidence | Severity |
|---|---|
| writers provably span two thread roles (call-graph joined) | Critical |
| thread-identity subscript, `thread_local`-derived or atomic elements or ≥2 writer functions | High |
| thread-identity subscript from the identifier set alone | Medium |

**Fix selection is an ROI decision, not a reflex.** Padding buys
isolation with L1D footprint, so the recommended shape is chosen
against both write frequency and cost:

| condition | recommended fix |
|---|---|
| a line-aligned per-thread structure already exists in-tree | **relocate**. Identical isolation, zero added footprint |
| hot-path writes, padding costs ≤10% of L1D | full padding |
| hot-path writes, padding costs >10% of L1D | head padding (isolate the hottest slot) |
| non-hot writes, padding costs >10% of L1D | **none**. Reported Informational, the coherence traffic is real but the fix costs more than it saves |

Write frequency comes from the hot-path oracle, refined by
`dispatch_path_patterns` and `tick_path_patterns` (fnmatch). Named
tiers outrank oracle hotness: the oracle reaches most functions via a
file glob or transitive propagation, which cannot separate a
per-connection setup routine from the per-command path in the same
file. **Unknown frequency does not demote**, unestablished is not
proven-low, and such findings keep their evidence severity while
carrying an escalation naming what would refine them.

Severity answers whether the finding is worth acting on; confidence
answers whether the hazard is real. They move independently: a
mechanism at 0.88 confidence whose only available fix would evict a
quarter of L1D is Informational.

**Mitigation respect:** an element stride that is a multiple of the line
size is full isolation and never fires. A line-aligned base **plus a
padded index origin** isolates slot 0 only (slots 1.. still pack) and
caps at Medium with the residual stated. Base alignment *alone* is not
mitigation: it separates slot 0 from the preceding symbol and does
nothing for slot 0 versus slot 1.

---

## Synchronization risks

### FL004, Aggregation Sweep Over Per-Thread Slots

**Base severity:** High &nbsp;|&nbsp; **Scope:** array (struct member or file-static) &nbsp;|&nbsp; **Gate:** sweep hotness

**Hardware mechanism:** a loop reads every slot of an array written under a
thread-identity index. Reading slot `i` takes its line in Shared, downgrading
the owning core out of Modified, and that owner pays an Exclusive re-acquire
on its next write. The sweep costs about `2 x lines` coherence transactions
per call.

Padding cannot fix this and increases the line count, so the correctly padded
array FL003 skips is exactly where it lives. redis pads and aligns
`used_memory[]`, FL003 stays silent, and `zmalloc_used_memory()` still
measured second on a loaded redis at 64 of 1198 HITM (i9-9900K, recorded in
`reports/measured-constants.md`). FL003 was already collecting the evidence
as `aggregators` and grading it "read side, not a striped write".

**Gates:** at least one thread-identity writer, since with no writer no line
is in Modified state and the sweep downgrades nothing; not `mainThreadOnly`,
since one thread owning every slot means no line is owned elsewhere; at least
4 lines swept.

**Severity** is the sweep's call rate. Hot over 16 or more lines is Critical,
hot is High, dispatch is Medium, tick is Informational, because sweeping on a
stats timer is the correct design. The reported line count is the array's
declared bound, an upper bound on what any one loop touches: a loop stopping
at a configured thread count touches proportionally fewer.

**Fix:** keep a running total the writers update, or cache the aggregate and
refresh it off the hot path.

### FL005, Redundant Store to a Shared Line

**Base severity:** Medium &nbsp;|&nbsp; **Scope:** store site &nbsp;|&nbsp; **Gate:** hot path

**Hardware mechanism:** A store to a line other cores hold is a
Request-For-Ownership whatever value it writes. The line is taken Exclusive
and invalidated in every sharer, and each of them re-fetches on its next read.
Storing a value that is already there pays that in full and buys nothing.

**Detection:** the destination roots at a file-scope object, its value is a
contraction (integer division or right shift by a literal, or a predicate), and
no enclosing condition tests the destination. The contraction is what makes the
claim provable rather than a guess: a value divided by K changes at most once
per K executions of the store.

**The repetition conjunct is settled in the reduce phase.** Whether a store
runs more than once is a property of the merged call graph, and a per-decl
`analyze` cannot see it. The rule ships the claim unestablished; the reduce
pass confirms it when the function is reached from a loop or from two call
sites, drops the finding when the function is reached once from `main`, and
leaves it unknown when no call edge was recorded, since a function reached
only through a pointer table has no caller in the graph. Without this the rule
reported redis `initServer`, which runs at startup, and was deleted once for it.

**Any early exit ahead of the store counts as a rate bound.** nginx returns on
`tp->sec == sec` and then stores `cached_gmtoff` derived from that same second,
so the store is already once-per-second while nothing tests `cached_gmtoff`
itself. Requiring the guard to name the destination reported it. A guarded
predecessor is treated as a bound instead, which costs findings where the exit
is unrelated and is the direction that does not invent them.

**Measured, including the part that did not work.** redis stores
`server.unixtime` as microseconds divided down to seconds about once per
command: 52,304,853 stores in one 20s run, 22 of which changed the value, on
the line carrying 12.3% of the process's HITM. Guarding the store removed that
line from the profile entirely and moved throughput by nothing measurable, and
regressed it at `io-threads` 1 and 2 when the guard read the shared location
back. The wasted traffic is certain; its endpoint value is not. Plain stores
therefore grade Informational and atomic ones Medium, and the mitigation
suggests keeping the compared value in a thread-local so the guard does not
touch the shared line either.

### FL010, Overly Strong Atomic Ordering

**Base severity:** High &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** hot path

**Hardware mechanism:** On x86-64 TSO, a `seq_cst` store lowers to `XCHG` (or
`MOV`+`MFENCE`). A full store-buffer drain. A `release` store is a plain
`MOV`: free. On ARM64, `seq_cst` costs real barriers (`DMB ISH`) on every
operation class, including loads (`LDAR`).

**Detection:** All atomic operation forms (see shared contract) whose
effective ordering is `seq_cst`, including implicit `seq_cst` from
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

### FL011, Atomic Contention Hotspot

**Base severity:** Critical &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** hot path

**Hardware mechanism:** Every atomic RMW takes the line in Modified state, so
two cores writing it trade ownership. The LOCK-prefixed operation costs ~4-6ns
uncontended at every ordering. The transfer on top is spacing-dependent within
a socket: +22ns at 8ns between writes, +0.3ns at 125ns, nothing past ~1us,
since the line must still be resident in a peer's L1 to be stolen. Across
sockets it does not decay at all, 32-52ns flat from ~670ns out to 85us.

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

### FL012, Lock in Hot Path

**Base severity:** Critical &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** hot path

**Hardware mechanism:** The lock word itself is a contended cache line (the
acquire is an atomic RMW); blocking adds kernel transitions; convoys form when
hold time exceeds arrival interval.

**Detection:** `std::mutex` / `std::lock_guard` / POSIX mutex/spinlock
acquisition in a hot function.

**Escalations:** nested locks; acquisition inside a loop.

**Mitigation:** Single-writer designs, partitioned state, lock-free structures
where the invariants allow.

### FL013, Spin-Wait Without Pause

**Severity:** High &nbsp;|&nbsp; **Scope:** function (hot-path gated)

Fires on a tight loop (≤4 body statements, larger bodies are work
loops, not spins) that polls an atomic or volatile in its condition or
body with **no de-speculation or descheduling** in the loop. Poll forms
covered: `load`/`compare_exchange_*`, the **implicit conversion
operator** (`while (flag)` desugars to a `CXXConversionDecl` call,
name matching alone misses the most common spin), atomic operator
overloads (RMW-as-poll), `std::atomic_flag::test`/`test_and_set` (the
TAS spinlock idiom, C++ and C11 spellings), `__atomic_load*`, C11
`_Atomic` lvalues, and volatile reads. Compound conditions report
every polled variable. Relax family: `_mm_pause`/
`__builtin_ia32_pause`, `umwait`/`tpause`/`monitor`/`mwait` (the
modern *designed* wait), `std::this_thread::yield`/`sleep_*`,
`sched_yield`, `nanosleep`, C++20 blocking waits (`wait`/`wait_for`/
`wait_until`. Matched by bare name deliberately: a method named
`wait` declares descheduling intent, and a custom one that internally
bare-spins is flagged once inside its own body, not at every caller),
DPDK `rte_pause`/`rte_delay_us`, blocking demultiplexers
(`epoll_wait`, `poll`, `select`. An event loop is not a spin), or any
inline `asm` (opaque semantics, `cpu_relax()` and hand-rolled pause
both arrive as asm, so the benefit of the doubt goes to the author).
Bespoke backoff vocabularies (folly `Sleeper`, in-house
`Backoff::pause`) are declared once via `relax_function_patterns`
(fnmatch on plain or qualified names) rather than chased here.

Mechanism: the pauseless spin speculates polled loads far ahead and the
writer's eventual invalidation triggers a memory-order machine clear
(full pipeline flush. `machine_clears.memory_ordering`). That is the
whole mechanism. The rule also claimed the spinning logical core
monopolizes issue ports its SMT sibling needs; `sync_cost` places a
spinner on the sibling and measures 1.474 ns/op with and without PAUSE,
**0.0% recovered**, on Coffee Lake and again on Zen 3.
Grading: TAS spin 0.78 (each iteration is an RFO **write**, contenders
trade the line in Modified state where a TTAS spins on a Shared copy),
load-spin 0.75, CAS-retry 0.62 (short retry bursts are often
acceptable; unbounded ones need runtime data).

`smt_enabled` (config) is reported in the evidence and nothing else. It
used to move severity a notch on the sibling-starvation clause; since
that clause is refuted on both vendors, every finding grades Medium
whether SMT is on or off. The mitigation states the PAUSE trade with
the measurement behind it (64 cycles on Zen 3 against the ~140 widely
cited for Skylake-derived cores, which this project has not measured);
a deliberate bare spin on a
sub-microsecond signaling path is what `// lshaz-suppress FL013` is
for, and the diagnostic says so.

### FL014, Atomic on an Unprovably Aligned Address

**Base severity:** Critical &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** none

**Hardware mechanism, and it differs by target.** On x86-64 a LOCK-prefixed
operation spanning two cache lines cannot lock a single line, so the core falls
back to a serializing path costing roughly 2400 cycles: 3007ns against 6.0ns
aligned on Coffee Lake (**500x**) and 710ns against 2.21ns on Zen 3 (**321x**),
the largest single figure in `measured-constants.md`. The cost lands on the
issuing core. This rule used to claim the bus lock stalled every core on the
socket; `buslock_blast` put a victim on a neighbouring core sharing nothing
with the aggressor and measured 1.03x, under an aligned-atomic control that
moved further than the treatment did, so that claim is withdrawn on AMD and
remains untested on Intel. On ARM64 the exclusive and LSE atomics
require natural alignment, so the identical source raises an alignment fault
and the process takes SIGBUS. Detection is the same on both; only the
consequence and the mitigation branch.

**Detection:** an atomic operation (`AtomicExpr`, so C11 `_Atomic` and the
GNU builtins, plus `__sync_*`) whose pointer operand is an explicit cast from
a base narrower than the access. That is the shape where the pointer's type
asserts an alignment the source never established, and the compiler believes
it: `__atomic_fetch_add((long*)(buf+60), ...)` emits `lock incq buf+60` on
x86-64 and `ldxr/stxr` on ARM64.

**A packed `_Atomic` field is a different shape and is not this rule.** Clang
diagnoses it under `-Watomic-alignment` and lowers it to a libatomic call, so
it never reaches a LOCK prefix or an exclusive. Reporting it here would
duplicate an existing compiler warning about a hazard that does not occur.

**Grading follows what the offset proves**, using the same realizable-shift
sweep as the pair co-residency contract:

| Evidence | Severity | Tier |
|---|---|---|
| Crosses a line under every realizable base alignment | Critical | `proven` |
| Crosses under some realizable base alignment | Critical | `likely` |
| Offset not compile-time evaluable | Medium | `speculative` |

An address is aligned to `gcd(align(base), offset)`, so a cast whose offset
already covers the access asserts nothing untrue and is not reported.

---

## Memory allocation risks

### FL020, Heap Allocation in Hot Path

**Base severity:** Critical &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** hot path

**Hardware mechanism:** Allocator metadata contention (arena locks under
glibc), TLB pressure from page-granular growth, and page faults on first
touch. Severity is shaped by `--allocator`: glibc arena-lock contention rates
Critical; thread-cached allocators (tcmalloc/jemalloc/mimalloc) demote the
lock component but keep the TLB/fault component.

**Detection:** `new`/`delete`, `malloc`/`free`, growth-capable containers, and
allocation-prone type-erasure (`std::function`, `std::shared_ptr`) in hot
functions, plus any name in `allocator_function_patterns`.

**A wrapped allocator is invisible without that config.** Serious C codebases
reach libc through their own name: redis `zmalloc`, nginx `ngx_palloc`,
postgres `palloc`, git `xmalloc`, Linux `kmalloc`. redis makes 1310 `z*`
allocation calls against 503 raw libc ones, and FL020 reported 3 findings
until the wrappers were declared, then 489. Same trap as `atomic_type_names`,
different subsystem. IR-confirmed when the IR pass is enabled: an allocation the
optimizer eliminated is demoted rather than reported on faith.

**Escalations:** allocation inside a loop; size above `alloc_size_escalation`
(default 1032B, glibc's `tcache_max`); data-flow evidence the pointer escapes
(passed out, stored to a field, returned) or flows into a loop body.

**Cross-thread free, resolved in the reduce phase.** Same-thread alloc/free is
flat in thread count on every part measured, so allocation volume is not the
hazard; returning a block to an arena another thread owns is, at 25x the
same-thread round trip at 512B. Establishing it needs the allocation and the
free attributed to disjoint thread roles, and those routinely sit in different
TUs, so the map phase emits per-TU sets of which functions allocate and which
free each **pointee type** and the reduce phase joins them against the merged
thread-role verdicts. The type name is the join key because no pointer value
survives the TU split. A site whose type cannot be named is not recorded, which
leaves the conjunct unestablished rather than guessed. When it does establish,
the arena-contention claim carries the finding to High and the verdict names
the type.

**Mitigation:** Preallocate; arena/slab allocators; object pools. Where the
handoff is the design, free on the allocating thread and hand back an index.

### FL021, Large Stack Frame

**Base severity:** Medium &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** none

**Hardware mechanism:** A frame that spans multiple 4KB pages costs TLB
entries and evicts L1D lines on every call/return cycle through it.

**Detection:** Estimated frame size above `stack_frame_warn_bytes` (default
2048B). IR-confirmed against the real frame layout when available.

**Escalations:** deep call chains; recursion.

**Mitigation:** Move large buffers to heap, static, or thread-local storage.

---

## Dispatch risks

### FL030, Virtual Dispatch in Hot Path

**Base severity:** High &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** hot path

**Hardware mechanism:** Two separable costs. The inlining barrier is ~1ns and
is always paid. Misprediction adds up to ~8ns, but only when the receiver type
varies unpredictably: a monomorphic site, or a predictable cycle over eight
types, costs the same as one type. Candidate-type count is not the signal, and
the two costs have different fixes.

**Detection:** Virtual calls in hot functions. The IR pass is decisive here:
calls the optimizer devirtualized are strongly demoted (−0.25 confidence);
surviving indirect calls are confirmed (+0.10).

**Mitigation:** CRTP, `std::variant` + visitation, or sealed hierarchies that
enable devirtualization.

### FL031, std::function in Hot Path

**Base severity:** High &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** hot path

**Hardware mechanism:** Type erasure means indirect dispatch, an inlining
barrier, and a possible heap allocation for large captures.

**Detection:** `std::function` invocation in hot functions; IR confirms
whether the indirect call survived.

**Mitigation:** Template on the callable; `auto` lambdas; function pointers
for stateless callbacks.

---

## Structural design risks

### FL040, Centralized Mutable Global State

**Base severity:** High (Critical when atomic) &nbsp;|&nbsp; **Scope:** variable &nbsp;|&nbsp; **Gate:** none

**Hardware mechanism:** One global written by many threads is one contended
cache line for the whole process, plus guaranteed remote-node access for all
but one socket under NUMA.

**Detection:** Global or namespace-scope mutable variables. Write sites are
counted per TU across **all** write forms (plain assignment, `++`/`--`,
member writes through the global, and every atomic form, an `atomicIncr`
macro expanding to `__atomic_add_fetch` counts), with loop context recorded
per site.

**Severity grades on write pressure, not site count**, write rate is what
coherence sees:

| Evidence (global aggregate) | Verdict |
|---|---|
| Atomic + any in-loop write, or ≥4 flat sites | Critical |
| Atomic + 2–3 flat sites (start/stop lifecycle signature) | High |
| Plain type, multiple sites | High |
| Plain type, single in-loop site (one write path; concurrent writers would be a data race) | Informational |
| At most one flat write total (write-once: configuration, not contention) | Informational |

A single site inside a loop is never write-once, one *site* is not one
*write*.

**Cross-TU aggregation:** FL040 is map/reduce. Each TU emits candidates
unconditionally with per-TU write and loop-write counts; the pipeline sums
globally before grading. Verdicts are therefore identical regardless of
shard count.

**Mitigation:** Per-thread/per-core partitions with read-time aggregation;
dependency injection over ambient state.

### FL041, Contended Queue Pattern

**Base severity:** High (Critical when the pair is confirmed) &nbsp;|&nbsp; **Scope:** struct &nbsp;|&nbsp; **Gate:** none

**Hardware mechanism:** In an SPSC/MPMC ring, producers own `head` and
consumers own `tail`. On one line, every enqueue invalidates every consumer's
cached `tail` and vice versa. The queue serializes on coherence instead of
running concurrently.

**Detection, atomic path:** Atomic fields whose names match
head/tail/producer/consumer index conventions, co-resident on one line (pair
co-residency contract). Line-aligned records rate `Proven` (0.82); sub-line
alignment rates `Likely` (0.76).

**Detection, plain path:** A ring whose head and tail are plain indices is the
canonical contended queue (single-writer-per-index needs no atomicity) so
atomics are not required. This path is gated far harder, because scanning all
mutable fields for the name list matches `bytes_read`/`bytes_written` on every
stats struct in a server. It requires:

1. a thread-escape verdict (the atomic path takes the atomics as their own
   evidence),
2. one head-like *and* one tail-like index, and
3. those two to be the co-located pair, not merely present in the record.

A queue-ish type name alone does not qualify without atomics, `buffer` and
`cache` name plenty of non-queues. Confidence drops by 0.14, and the finding
reports only the head/tail pair so queue-index language is never attached to
unrelated arrays sharing the line.

**Not demoted by deliberate layout**. An aligned queue struct whose indices
still share a line is the bug this rule exists to catch.

**Mitigation:** Pad each index to its own line; per-core queues.

---

## Branching risks

### FL050, Deep Conditional Tree in Hot Path

**Base severity:** Medium &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** hot path

**Hardware mechanism:** Nested conditionals widen the misprediction surface. A
missed branch costs ~26 cycles and a predicted one is free. Target count does
not matter: a predictable indirect branch costs the same at 4096 targets as at
2, so BTB capacity is not the mechanism and case count is not a severity
signal. Cost requires the outcome to be data-dependent, which is a runtime
property, hence Medium without a profile.

**Detection:** Conditional nesting depth above `branch_depth_warn`
(default 4) in hot functions.

**Mitigation:** Table-driven dispatch; flatten to early returns; precompute
decision outcomes.

---

## NUMA risks

### FL060, NUMA-Unfriendly Shared Structure

**Base severity:** High &nbsp;|&nbsp; **Scope:** struct &nbsp;|&nbsp; **Gate:** none

**Hardware mechanism:** A remote access pays the interconnect on the critical
path, roughly +40ns over local, about 1.25x. Latency is the mechanism, not
bandwidth: one core reads local and remote memory at the same rate, so
widening the structure does not help and placement does. Pages are placed by
first touch, so a structure initialized on one node and written from all nodes
is remote for every other socket.

**Detection:** Shared mutable structures (≥256B) with thread-escape evidence
and unfavorable placement inference (`NUMATopology`: local-init, main-thread,
any-thread, interleaved, explicit-bind, unknown).

**Mitigation:** First-touch-aware initialization; per-socket replication;
explicit binding.

**Affinity respect:** when any TU calls a placement API
(`sched_setaffinity`, `pthread_setaffinity_np`, `mbind`,
`set_mempolicy`, `numa_*`), every FL060 finding demotes one severity
notch (−0.10 confidence) with the reason stated: the author is already
steering placement, and the first-touch default model must defer to
their policy. Same contract deliberate layout earns from FL002/FL090.

### FL070, TLB Pressure

**Base severity:** Medium &nbsp;|&nbsp; **Scope:** mixed &nbsp;|&nbsp; **Gate:** globals hot-gated, allocation sites ungated

**Hardware mechanism:** a working set spanning more base pages than the
dTLB covers (~64 L1 / ~1–2K L2 entries at 4KB) turns strided access into
page walks. 4-level lookups, each a potential cache-miss chain
(`dtlb_load_misses.walk_completed`). One 2MB hugepage entry covers 512×
the reach, but khugepaged collapses only 2MB-**aligned** virtual
extents: a 4MB array misaligned by a page backs 1 huge page instead of
2; exactly-2MB misaligned backs 0. Base alignment gates the mitigation.

**Detection, graded by what is provable:**

- *Hot-referenced globals* ≥2MB: fired from the hot accessor (statelessly;
  dedup collapses multiple accessors to the `VarDecl` location). Missing
  2MB alignment is named as the primary defect (Medium 0.65); a
  hugepage-aligned definition reports at the mitigation-respect floor
  (Informational 0.35).
- *Allocation sites* (`mmap` without `MAP_HUGETLB`, `posix_memalign` /
  `aligned_alloc` with sub-2MB alignment) with compile-time-provable
  sizes. When the exonerating argument (mmap flags, memalign alignment)
  is **not** compile-time evaluable, the site grades Speculative 0.30
  with the unprovable argument named. It may resolve safe at runtime,
  and unprovable is a tier, never a Medium assertion.
- With `--allocator jemalloc|tcmalloc`, allocation-path findings demote:
  those allocators chunk large allocations 2MB-aligned and THP-aware.
- In-tree `madvise`/`posix_madvise`/`mallopt` demotes all FL070 findings
  in post-processing (paging policy is author-managed), the same
  respect contract FL060 gives explicit affinity.

### FL061, Centralized Dispatcher Bottleneck

**Base severity:** High &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Gate:** hot path

**Hardware mechanism:** The cost is misprediction on the selector, ~26 cycles
when it is data-dependent. Arm count is nearly free: quadrupling it measured
+8% on thin arms and +0.02% on fat ones, so this is the mechanism FL050
already prices and dispatcher width adds almost nothing. Instruction-cache
pressure applies only once the inlined arms exceed L1i, which is untested.
Centralization also prevents per-core locality of handler state, a separate
argument from either.

**Detection:** High fan-out dispatcher functions in hot paths.

**Mitigation:** Partition dispatch tables; compile-time routing where the
message set is closed.

---

## Compound risks

### FL090, Hazard Amplification

**Base severity:** Critical &nbsp;|&nbsp; **Scope:** struct &nbsp;|&nbsp; **Gate:** none

**Hardware mechanism:** Latency multipliers interact super-additively on a
single structure: per-line RFO ownership transfer × multi-line footprint ×
cross-core sharing.

**Detection:** Requires all three signals on one record: spans ≥3 cache
lines, contains atomic fields, and has thread-escape evidence. Confidence is
`0.70 + 0.18 × contention` from the escape verdict. Escalations enumerate the
per-line atomic distribution, wide-granule straddlers, and mutable write
surface.

**Demotions:** deliberate-layout contract. The compound never outranks its
mitigation-adjusted components (FL001/FL002 demote → FL090 demotes with
them).

### FL091, Synthesized Interaction

**Severity:** derived &nbsp;|&nbsp; **Scope:** synthesized in post-processing

FL091 findings are not emitted by a rule; the pipeline joins existing
diagnostics that share an **entity**. The same `file:line` site, the same
`type_name` (this is how a struct-level FL002 joins a function-level FL011
that writes that struct's fields), or the same function.

Pairs take `max(parent severities)`, a demoted parent demotes the compound,
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

### FL092, Unapplied In-Tree Mitigation

**Severity:** inherited from component &nbsp;|&nbsp; **Scope:** synthesized in post-processing

Synthesized when three facts join: (1) an FL002 or FL090 finding carries
**cross-TU thread-role attribution** (its fields are written from provably
disjoint thread roles, see the thread-role reduce in
[architecture.md](architecture.md)); (2) the flagged type does **not** carry
the deliberate-layout idiom (explicit line alignment or trailing pad-to-line);
(3) the merged escape summary shows **other** types in the codebase that do.
The finding names an exemplar and the count. The codebase itself validates
both the hazard class and the fix idiom; the flagged struct never received
the treatment.

FL002 components join at pair granularity through their `pair_fields`
evidence; FL090 components join at struct granularity (its claim is
struct-wide, and very large structs put the disjoint pair beyond the pair
evidence bound). One compound per type; severity and confidence inherit
from the component, so mitigation-adjusted demotions are never outranked.

Thread-role attribution roots come from thread-creation detection
(`pthread_create`, `thrd_create`, `std::thread`/`std::jthread`,
`std::async`) plus the `thread_entry_patterns` / `main_function_patterns`
config globs. Required in codebases whose workers dispatch through
function-pointer tables (see [configuration.md](configuration.md)).
Attribution is deliberately strict: a function reachable from both roots
attributes to both roles, and any unknown writer defeats disjointness, so
mode-dependent dual-path functions (the same read/write helpers called
inline on main or offloaded to a worker) do not produce escalations.

---

## Compiler-observed findings

### C002, Loop-Invariant Load Not Hoisted

**Severity:** Medium, hot-path bounded &nbsp;|&nbsp; **Scope:** function &nbsp;|&nbsp; **Source:** LLVM optimization remarks

LICM could not hoist a load whose address does not change across the loop,
because a store in the body may alias it, so the load repeats every
iteration. The compiler recorded the decision; the analyzer did not infer it.

This class asserts no hardware effect, which is why it needs no workload to
be true. Every FL0xx rule claims a cost and has to defend it against a
machine the tool does not have.

**Collection.** The remark file rides the clang invocation the IR pass
already forks, via `-fsave-optimization-record`, and is read with
`llvm::remarks`. `--no-ir` disables this class with it. `-opt-record-passes`
narrows what the compiler serializes to the whitelisted passes: on one redis
TU that is 3.94 MB and 9524 records down to 0.57 MB and 1870, with all 1595
reportable records intact.

Findings are limited to functions the cross-TU hot verdict reaches or that
match `hot_function_patterns`. Deduplicated per (function, kind, file, line),
because overloads share a qualified name on both sides of the join and
merging them drops one, then capped at three sites per function with the
total in `sites_in_function`.

**Not collected.** `gvn/LoadClobbered` is 4822 of one file's 8264 missed
remarks and reports imprecise alias analysis rather than lost work.
`regalloc/LoopSpillReloadCopies` is a backend pass, and `-S -emit-llvm`
stops before codegen.

**Mitigation:** hoist the load into a local before the loop, or qualify the
pointers with `restrict` if they genuinely do not alias. `restrict` is a
promise to the compiler, so establish it rather than adding it to silence
the finding.

## Scan-health diagnostics

### B001, Broken scan

Not a hazard. B001 reports that the **scan itself was unsound**, so the
absence of findings in the affected translation units means nothing.

**Trigger.** The same header is missing from 3 or more TUs, detected by
fingerprinting `fatal error: 'x.h' file not found` across per-TU failure
reasons.

**Cause.** Almost always a project that must be built before it can be
scanned: generated headers from `configure_file`, a `custom_target`, or a
protobuf/flatbuffer step that has not run. `compile_commands.json` exists and
is valid, but the files it references do not yet.

**Emission.** Location `<pipeline>:0`, severity Medium, confidence 1.0,
evidence tier `speculative`. Evidence carries `missing_header` and
`tu_count`. It deliberately bypasses severity and evidence filters, a
report about a broken scan must not be filtered out by the flags used to
narrow that scan, but is re-sorted afterwards so the ordering contract holds.

**Action.** Build the project, then re-scan. Do not interpret a clean result
alongside a B001 as clean.

Related: exit code `2` means one or more TUs failed to compile at all, and
`failedTUErrors` in the JSON output names the reason per file.

## Querying rules from the CLI

```bash
lshaz explain --list     # all rules with base severities
lshaz explain FL002      # mechanism + mitigation for one rule
```
