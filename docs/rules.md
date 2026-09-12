# Rules Reference

Every rule maps to one hardware mechanism: cache, coherence, store buffer, TLB,
branch predictor, NUMA, or allocator. A check that cannot name its mechanism is
not a rule.

`lshaz explain <ID>` prints the mechanism and mitigation the diagnostics carry.
This file is the detection spec: what fires each rule, how evidence grades it,
and what it cannot prove.

## Index

Nineteen rules run during AST analysis. Five are synthesized in the reduce
phase, where the merged call graph and access sets exist. `C002` comes from the
compiler's remark stream; `B001` reports on the scan rather than the program.

| ID | Hazard | Fires on | Scope | Hot gate |
|---|---|---|---|---|
| FL001 | Cache geometry | Struct spanning multiple lines | struct | no |
| FL002 | False sharing | Independently written fields co-resident on one line | struct | no |
| FL005 | Redundant shared store | Unconditional store of a coarsened value into a file-scope object | store site | yes |
| FL010 | Atomic ordering | `seq_cst` where the ISA makes a weaker order free | function | yes |
| FL011 | Atomic contention | Atomic write sites on thread-escaping data | function | yes |
| FL012 | Lock contention | Mutex or spinlock acquisition | function | yes |
| FL013 | Spin-wait | Tight atomic poll with no pause, yield or backoff | function | yes |
| FL014 | Misaligned atomic | Atomic through a cast the source never proved aligned | function | no |
| FL020 | Heap allocation | Allocation, graded by allocator topology | function | yes |
| FL021 | Stack pressure | Frame above `stack_frame_warn_bytes` | function | no |
| FL030 | Virtual dispatch | Virtual call not devirtualized in IR | function | yes |
| FL031 | Type erasure | `std::function` invocation | function | yes |
| FL040 | Global state | File-scope mutable written from several sites | variable | no |
| FL041 | Contended queue | Head/tail-named index pair on one line | struct | no |
| FL050 | Deep conditional | Nesting above `branch_depth_warn` | function | yes |
| FL060 | NUMA locality | Shared mutable structure, unfavourable inferred placement | struct | no |
| FL061 | Centralized dispatch | One dispatcher routing to many handlers | function | yes |
| FL070 | TLB pressure | >=2MB hot global, or large mapping without hugepage provision | mixed | partial |
| FL090 | Amplification | Multi-line footprint, atomics and thread escape on one record | struct | no |
| FL003 | Striped array | Slots written under a thread-identity index, several per line | array | reduce |
| FL004 | Aggregation sweep | Loop reading every per-thread slot | array | reduce |
| FL006 | True sharing | One field stored by one thread role, read by another | field | reduce |
| FL091 | Interaction | Two or three eligible hazards on one entity | synthesized | no |
| FL092 | Unapplied mitigation | Attributed FL002/FL090 on a record lacking an in-tree idiom | synthesized | no |
| C002 | Missed hoist | LICM declined to hoist a loop-invariant load | function | yes |
| B001 | Broken scan | Same header missing from three or more TUs | scan | n/a |

Hot-path classification: [configuration.md](configuration.md#hot-path-annotation).
A gated rule emits nothing without a hotness signal.

## Shared contracts

**Claims bound severity.** Each rule decomposes its argument into claims
carrying an `effect`, the `precondition` it needs, the `state` of that
precondition, and the severity it `supports`. Ordinary claims are alternatives
and combine with `max`. A **gating** claim is a conjunct and caps the result;
hotness is the canonical gate. The pipeline clamps every finding to what its
claims establish, and `scan_test` fails any finding that omits its claims or
outranks an established one.

A claim is `unknown`, `established` or `refuted`. Unknown means nobody
decided, so it cannot promote and does not withdraw. Refuted means an evidence
source looked and found the precondition false: a refuted gate, or every
alternative refuted, retires the finding and names what did it. A rule's own
predicate coming out false is `unknown`, never `refuted`: not observing a
condition is not disproving it.

**Hot-path gating caps severity.** A profile or a declaration (`hot` attribute,
config glob) imposes no ceiling. Hotness inferred from nested loops or recursion
caps one grade below; from a single loop level, two grades below. Inference
establishes shape, not execution.

**Sharing needs a route to the same object.** Escape means threads reach the
*type*; false sharing needs two cores reaching one *object*:

```
hasSharingRoute = hasPublication || hasThreadWriters
                || (hasGlobalInstance && anyWriterOnThread)
```

Rules separate **standing** accesses (`g_stats.hits++`, a fixed object every
thread names) from **handed** ones (`io->len = n`, whatever the caller passed).
A per-request object handed to one owner at a time is never falsely shared
however many functions write it; writer counts cannot express that, the
base-expression root can. The read side is tracked because a setter writing
through its parameter looks handed while its readers name one global instance,
and only the reads establish that both touch a single object.

**Contention needs two cores, not two functions.** A thread entry spawned in a
loop, or from several call sites, runs on several threads at once, so one writer
function suffices.

**Atomic coverage.** Counting as atomic operations (FL010, FL011) and as writes
(FL002, FL040): `std::atomic` and `std::atomic_ref` methods and operators; C11
`_Atomic` lvalue `++`, `--`, `=`, compound assignment; `__c11_atomic_*` and
`__atomic_*` builtins, whose ordering argument is evaluated when constant and
skipped when runtime-variable; `__sync_*`; and opaque wrappers named in
`atomic_type_names`. A codebase wrapping its atomics in a plain typedef has
neither spelling anywhere, so without that config the fields do not exist as far
as detection is concerned.

**Deliberate-layout demotion** (FL001, FL002, FL090). Record alignment at or
above the line size, or a trailing pad bringing the record to an exact line
multiple, caps the finding at Medium with the reason in the escalation trace.
The finding still reports: single-writer discipline is an assumption the
analyzer cannot verify. FL041 is exempt, since head/tail naming implies
producer/consumer roles and an aligned record with unpadded indices is the bug.

**Pair co-residency.** Two fields pair only if a realizable base alignment
places both on one line: for sub-line records the analyzer sweeps every base
shift at multiples of the record alignment, which for line-aligned records
reduces to the exact same-line test. Fields more than a line apart never pair.
Bitfields are excluded, because a bitfield's exported extent is its declared
type's rather than the bits it owns.

---

## FL001, Cache Line Spanning Struct

**High** | struct | no gate

**Detects.** Field-by-field layout onto lines via `ASTRecordLayout`, including
base subobjects and nested records, past `cache_line_span_warn` /
`cache_line_span_crit`.

**Grades.** Critical needs written fields spanning three or more lines, each
its own RFO. A record whose written fields cluster on fewer lines keeps High and
says the remaining span is footprint, not coherence. No observed writes is
absence of evidence and must not outrank the case where writes were counted.

**Limits.** A sub-line record spans lines only under adverse placement, so it
caps at Medium. Atomics spread across lines are FL002's prescribed fix, not an
escalation here.

## FL002, False Sharing Candidate

**Critical** | struct | no gate

**Detects.** All of: thread-escape evidence for the type; a mutable co-resident
pair; and concurrency evidence, either an atomic field or proven distinct writer
functions for the pair.

**Atomicity is not the gate.** Striped and role-partitioned fields are
single-writer-per-slot, so the dominant idiom is deliberately non-atomic: no
data race, pure coherence traffic. A non-atomic record keeps the severity and
takes lower confidence, since concurrent execution of the writers is unproven.

An **intra-array** pair is two elements of one array on one line. An array is a
single `FieldDecl`, so pairing distinct decls cannot express it, and co-residency
alone is not contention there (padding arrays share lines and are never written),
so it additionally requires distinct writers reaching the array.

| Evidence | Severity | Confidence |
|---|---|---|
| Atomic pair, line-aligned record | Critical | 0.88 `proven` |
| Atomic pair, sub-line alignment | Critical | 0.80 `likely` |
| Atomics present, no atomic pair | High | 0.68 |
| Mutable pairs only | High | 0.55 |

**Write evidence**, on top of the ladder. Geometry cannot distinguish parallel
writers from an init-only pattern, so write sites are attributed to the
enclosing function, constructor member-init lists excluded. Both fields written
from distinct functions: +0.06, cap 0.95. One function, or one side only:
unchanged, since the init signature must not boost. No observed writes: Critical
caps at High, −0.08, reported as structural evidence only, because writers in
another TU carry their own instance and outrank this one at dedup.

**Cross-TU pairs.** The reduce phase re-forms co-residency from serialized field
offsets and joins it against the merged writer and reader sets, adding evidence
to an existing finding or emitting one where no TU held both halves. Pairs rank
by mechanism, not field order: a neighbour read somewhere and written nowhere in
the merged program outranks everything, since one writer against N reading cores
costs N re-fetches per store with nothing coming back and relocating a field
nothing writes cannot break anything. That claim needs the neighbour to be a
plain scalar, since an aggregate mutated through its address shows no writer and
the finding would say to relocate a live mutex, and it needs a confirmed-hot
writer, since co-location with a field written twice at startup costs nothing.

**Demotions.** Deliberate layout, plus a density conjunct: contended-RMW cost
decays with inter-write spacing only while both writers share a last-level
cache, and not at all across coherence domains, so `coherence_domains` is the
predicate and socket count is not. A chiplet part is one socket with several
domains. Unknown declines to demote.

A **refcount-only** record (one atomic matching a refcount pattern, sharing
lines only with immutable data) and a **self-guarded** one (own sync primitive,
no atomics) report at reduced severity rather than suppressing, since per-field
lock coverage is not provable here.

## FL003, Per-Thread Array False Sharing

**High** | array | reduce phase

**The gate is index provenance, not element atomicity**, because striping makes
each slot single-writer and these arrays are routinely plain scalars. A write
counts as striped when its subscript is `thread_local`-derived (the value *is*
the identity) or matches a narrow identifier set (`tid`, `thread_index`,
`*_tid`, `sched_getcpu`), extended by `thread_index_patterns`. The set stays
narrow because generic spellings are ambiguous: `slot` names per-thread arrays
and hash buckets equally often.

**Whose identity the subscript names decides the grade.** `arr[c->tid]` reads
the id out of an object the caller handed in, so it names that object's *owner*
and one thread can drive every slot. Owner-indexed findings with no established
second role cap at Medium, lose 0.15 confidence, and carry
`index_identity: owner`. Demoted rather than dropped: a worker that stamps
itself into the object makes the owner id its own.

Loop-induction subscripts are aggregation sweeps (FL004), not multi-thread
evidence. Pointer aliases (`T *p = &arr[K]`) retarget onto the array.

| Evidence | Severity |
|---|---|
| Writers provably span two thread roles | Critical |
| Thread-identity subscript, `thread_local`-derived or atomic elements or >=2 writers | High |
| Thread-identity subscript from the identifier set alone | Medium |

**Fix selection is an ROI decision**, since padding buys isolation with L1D
footprint: relocate into a line-aligned per-thread structure if one exists
in-tree (same isolation, no added footprint); full padding for hot writes under
10% of L1D; head padding above that, isolating the hottest slot; and no fix at
all for non-hot writes above 10%, reported Informational because the traffic is
real and the fix costs more.

Frequency comes from the hot-path oracle, refined by `dispatch_path_patterns`
and `tick_path_patterns`. Named tiers outrank oracle hotness, which reaches most
functions by glob or propagation and cannot separate a per-connection setup
routine from the per-command path in the same file. **Unknown frequency does not
demote**: unestablished is not proven-low, so the finding keeps its evidence
severity and names what would refine it.

**Mitigation respect.** A stride that is a line multiple is full isolation and
never fires. A line-aligned base **plus a padded index origin** isolates slot 0
only and caps at Medium with the residual stated. Base alignment alone is not
mitigation: it separates slot 0 from the preceding symbol and does nothing for
slot 0 against slot 1.

## FL004, Aggregation Sweep Over Per-Thread Slots

**High** | array | reduce phase

Padding cannot fix this and increases the line count, so the correctly padded
array FL003 skips is exactly where it lives.

**Gates.** At least one thread-identity writer, since with no writer no line is
Modified and the sweep downgrades nothing; not main-thread-only, since one
thread owning every slot means no line is held elsewhere; at least four lines
swept.

**Grades** on the sweep's call rate: hot over sixteen lines Critical, hot High,
dispatch Medium, tick Informational, because sweeping on a stats timer is the
correct design.

**Limits.** The reported line count is the array's declared bound, an upper
bound on any one loop: a loop stopping at a configured thread count touches
fewer.

## FL005, Redundant Store to a Shared Line

**Medium** | store site | hot gate

**Detects.** The destination roots at a file-scope object, its value is a
contraction (integer division or right shift by a literal, or a predicate), and
no enclosing condition tests the destination. The contraction is what makes the
claim provable: a value divided by K changes at most once per K stores.

**The repetition conjunct is settled in the reduce phase**, since whether a
store runs more than once is a property of the merged call graph. The rule ships
it unestablished; the reduce pass confirms when the function is reached from a
loop or two call sites, drops the finding when reached once from `main`, and
leaves it unknown when no call edge was recorded, because a function reached only
through a pointer table has no caller in the graph.

**Any early exit ahead of the store counts as a rate bound.** A clock cache that
returns when the second has not changed, then stores a derived value, is already
guarded once per second while nothing tests the destination. Requiring the guard
to name the destination reports it anyway. That costs findings where the exit is
unrelated, which is the direction that does not invent them.

**Limits.** What is removed is traffic, not necessarily latency, and a guard
that reads the shared location back can cost more than it saves at low thread
counts. Plain stores therefore grade Informational, atomic ones Medium.

## FL006, Cross-Thread Read of a Recurrently Written Field

**High** | field | reduce phase

One field, stored by one thread role and read without being written by another.
FL002 covers two *distinct* fields colliding, where padding fixes it because
they never needed to be neighbours; here the readers want the value, so padding
only relocates the transfer. Different fix, and no pair of field names to
describe it with, which is why it is its own rule.

**Gates**, counted per rejection so a silent rule stays distinguishable from a
clean program: a thread route to the type; the field both written and read; the
writes observable, meaning a plain scalar or an atomic, since an aggregate
mutated through its address shows no writer; at least one standing access; the
store recurring by loop or by rate, or the line settles into Shared after the
first read; at least one reader that never writes; and the roles spanning more
than one.

Object freshness and writer hotness are deliberately **not** gates. An object
handed between threads is contended on exactly the fields they hand it with, and
hotness would import the oracle's thresholds into a rule that does not use them.
Both survive as evidence.

## FL010, Overly Strong Atomic Ordering

**High** | function | hot gate

**Detects.** Any atomic form whose effective ordering is `seq_cst`, including
the implicit `seq_cst` of an argument-less `store()`, C11 `_Atomic` operators
and `__sync_*`. The ordering argument participates only when it is a
`memory_order` enum or a constant evaluating to one.

| Target | Store | RMW | Load |
|---|---|---|---|
| x86-64 | High 0.85 | Medium 0.55 | not reported, free under TSO |
| ARM64 | Critical 0.90 | High 0.80 | High 0.80 |

**Escalations.** A store inside a loop goes Critical 0.92 for the per-iteration
drain. Data-flow evidence that an atomic load feeds a branch marks the CAS-retry
or spin shape.

## FL011, Atomic Contention Hotspot

**Critical** | function | hot gate

**Detects.** Atomic **write** sites, loads and pure fences excluded, in hot
functions on data with thread-escape evidence. The owning record's qualified
name is captured as `type_name`, which is how FL011 joins struct-level findings
during FL091 synthesis.

**Scope.** FL011 is function-level (write sites), FL002 struct-level (layout). A
record triggers FL002 without FL011 when no hot function writes its atomics, and
the reverse.

**Escalations.** Several atomic writes per loop iteration; adjacent atomics in
one record.

## FL012, Lock in Hot Path

**Critical** | function | hot gate

**Detects.** `std::mutex`, `std::lock_guard`, POSIX mutex and spinlock
acquisition, plus `lock_function_patterns` / `unlock_function_patterns` for
project wrappers. Acquire and release are separate lists because nesting depth
is a count, and inferring the release side from the spelling desynchronizes it
on the first wrapper that does not say "unlock".

A hand-rolled spin lock has no POSIX call and no attribute, only a mechanism: an
acquire is an atomic RMW whose loop exits on success, the release the same RMW
with no loop. Those pair by the parameter's pointee type, which is what
separates a lock from a lock-free retry loop running the identical CAS, since a
queue push has no release counterpart on the same type.

**Escalations.** Nested locks; acquisition inside a loop.

## FL013, Spin-Wait Without Pause

**High** | function | hot gate

**Detects.** A tight loop, at most four body statements since larger bodies are
work loops, polling an atomic or volatile with no de-speculation or descheduling
anywhere in it.

Poll forms: `load`, `compare_exchange_*`, the implicit conversion operator
(`while (flag)` desugars to a `CXXConversionDecl` call, which name matching
alone misses), atomic operator overloads, `atomic_flag::test` and
`test_and_set` in both C++ and C11 spellings, `__atomic_load*`, C11 `_Atomic`
lvalues, volatile reads. Compound conditions report every polled variable.

Relax forms: `_mm_pause` and `__builtin_ia32_pause`; `umwait` / `tpause` /
`monitor` / `mwait`; `std::this_thread::yield` and `sleep_*`; `sched_yield`;
`nanosleep`; the C++20 `wait` / `wait_for` / `wait_until`; `rte_pause` and
`rte_delay_us`; blocking demultiplexers (`epoll_wait`, `poll`, `select`, since
an event loop is not a spin); and any inline `asm`, whose semantics are opaque
and where hand-rolled pause arrives. The blocking waits match on bare name
deliberately: a method named `wait` declares descheduling intent, and a custom
one that bare-spins is flagged inside its own body rather than at every call
site. Bespoke backoff vocabularies go in `relax_function_patterns`.

**Grades.** TAS spin 0.78, because each iteration is an RFO **write** and
contenders trade the line Modified where a test-and-test-and-set spins read-only
on a Shared copy. Load spin 0.75. CAS retry 0.62, since short retry bursts are
often correct and unbounded ones need runtime data.

**Limits.** The claim that a spinning logical core monopolizes issue ports its
SMT sibling needs ships **unestablished**, so severity does not depend on
`smt_enabled`, which appears in the evidence and nowhere else. The claim stays
in the finding so the verdict names what it did not establish. PAUSE latency
differs by roughly an order of magnitude between vendors, so a fixed spin count
does not port.

## FL014, Atomic on an Unprovably Aligned Address

**Critical** | function | no gate

**Detects.** An atomic operation (`AtomicExpr`, so C11 `_Atomic` and the GNU
builtins, plus `__sync_*`) whose pointer operand is an explicit cast from a base
narrower than the access. The cost lands on the issuing core only; this rule
makes no socket-wide claim. That is the shape where the pointer's type asserts an
alignment the source never established and the compiler believes it:
`__atomic_fetch_add((long*)(buf+60), ...)` emits `lock incq buf+60`.

A packed `_Atomic` field is a different shape and not this rule: Clang diagnoses
it under `-Watomic-alignment` and lowers it to a libatomic call, so it reaches
neither a LOCK prefix nor an exclusive.

| Evidence | Severity | Tier |
|---|---|---|
| Crosses a line under every realizable base alignment | Critical | `proven` |
| Crosses under some realizable base alignment | Critical | `likely` |
| Offset not compile-time evaluable | Medium | `speculative` |

An address is aligned to `gcd(align(base), offset)`, so a cast whose offset
already covers the access asserts nothing untrue and is not reported.

## FL020, Heap Allocation in Hot Path

**Critical** | function | hot gate

**Detects.** `new` / `delete`, `malloc` / `free`, growth-capable containers,
allocation-prone type erasure, and any name in `allocator_function_patterns`.
The vocabulary prepass also derives the project's own wrapper names by closing
the allocator set over return-forward edges from the libc seeds, so a wrapper is
discovered rather than declared; a C tree reaching libc only through its own
names is otherwise almost invisible here. IR-confirmed when the IR pass runs: an
allocation the optimizer eliminated is demoted rather than reported on faith.

**Grades.** `--allocator` shapes it: glibc arena contention rates Critical,
thread-caching allocators demote the lock component and keep the TLB and fault
component.

**Escalations.** Allocation inside a loop. Size above `alloc_size_escalation`,
default `1032` at glibc's `tcache_max`, above which the request misses the
per-thread cache and takes the arena path. Data-flow evidence the pointer
escapes or flows into a loop body.

**Cross-thread free, resolved in the reduce phase.** Same-thread alloc/free is
flat in thread count, so volume is not the hazard; returning a block to an arena
another thread owns is. That needs allocation and free attributed to disjoint
thread roles, which routinely sit in different TUs, so the map phase emits
per-TU sets of which functions allocate and which free each **pointee type** and
the reduce phase joins them against the merged role verdicts. The type name is
the join key because no pointer value survives the split. A site whose type
cannot be named is not recorded, leaving the conjunct unestablished rather than
guessed.

## FL021, Large Stack Frame

**Medium** | function | no gate

**Detects.** Estimated frame above `stack_frame_warn_bytes`, default `2048`.
IR-confirmed against the real frame layout when available, which suppresses the
finding outright when the actual frame is below threshold.

**Limits.** A sub-page frame sits on the most reliably resident memory in the
process, so the claim there is the L1D lines it touches on entry, not TLB
working-set growth.

**Escalations.** Deep call chains; recursion.

## FL030, Virtual Dispatch in Hot Path

**High** | function | hot gate

**Detects.** Virtual calls in hot functions. The IR pass is decisive: a
devirtualized call is strongly demoted (−0.25 confidence), a surviving indirect
call confirmed (+0.10). The reduce phase additionally checks whether anything in
the program overrides the callee; if nothing does, dispatch is monomorphic
program-wide and the misprediction term is absent.

**Limits.** A loop multiplies how often the lost inline is paid, not the cost of
each dispatch.

## FL031, std::function in Hot Path

**High** | function | hot gate

**Detects.** `std::function` invocation in hot functions; IR confirms whether
the indirect call survived. A `std::function` **parameter** with no use site in
the body reports separately: the erasure is in the signature, so the indirect
call is certain while neither the allocation nor the per-iteration cost can be
attributed from there.

## FL040, Centralized Mutable Global State

**High**, Critical when atomic | variable | no gate

**Detects.** File- or namespace-scope mutable variables. Write sites are counted
per TU across every write form, including member writes through the global and
every atomic form, with loop context recorded per site.

**Grades on write pressure, not site count**, because rate is what coherence
sees, applied to the **global** sum:

| Evidence | Verdict |
|---|---|
| Atomic and any in-loop write, or >=4 flat sites | Critical |
| Atomic and 2-3 flat sites (start/stop lifecycle) | High |
| Plain type, several sites | High |
| Plain type, one in-loop site: one write path, concurrent writers would be a data race | Informational |
| At most one flat write total: configuration, not contention | Informational |

One site inside a loop is never write-once. One *site* is not one *write*.

**Cross-TU aggregation.** FL040 is the map/reduce reference: each TU emits
candidates unconditionally with per-TU write and loop-write counts, and the
pipeline sums globally before grading, so verdicts are identical at any shard
count.

## FL041, Contended Queue Pattern

**High**, Critical when confirmed | struct | no gate

**Detects, atomic path.** Atomic fields whose names match head/tail/
producer/consumer conventions, co-resident per the pair contract. Line-aligned
records rate `proven` 0.82, sub-line `likely` 0.76.

**Detects, plain path.** A ring whose indices are plain is the canonical
contended queue, since single-writer-per-index needs no atomicity. Gated far
harder, because scanning all mutable fields against a name list matches
`bytes_read` on every stats record. Requires a thread-escape verdict, one
head-like **and** one tail-like index, and those two to be the co-located pair
rather than merely present. A queue-ish type name alone does not qualify without
atomics. Confidence drops 0.14, and the finding reports only the head/tail pair
so queue language is never attached to unrelated arrays on the line.

**Not demoted by deliberate layout.** An aligned queue record whose indices
still share a line is the bug this rule exists for.

## FL050, Deep Conditional Tree in Hot Path

**Medium** | function | hot gate

**Detects.** Nesting above `branch_depth_warn`, default `4`, emitted only for
the deepest nesting point in a function.

**Limits.** A switch whose every arm returns a constant is a lookup, not a
branch tree: the compiler emits a jump table into trivial stubs or an indexed
array with no branch at all, so the cost does not scale with case count and this
mechanism does not apply.

## FL060, NUMA-Unfriendly Shared Structure

**High** | struct | no gate

**Detects.** Shared mutable structures at or above 256B with thread-escape
evidence and unfavourable placement inference: local-init, main-thread,
any-thread, interleaved, explicit-bind, or unknown.

**Limits.** On one socket there is no remote node and the mechanism is null, so
the rule reports nothing. Socket count is a deployment property, unreadable from
source, so it comes from config; `0` leaves the assumption labelled in the
output.

**Affinity respect.** A TU calling a placement API (`sched_setaffinity`,
`pthread_setaffinity_np`, `mbind`, `set_mempolicy`, `numa_*`) demotes every
FL060 finding one notch with −0.10 confidence and the reason stated: the author
is steering placement and the first-touch default model must defer.

## FL061, Centralized Dispatcher Bottleneck

**High** | function | hot gate

**Detects.** High fan-out in hot functions, counted in real transfers of
control. Compiler builtins and `always_inline` callees cost neither a BTB entry
nor an I-cache line at a callee, so counting them reads a hand-vectorised kernel
as a wide dispatcher.

## FL070, TLB Pressure

**Medium** | mixed | globals gated, allocation sites ungated

**Detects**, graded by what is provable:

- **Hot-referenced globals** at or above 2MB, fired from the hot accessor since
  a `VarDecl` cannot see its readers; dedup collapses accessors to the
  declaration. Missing 2MB alignment is the primary defect (Medium 0.65); a
  hugepage-aligned definition reports at the mitigation-respect floor
  (Informational 0.35).
- **Allocation sites** with compile-time-provable sizes: `mmap` without
  `MAP_HUGETLB`, or `posix_memalign` / `aligned_alloc` with sub-2MB alignment.
  When the exonerating argument is not compile-time evaluable the site grades
  Speculative 0.30 and names what could not be proved, because it may resolve
  safe at runtime and unprovable is a tier rather than a Medium assertion.
- Large-mapping wrappers come from `mapping_function_patterns` as `name` or
  `name:N`, `N` being the zero-based size parameter. The index is required
  rather than inferred: an aligned-allocation wrapper takes the alignment first,
  and a first-integer-wins rule would grade that as the mapping size.

**Demotions.** `--allocator jemalloc|tcmalloc` demotes allocation-path findings,
since those chunk large allocations 2MB-aligned and THP-aware. In-tree
`madvise` / `posix_madvise` / `mallopt` demotes every FL070 finding in
post-processing, the same respect contract FL060 gives explicit affinity.

## FL090, Hazard Amplification

**Critical** | struct | no gate

**Detects.** All three on one record: spans three or more lines, contains
atomics, has thread-escape evidence. Confidence is `0.70 + 0.18 x contention`
from the escape verdict. Escalations enumerate the per-line atomic distribution,
wide-granule straddlers, and mutable write surface.

**Limits.** A single atomic occupies one line at runtime however many buckets
alignment uncertainty smears it across, so amplification needs the RFO surface
itself to span lines.

**Demotions.** Deliberate layout. The compound never outranks its
mitigation-adjusted components: when FL001 or FL002 demote, FL090 demotes too.

## FL091, Hazard Interaction

Derived severity | synthesized

Not emitted by a rule. The pipeline joins diagnostics sharing an **entity**: the
same `file:line`, the same `type_name` (which is how a struct-level FL002 joins
a function-level FL011 writing that record's fields), or the same function.

Pairs take `max(parent severities)`, so a demoted parent demotes the compound,
and `min(parent confidences) x (1 + interaction threshold)` capped at 1.0.
Triples rate Critical. One compound per (template, participant set) regardless
of how many entity keys the participants share.

| Template | Components |
|---|---|
| IX-001 | CacheGeometry x AtomicContention |
| IX-002 | FalseSharing x AtomicContention |
| IX-003 | AtomicOrdering x AtomicContention |
| IX-004 | AtomicContention x NUMALocality |
| IX-005 | LockContention x HeapAllocation |
| IX-006 | VirtualDispatch x DeepConditional |
| IX-007 | CacheGeometry x AtomicContention x NUMALocality |

## FL092, Unapplied In-Tree Mitigation

Severity inherited from the component | synthesized

Three facts join: an FL002 or FL090 finding carries **cross-TU thread-role
attribution**, meaning its fields are written from provably disjoint roles; the
flagged type does **not** carry the deliberate-layout idiom; and the merged
escape summary shows **other** types in the tree that do. The finding names an
exemplar and the count, so the codebase itself validates both the hazard class
and the fix.

FL002 components join at pair granularity through `pair_fields`; FL090 at struct
granularity, since its claim is struct-wide and a very large record puts the
disjoint pair beyond the pair-evidence bound. One compound per type, inheriting
severity and confidence so mitigation-adjusted demotions are never outranked.

Attribution is deliberately strict: a function reachable from both roots
attributes to both roles and any unknown writer defeats disjointness, so a
dual-path helper called inline on main and offloaded to a worker produces no
escalation. Roots come from thread-creation detection plus the
`thread_entry_patterns` and `main_function_patterns` globs, which a codebase
dispatching through function-pointer tables needs.

## C002, Loop-Invariant Load Not Hoisted

Medium, hot-bounded | function | LLVM optimization remarks

LICM declined to hoist a load whose address does not change across the loop,
because a store in the body may alias it. The compiler recorded the decision;
the analyzer did not infer it. That also makes this the one class asserting no
hardware effect, so it needs no workload to be true.

**Collection.** The remark file rides the clang invocation the IR pass already
forks, via `-fsave-optimization-record`, read with `llvm::remarks`. `--no-ir`
disables the class. `-opt-record-passes` narrows what the compiler serializes to
the whitelisted passes, since a full remark stream runs to megabytes per TU.
Findings are limited to functions the cross-TU hot verdict reaches or that match
`hot_function_patterns`, deduplicated per (function, kind, file, line) because
overloads share a qualified name on both sides of the join, then capped at three
sites per function with the total in `sites_in_function`.

**Not collected.** `gvn/LoadClobbered` reports imprecise alias analysis rather
than lost work. `regalloc/LoopSpillReloadCopies` is a backend pass, and
`-S -emit-llvm` stops before codegen.

## B001, Broken scan

Not a hazard. B001 reports that the scan itself was unsound, so the absence of
findings in the affected translation units means nothing.

**Trigger.** The same header missing from three or more TUs, fingerprinted from
`fatal error: 'x.h' file not found` across per-TU failure reasons. Almost always
a project that must be built before it can be scanned: generated headers from
`configure_file`, a `custom_target`, or a protobuf step that has not run.
`compile_commands.json` is valid; the files it references do not exist yet.

**Emission.** `<pipeline>:0`, Medium, confidence 1.0, tier `speculative`, with
`missing_header` and `tu_count` in the evidence. It bypasses the severity and
evidence filters by design, since a report about a broken scan must not be
filtered out by the flags used to narrow that scan, and is re-sorted afterwards
so the ordering contract holds.

Exit code `2` means one or more TUs failed to compile; `failedTUErrors` in the
JSON output names the reason per file.

## Querying rules

```bash
lshaz explain --list     # every rule with its base severity
lshaz explain FL002      # mechanism and mitigation for one rule
```
