# Rules Reference

lshaz ships 15 rules, each targeting a specific microarchitectural hazard class in C and C++ codebases. Every rule must map to a concrete hardware mechanism — cache, coherence, store buffer, TLB, branch predictor, NUMA, or allocator.

## Rule Index

| ID | Hazard Class | What It Detects | Scope |
|---|---|---|---|
| FL001 | Cache geometry | Struct spanning multiple 64B cache lines; fields straddling line boundaries | Struct |
| FL002 | False sharing | Mutable fields sharing a cache line in a type with thread-escape evidence | Struct |
| FL010 | Atomic ordering | `seq_cst` ordering where `release`/`acquire` is sufficient on x86-64 TSO | Function (hot) |
| FL011 | Atomic contention | Atomic write sites likely to generate cross-core RFO traffic | Struct |
| FL012 | Lock contention | `std::mutex`, `std::lock_guard`, or similar in a hot function | Function (hot) |
| FL020 | Heap allocation | `operator new`, `operator delete`, `malloc`, `free` in hot function. Severity adjusted by allocator topology. | Function (hot) |
| FL021 | Stack pressure | Function stack frame exceeding configurable threshold (default 2048B) | Function |
| FL030 | Virtual dispatch | Virtual method call or indirect call via vtable in a hot function | Function (hot) |
| FL031 | `std::function` | `std::function` invocation in a hot function (type erasure + indirect call) | Function (hot) |
| FL040 | Global mutable state | Global or namespace-scope mutable variable accessible without thread confinement | Declaration |
| FL041 | Contended queue | Producer/consumer atomic fields (`head`/`tail`) on the same cache line | Struct |
| FL050 | Deep conditional | Conditional nesting depth exceeding threshold (default 4) in a function | Function |
| FL060 | NUMA locality | Shared mutable structure with unfavorable inferred NUMA placement | Struct |
| FL061 | Centralized dispatch | Single dispatcher function routing to many handlers (branch predictor stress) | Function (hot) |
| FL090 | Hazard amplification | Compound structural hazard: cache line spanning + atomic contention + thread escape | Struct |
| FL091 | Synthesized interaction | Post-hoc correlation: multiple rules fire at the same site (from InteractionEligibilityMatrix) | Synthesized |

---

## Structural Cache Risks

### FL001 — Cache Line Spanning Struct

**Severity:** High (Critical if shared-write)

**Hardware Mechanism:** L1/L2 cache line footprint expansion. Increased eviction probability. Higher coherence traffic under multi-core writes.

**Detection:** Compute `sizeof(T)`. Flag if > 64 bytes with hot-path evidence. Escalate if > 128 bytes or contains atomic/mutable fields with thread escape.

**False Positives:** Read-only large structs. Thread-local instances.

**Mitigation:** Convert AoS → SoA. Split hot/cold fields. `alignas(64)` where justified.

**Example:**

```cpp
struct OrderBookLevel {
    uint64_t px[8];
    uint64_t qty[8];
    uint64_t flags[4];
};
// sizeof = 160B → spans 3 cache lines
```

Fix: split into `OrderBookHot` (one cache line) and `OrderBookCold`.

### FL002 — False Sharing Candidate

**Severity:** Critical

**Hardware Mechanism:** MESI invalidation ping-pong across cores due to shared cache line writes. Each write by one core forces invalidation in all other cores' L1/L2, triggering RFO traffic.

**Detection:** Struct contains 2+ mutable fields on the same cache line with thread-escape evidence.

**Escalation:** Presence of `std::atomic` fields. Used in tight loop.

**False Positives:** Struct always accessed under same-thread confinement.

**Mitigation:** Separate fields onto different cache lines. Pad to 64B. Use per-thread storage.

**Example:**

```cpp
// Before:
struct Counters {
    std::atomic<uint64_t> head;
    std::atomic<uint64_t> tail;
};

// After:
struct Counters {
    alignas(64) std::atomic<uint64_t> head;
    alignas(64) std::atomic<uint64_t> tail;
};
```

---

## Synchronization Risks

### FL010 — Overly Strong Atomic Ordering

**Severity:** High

**Hardware Mechanism:** Full memory fences emitted for `memory_order_seq_cst` cause pipeline serialization and store buffer drains.

**Detection:** `std::atomic` operations with `memory_order_seq_cst` in hot path.

**Escalation:** Inside tight loop. Multiple atomics in same function. Data-flow: atomic load result feeds branch condition (CAS retry loop or spin-wait pattern).

**False Positives:** Correctness requires seq_cst.

**Mitigation:** Use `memory_order_release`/`acquire`. Use relaxed where safe.

**Example:**

```cpp
// Before:
seq.store(v); // implicit seq_cst

// After:
seq.store(v, std::memory_order_release);
```

On x86-64 TSO, `release` stores do not require `MFENCE` or `LOCK`-prefixed instructions.

### FL011 — Atomic Contention Hotspot

**Severity:** Critical

**Hardware Mechanism:** Cache line ownership thrashing. Store buffer pressure. Cross-core invalidation storms.

**Detection:** Atomic variable written in hot path with thread-escape evidence. Requires hot-path classification (see [Hot Path Annotation](configuration.md#hot-path-annotation)).

> **Note:** FL011 is a *function-level* rule that detects atomic write contention in hot code paths. FL002 is a *struct-level* rule that detects false sharing from layout analysis. A struct may trigger FL002 (layout hazard) without triggering FL011 if no hot-path function writes to its atomic fields.

**Escalation:** Multiple atomic writes per iteration. Adjacent atomics in same struct.

**Mitigation:** Shard per-core. Use batching. Redesign ownership model.

### FL012 — Lock in Hot Path

**Severity:** Critical

**Hardware Mechanism:** Lock convoy. Kernel transition (if blocking). Cache line contention on lock word.

**Detection:** `std::mutex` / spinlock acquired in hot path.

**Escalation:** Nested locks. Lock inside loop.

**Mitigation:** Lock-free design. Single-writer model. Partition state.

---

## Memory Allocation Risks

### FL020 — Heap Allocation in Hot Path

**Severity:** Critical

**Hardware Mechanism:** Allocator lock contention. TLB pressure. Page faults. Fragmentation.

**Detection:** `new`/`delete`, `std::vector` growth, `std::function`, `std::shared_ptr`, `malloc` in hot path. IR-confirmed when available.

**Escalation:** Allocation inside loop. Allocation size > 256 bytes. Data-flow: allocated pointer escapes function (passed to callee, stored to field, or returned). Data-flow: allocation result flows into loop body.

**Mitigation:** Preallocate. Use arena/slab. Object pools.

### FL021 — Large Stack Frame

**Severity:** Medium (High in deep call chains)

**Hardware Mechanism:** TLB pressure. L1 data cache pressure.

**Detection:** Stack frame > configurable threshold (default 2048B).

**Escalation:** Deep call stack. Recursive patterns.

**Mitigation:** Move large arrays to heap or static region. Reduce local buffers.

---

## Dispatch Risks

### FL030 — Virtual Dispatch in Hot Path

**Severity:** High

**Hardware Mechanism:** Indirect branch misprediction. Pipeline flush. BTB pressure.

**Detection:** Virtual function call in hot path, not devirtualized in IR.

**Escalation:** Inside tight loop.

**Mitigation:** CRTP. Variant + visitation. Function pointers with known targets.

### FL031 — std::function in Hot Path

**Severity:** High

**Hardware Mechanism:** Possible heap allocation. Indirect dispatch. Poor inlining.

**Detection:** `std::function` type invocation in hot path.

**Escalation:** Constructed dynamically. Captures large objects.

**Mitigation:** Template callable. Auto lambda. Function pointer.

---

## Structural Design Risks

### FL040 — Centralized Mutable Global State

**Severity:** High (Critical if multi-writer)

**Hardware Mechanism:** NUMA remote memory access. Cache line contention. Scalability collapse.

**Detection:** Global/static mutable object referenced in hot path, escaping thread-local confinement.

**Escalation:** Contains atomics. Modified by multiple functions.

**Mitigation:** Partition per thread/core. Inject via context.

### FL041 — Contended Queue Pattern

**Severity:** High

**Hardware Mechanism:** Head/tail cache line bouncing. Atomic contention.

**Detection:** Shared queue with atomic head/tail indices on the same cache line.

**Escalation:** No padding between head/tail. Tight loop enqueue/dequeue.

**Mitigation:** Pad head/tail to 64B. Use per-core queues.

---

## Branching Risks

### FL050 — Deep Conditional Tree in Hot Path

**Severity:** Medium (High if data-dependent)

**Hardware Mechanism:** Branch misprediction. I-cache pressure.

**Detection:** N nested conditionals (configurable, default 4) in hot path.

**Mitigation:** Table-driven dispatch. Flatten logic. Precompute decision trees.

---

## NUMA Risks

### FL060 — NUMA-Unfriendly Shared Structure

**Severity:** High

**Hardware Mechanism:** Cross-socket memory access adds ~100-300ns per access.

**Detection:** Shared mutable structure (>= 256B) with thread-escape evidence and unfavorable NUMA placement inference.

**Mitigation:** Pin threads. Use local allocation. Replicate per-socket.

### FL061 — Centralized Dispatcher Bottleneck

**Severity:** High

**Hardware Mechanism:** Branch predictor stress from single function routing to many handlers.

**Detection:** Single dispatcher function with high fan-out in hot path.

**Mitigation:** Partition dispatch tables. Use compile-time routing.

---

## Compound Risks

### FL090 — Hazard Amplification

**Severity:** Critical

**Hardware Mechanism:** Multiple interacting latency multipliers on a single struct.

**Detection:** Struct > 128B with atomic fields, thread-escape evidence, used in loop. Escalates to Critical with composite explanation when all signals present.

### FL091 — Synthesized Interaction

**Severity:** Varies (computed from components)

**Hardware Mechanism:** Super-additive compound hazard from multiple rules firing at the same site.

Seven defined interaction templates:

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

## Querying Rules from the CLI

```bash
# List all rules
lshaz explain --list

# Show details for a specific rule
lshaz explain FL002
```
