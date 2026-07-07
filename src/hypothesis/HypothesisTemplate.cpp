// SPDX-License-Identifier: Apache-2.0
#include "lshaz/hypothesis/HypothesisTemplate.h"

namespace lshaz {

namespace {

std::vector<ConfoundControl> standardConfounds() {
    return {
        {"cpu_frequency", "cpupower frequency-set --governor performance"},
        {"turbo_boost", "echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo"},
        {"c_states", "disable states > C0 via cpuidle sysfs"},
        {"cpu_pinning", "taskset / pthread_setaffinity_np"},
        {"transparent_hugepages", "echo never > /sys/kernel/mm/transparent_hugepage/enabled"},
        {"aslr", "echo 0 > /proc/sys/kernel/randomize_va_space"},
        {"compiler_flags", "-O2 -march=native -fno-lto"},
        {"interrupt_isolation", "isolcpus + irqbalance disabled on test cores"},
    };
}

PMUCounterSet cacheGeometryCounters() {
    return {
        .required = {
            {"L1-dcache-load-misses", CounterTier::Standard,
             "Direct measure of L1D pressure from footprint", ""},
            {"L1-dcache-store-misses", CounterTier::Standard,
             "Write-side pressure", ""},
            {"LLC-load-misses", CounterTier::Standard,
             "Eviction cascading to LLC", ""},
            {"cycles", CounterTier::Universal, "Baseline for IPC", ""},
            {"instructions", CounterTier::Universal, "Baseline for IPC", ""},
        },
        .optional = {
            {"MEM_LOAD_RETIRED.L1_MISS", CounterTier::Extended,
             "Precise L1 miss attribution", ""},
            {"MEM_LOAD_RETIRED.L2_MISS", CounterTier::Extended,
             "L2 cascade confirmation", ""},
        },
    };
}

PMUCounterSet falseSharingCounters() {
    return {
        .required = {
            {"L1-dcache-load-misses", CounterTier::Standard,
             "Invalidation forces reload", ""},
            {"L1-dcache-store-misses", CounterTier::Standard,
             "RFO stall", ""},
            {"LLC-store-misses", CounterTier::Standard,
             "Ownership transfer reaching LLC", ""},
            {"stalled-cycles-backend", CounterTier::Standard,
             "Pipeline stall from coherence wait", ""},
        },
        .optional = {
            {"offcore_response.demand_rfo.l3_miss.snoop_hitm", CounterTier::Extended,
             "Direct HITM measurement", ""},
            {"MEM_LOAD_L3_HIT_RETIRED.XSNP_HITM", CounterTier::Extended,
             "Cross-core snoop hit modified (ICL+)", ""},
        },
    };
}

PMUCounterSet atomicOrderingCounters() {
    return {
        .required = {
            {"stalled-cycles-backend", CounterTier::Standard,
             "Store buffer drain stall", ""},
            {"stalled-cycles-frontend", CounterTier::Standard,
             "Serialization-induced frontend stall", ""},
            {"cycles", CounterTier::Universal, "Total cycle cost", ""},
            {"instructions", CounterTier::Universal, "IPC computation", ""},
        },
        .optional = {
            {"MACHINE_CLEARS.MEMORY_ORDERING", CounterTier::Extended,
             "Memory ordering machine clears", ""},
        },
    };
}

PMUCounterSet atomicContentionCounters() {
    return {
        .required = {
            {"stalled-cycles-backend", CounterTier::Standard,
             "Ownership transfer stall", ""},
            {"LLC-store-misses", CounterTier::Standard,
             "RFO reaching LLC", ""},
            {"L1-dcache-store-misses", CounterTier::Standard,
             "Invalidation-induced store miss", ""},
        },
        .optional = {
            {"offcore_response.demand_rfo.l3_miss.snoop_hitm", CounterTier::Extended,
             "Direct cross-core contention", ""},
            {"offcore_response.demand_rfo.l3_hit.snoop_hitm", CounterTier::Extended,
             "Intra-socket contention", ""},
        },
    };
}

PMUCounterSet lockContentionCounters() {
    return {
        .required = {
            {"context-switches", CounterTier::Universal,
             "Direct serialization measure", ""},
            {"cpu-migrations", CounterTier::Universal,
             "Scheduler-induced cache invalidation", ""},
            {"stalled-cycles-backend", CounterTier::Standard,
             "Lock spin + syscall overhead", ""},
            {"cycles", CounterTier::Universal, "Total cost", ""},
        },
        .optional = {
            {"page-faults", CounterTier::Universal,
             "Post-context-switch TLB refill", ""},
        },
    };
}

PMUCounterSet heapAllocationCounters() {
    return {
        .required = {
            {"dTLB-load-misses", CounterTier::Standard,
             "New page TLB pressure", ""},
            {"dTLB-store-misses", CounterTier::Standard,
             "Write-side TLB pressure", ""},
            {"page-faults", CounterTier::Universal,
             "New page mapping", ""},
            {"cache-misses", CounterTier::Universal,
             "Cold cache on new allocation", ""},
            {"cycles", CounterTier::Universal, "Total cost", ""},
        },
        .optional = {},
    };
}

PMUCounterSet stackPressureCounters() {
    return {
        .required = {
            {"dTLB-load-misses", CounterTier::Standard,
             "Stack page TLB pressure", ""},
            {"L1-dcache-load-misses", CounterTier::Standard,
             "Stack data L1D pressure", ""},
            {"cycles", CounterTier::Universal, "Total cost", ""},
        },
        .optional = {},
    };
}

PMUCounterSet indirectDispatchCounters() {
    return {
        .required = {
            {"branch-misses", CounterTier::Universal,
             "Direct misprediction count", ""},
            {"branches", CounterTier::Universal,
             "Total branch count for miss rate", ""},
            {"L1-icache-load-misses", CounterTier::Standard,
             "I-cache pressure from multiple targets", ""},
            {"cycles", CounterTier::Universal, "Total cost", ""},
        },
        .optional = {
            {"BR_MISP_RETIRED.INDIRECT", CounterTier::Extended,
             "Indirect branch misprediction specifically", ""},
            {"BR_MISP_RETIRED.INDIRECT_CALL", CounterTier::Extended,
             "Indirect call misprediction", ""},
            {"BACLEARS.ANY", CounterTier::Extended,
             "Frontend resteers from misprediction", ""},
        },
    };
}

PMUCounterSet numaLocalityCounters() {
    return {
        .required = {
            {"LLC-load-misses", CounterTier::Standard,
             "Misses reaching memory subsystem", ""},
            {"stalled-cycles-backend", CounterTier::Standard,
             "Memory stall", ""},
        },
        .optional = {
            {"offcore_response.demand_data_rd.l3_miss.remote_dram",
             CounterTier::Extended, "Direct remote DRAM access", ""},
            {"offcore_response.demand_data_rd.l3_miss.local_dram",
             CounterTier::Extended, "Local DRAM baseline", ""},
            {"node-load-misses", CounterTier::Standard,
             "NUMA node miss", ""},
            {"node-store-misses", CounterTier::Standard,
             "NUMA node store miss", ""},
        },
    };
}

} // anonymous namespace

const HypothesisTemplateRegistry &HypothesisTemplateRegistry::instance() {
    static HypothesisTemplateRegistry reg;
    return reg;
}

const HypothesisTemplate *HypothesisTemplateRegistry::lookup(HazardClass hc) const {
    for (const auto &t : templates_) {
        if (t.hazardClass == hc)
            return &t;
    }
    return nullptr;
}

HypothesisTemplateRegistry::HypothesisTemplateRegistry() {
    auto confounds = standardConfounds();

    templates_ = {
        {
            HazardClass::CacheGeometry,
            "Struct layout does not cause measurable increase in L1D/L2 miss rate "
            "or coherence traffic under concurrent access.",
            "Struct spanning {cache_lines} cache lines causes >= {mde}% increase "
            "in L1-dcache-load-misses and >= {mde}% increase in {percentile} "
            "operation latency compared to cache-line-aligned control.",
            {"p99.9_operation_latency_ns", "nanoseconds", "p99.9"},
            cacheGeometryCounters(),
            0.05,
            confounds,
            true,
        },
        {
            HazardClass::FalseSharing,
            "Adjacent mutable fields on same cache line do not cause measurable "
            "coherence traffic under multi-writer access.",
            "Unpadded adjacent fields cause >= {mde}% increase in HITM events "
            "and >= {mde}% increase in {percentile} latency compared to "
            "64B-padded control.",
            {"p99.9_operation_latency_ns", "nanoseconds", "p99.9"},
            falseSharingCounters(),
            0.05,
            confounds,
            true,
        },
        {
            HazardClass::AtomicOrdering,
            "memory_order_seq_cst does not cause measurable pipeline "
            "serialization cost compared to acquire/release on x86-64 TSO.",
            "seq_cst operations in hot loop cause >= {mde}% increase in "
            "stalled-cycles-backend and >= {mde}% increase in {percentile} "
            "latency compared to acquire/release variant.",
            {"p99_operation_latency_ns", "nanoseconds", "p99"},
            atomicOrderingCounters(),
            0.05,
            confounds,
            true,
        },
        {
            HazardClass::AtomicContention,
            "Concurrent atomic writes to shared variable do not cause measurable "
            "cross-core ownership transfer cost.",
            "N-thread concurrent atomic writes cause >= {mde}% increase in "
            "HITM events and >= {mde}% increase in {percentile} latency "
            "compared to per-core sharded control.",
            {"p99.9_operation_latency_ns", "nanoseconds", "p99.9"},
            atomicContentionCounters(),
            0.05,
            confounds,
            true,
        },
        {
            HazardClass::LockContention,
            "Mutex acquisition in hot path does not cause measurable "
            "serialization or context-switch cost under concurrent load.",
            "Contended mutex causes >= {mde}% increase in context-switches "
            "and >= {mde}% increase in {percentile} latency compared to "
            "lock-free control.",
            {"p99.99_operation_latency_ns", "nanoseconds", "p99.99"},
            lockContentionCounters(),
            0.05,
            confounds,
            true,
        },
        {
            HazardClass::HeapAllocation,
            "Heap allocation in hot path does not cause measurable allocator "
            "contention or TLB pressure.",
            "Per-iteration allocation causes >= {mde}% increase in "
            "dTLB-load-misses and >= {mde}% increase in {percentile} latency "
            "compared to preallocated control.",
            {"p99.9_operation_latency_ns", "nanoseconds", "p99.9"},
            heapAllocationCounters(),
            0.05,
            confounds,
            false,
        },
        {
            HazardClass::StackPressure,
            "Large stack frame does not cause measurable TLB or L1D pressure "
            "in hot path.",
            "Stack frame > {threshold}B causes >= {mde}% increase in "
            "dTLB-load-misses and >= {mde}% increase in {percentile} latency "
            "compared to reduced-frame control.",
            {"p99_operation_latency_ns", "nanoseconds", "p99"},
            stackPressureCounters(),
            0.05,
            confounds,
            false,
        },
        {
            HazardClass::VirtualDispatch,
            "Virtual/indirect call in hot path does not cause measurable "
            "branch misprediction cost.",
            "Polymorphic dispatch with {target_count} targets causes >= {mde}% "
            "increase in branch-misses and >= {mde}% increase in {percentile} "
            "latency compared to direct/CRTP control.",
            {"p99_operation_latency_ns", "nanoseconds", "p99"},
            indirectDispatchCounters(),
            0.05,
            confounds,
            true,
        },
        {
            HazardClass::StdFunction,
            "std::function invocation in hot path does not cause measurable "
            "indirect dispatch or allocation cost.",
            "std::function usage causes >= {mde}% increase in branch-misses "
            "and >= {mde}% increase in {percentile} latency compared to "
            "template callable control.",
            {"p99_operation_latency_ns", "nanoseconds", "p99"},
            indirectDispatchCounters(),
            0.05,
            confounds,
            false,
        },
        {
            HazardClass::ContendedQueue,
            "Adjacent atomic indices on same cache line do not cause measurable "
            "coherence traffic under producer-consumer access.",
            "Unpadded head/tail atomics cause >= {mde}% increase in HITM "
            "events and >= {mde}% increase in {percentile} latency compared "
            "to 64B-padded control.",
            {"p99.9_operation_latency_ns", "nanoseconds", "p99.9"},
            falseSharingCounters(),
            0.05,
            confounds,
            true,
        },
        {
            HazardClass::NUMALocality,
            "Shared mutable structure does not incur measurable remote memory "
            "access penalty.",
            "Cross-socket access to shared structure causes >= {mde}% increase "
            "in remote DRAM accesses and >= {mde}% increase in {percentile} "
            "latency compared to socket-local control.",
            {"p99.9_operation_latency_ns", "nanoseconds", "p99.9"},
            numaLocalityCounters(),
            0.05,
            confounds,
            true,
        },
        {
            HazardClass::HazardAmplification,
            "Co-occurrence of multiple structural hazards does not produce "
            "super-additive tail latency effect.",
            "Combined hazard produces tail latency increase > sum of "
            "individual hazard effects.",
            {"p99.99_operation_latency_ns", "nanoseconds", "p99.99"},
            cacheGeometryCounters().merged(atomicContentionCounters())
                                   .merged(numaLocalityCounters()),
            0.05,
            confounds,
            false,
        },
        // FL040/FL050/FL061 previously had no template: hyp/exp dropped
        // their findings without attribution.
        {
            HazardClass::GlobalState,
            "Concurrent writes to a centralized mutable global do not cause "
            "measurable cross-core cache line ownership transfer cost.",
            "Multi-writer access to the shared global causes >= {mde}% "
            "increase in HITM events and >= {mde}% increase in {percentile} "
            "latency compared to per-core sharded control.",
            {"p99.9_operation_latency_ns", "nanoseconds", "p99.9"},
            atomicContentionCounters(),
            0.05,
            confounds,
            true,
        },
        {
            HazardClass::DeepConditional,
            "Nested conditional depth does not cause measurable branch "
            "misprediction cost on realistic input distributions.",
            "Deep conditional tree causes >= {mde}% increase in "
            "branch-misses and >= {mde}% increase in {percentile} latency "
            "compared to table-driven control.",
            {"p99_operation_latency_ns", "nanoseconds", "p99"},
            indirectDispatchCounters(),
            0.05,
            confounds,
            true,
        },
        {
            HazardClass::CentralizedDispatch,
            "Single-point dispatch fan-out does not cause measurable BTB or "
            "I-cache pressure compared to partitioned dispatch.",
            "Centralized dispatcher causes >= {mde}% increase in "
            "branch-misses/iTLB pressure and >= {mde}% increase in "
            "{percentile} latency compared to partitioned control.",
            {"p99_operation_latency_ns", "nanoseconds", "p99"},
            indirectDispatchCounters(),
            0.05,
            confounds,
            false,
        },
    };
}

} // namespace lshaz
