#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace faultline {

// Allocator topology classification.
//
// Models the latency characteristics of different allocator call sites:
//   - ThreadLocal: tcmalloc/jemalloc fast path, per-thread cache hit.
//     Sub-100ns, no lock contention. Low hazard on hot path.
//   - ArenaLock: glibc malloc default path, arena lock contention.
//     100ns-10μs under contention. High hazard on hot path.
//   - Syscall: mmap/brk for large allocations (>128KB default).
//     10μs-100μs, page fault risk. Critical hazard on hot path.
//   - PoolSlab: user pool/slab/arena allocator (custom or pmr).
//     Fast path similar to ThreadLocal. Low hazard.
//   - Unknown: cannot classify. Conservative: treat as ArenaLock.
enum class AllocatorClass : uint8_t {
    ThreadLocal,
    ArenaLock,
    Syscall,
    PoolSlab,
    Unknown,
};

constexpr std::string_view allocatorClassName(AllocatorClass c) {
    switch (c) {
        case AllocatorClass::ThreadLocal: return "thread-local-cache";
        case AllocatorClass::ArenaLock:   return "arena-lock";
        case AllocatorClass::Syscall:     return "syscall-mmap";
        case AllocatorClass::PoolSlab:    return "pool-slab";
        case AllocatorClass::Unknown:     return "unknown";
    }
    return "unknown";
}

// Severity multiplier for allocator class.
// 1.0 = baseline (ArenaLock). Lower = less severe, higher = more severe.
constexpr double allocatorSeverityFactor(AllocatorClass c) {
    switch (c) {
        case AllocatorClass::ThreadLocal: return 0.3;
        case AllocatorClass::ArenaLock:   return 1.0;
        case AllocatorClass::Syscall:     return 1.5;
        case AllocatorClass::PoolSlab:    return 0.2;
        case AllocatorClass::Unknown:     return 1.0;
    }
    return 1.0;
}

// Classifies allocation sites based on allocator function name,
// allocation size (if known), and linkage hints.
class AllocatorTopology {
public:
    AllocatorTopology();

    // Classify a call site by callee name and optional allocation size.
    AllocatorClass classify(const std::string &calleeName,
                            size_t allocSize = 0) const;

    // Register a custom pool/slab allocator function name.
    void registerPoolAllocator(const std::string &funcName);

    // Register that the binary links against a specific allocator library.
    // Supported: "tcmalloc", "jemalloc", "mimalloc".
    void setLinkedAllocator(const std::string &allocatorLib);

private:
    std::unordered_set<std::string> poolAllocators_;
    std::string linkedAllocator_; // "tcmalloc", "jemalloc", "mimalloc", or ""

    // Threshold above which glibc malloc uses mmap instead of sbrk.
    static constexpr size_t kMmapThreshold = 128 * 1024;
};

} // namespace faultline
