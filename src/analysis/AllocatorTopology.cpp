#include "faultline/analysis/AllocatorTopology.h"

namespace faultline {

AllocatorTopology::AllocatorTopology() {
    // Common pool/slab allocator patterns.
    poolAllocators_ = {
        // C++ PMR allocators.
        "std::pmr::polymorphic_allocator",
        "std::pmr::monotonic_buffer_resource",
        "std::pmr::unsynchronized_pool_resource",
        "std::pmr::synchronized_pool_resource",
        // Boost.Pool.
        "boost::pool_allocator",
        "boost::fast_pool_allocator",
        "boost::object_pool",
        "boost::singleton_pool",
        // Common custom patterns.
        "arena_alloc", "slab_alloc", "pool_alloc",
        "arena_allocate", "slab_allocate", "pool_allocate",
    };
}

AllocatorClass AllocatorTopology::classify(const std::string &calleeName,
                                            size_t allocSize) const {
    // Pool/slab allocators: lowest latency.
    if (poolAllocators_.count(calleeName))
        return AllocatorClass::PoolSlab;

    // Check for PMR resource usage via template name prefix.
    if (calleeName.find("std::pmr::") == 0)
        return AllocatorClass::PoolSlab;
    if (calleeName.find("boost::pool") != std::string::npos ||
        calleeName.find("boost::object_pool") != std::string::npos)
        return AllocatorClass::PoolSlab;

    // Large allocations go through mmap regardless of allocator.
    if (allocSize >= kMmapThreshold)
        return AllocatorClass::Syscall;

    // mmap/munmap/brk/sbrk are always syscalls.
    if (calleeName == "mmap" || calleeName == "mmap64" ||
        calleeName == "munmap" || calleeName == "brk" ||
        calleeName == "sbrk")
        return AllocatorClass::Syscall;

    // Standard allocation functions: classification depends on linked allocator.
    bool isStdAlloc =
        calleeName == "malloc" || calleeName == "calloc" ||
        calleeName == "realloc" || calleeName == "free" ||
        calleeName == "aligned_alloc" || calleeName == "posix_memalign" ||
        calleeName == "operator new" || calleeName == "operator delete" ||
        calleeName == "std::make_shared" || calleeName == "std::make_unique" ||
        calleeName == "std::make_shared_for_overwrite" ||
        calleeName == "std::make_unique_for_overwrite";

    if (isStdAlloc) {
        // tcmalloc/jemalloc/mimalloc: fast thread-local cache path for
        // small allocations. Their fast path avoids locks entirely.
        if (linkedAllocator_ == "tcmalloc" ||
            linkedAllocator_ == "jemalloc" ||
            linkedAllocator_ == "mimalloc")
            return AllocatorClass::ThreadLocal;

        // Default: glibc malloc arena lock path.
        return AllocatorClass::ArenaLock;
    }

    // STL container constructors: delegate to their allocator.
    // Default std::allocator → same as malloc.
    if (calleeName.find("std::vector") == 0 ||
        calleeName.find("std::map") == 0 ||
        calleeName.find("std::unordered_map") == 0 ||
        calleeName.find("std::list") == 0 ||
        calleeName.find("std::deque") == 0 ||
        calleeName.find("std::set") == 0 ||
        calleeName.find("std::unordered_set") == 0 ||
        calleeName.find("std::basic_string") == 0 ||
        calleeName.find("std::__cxx11::basic_string") == 0 ||
        calleeName.find("std::shared_ptr") == 0 ||
        calleeName.find("std::function") == 0) {
        if (linkedAllocator_ == "tcmalloc" ||
            linkedAllocator_ == "jemalloc" ||
            linkedAllocator_ == "mimalloc")
            return AllocatorClass::ThreadLocal;
        return AllocatorClass::ArenaLock;
    }

    return AllocatorClass::Unknown;
}

void AllocatorTopology::registerPoolAllocator(const std::string &funcName) {
    poolAllocators_.insert(funcName);
}

void AllocatorTopology::setLinkedAllocator(const std::string &allocatorLib) {
    linkedAllocator_ = allocatorLib;
}

} // namespace faultline
