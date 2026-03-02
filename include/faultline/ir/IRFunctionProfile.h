#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace faultline {

struct IRAllocaInfo {
    std::string name;
    uint64_t sizeBytes = 0;
    bool isArray = false;
};

struct IRCallSiteInfo {
    std::string calleeName; // empty if indirect
    bool isIndirect = false;
    bool isIntrinsic = false;
    bool isInLoop = false;
};

struct IRAtomicInfo {
    enum Op { Load, Store, RMW, CmpXchg, Fence };
    Op op;
    unsigned ordering = 0; // llvm::AtomicOrdering as unsigned
    bool isInLoop = false;
    std::string sourceFile;
    unsigned sourceLine = 0;
};

struct IRFunctionProfile {
    std::string mangledName;
    std::string demangledName;

    // Stack frame
    uint64_t totalAllocaBytes = 0;
    std::vector<IRAllocaInfo> allocas;

    // Heap allocation calls (post-inlining)
    std::vector<IRCallSiteInfo> heapAllocCalls;

    // All non-intrinsic call sites (for lock/sync correlation)
    std::vector<IRCallSiteInfo> allCalls;

    // Indirect calls (post-devirtualization)
    unsigned indirectCallCount = 0;
    unsigned directCallCount = 0;

    // Atomics and fences
    std::vector<IRAtomicInfo> atomics;
    unsigned fenceCount = 0;
    unsigned seqCstCount = 0;

    // Basic block / loop structure
    unsigned basicBlockCount = 0;
    unsigned loopCount = 0;

    bool hasProfile() const { return !mangledName.empty(); }
};

} // namespace faultline
