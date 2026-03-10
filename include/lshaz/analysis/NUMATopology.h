// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string>
#include <string_view>
#include <cstdint>

namespace clang {
class VarDecl;
class RecordDecl;
class CXXRecordDecl;
class FunctionDecl;
class ASTContext;
} // namespace clang

namespace lshaz {

// First-touch page placement classification.
//
// Linux default: pages are allocated on the NUMA node of the thread
// that first writes to them (first-touch policy). This model infers
// the likely NUMA placement based on how/where a variable is allocated.
enum class NUMAPlacement : uint8_t {
    LocalInit,      // Allocated+initialized in same context (likely local)
    MainThread,     // Allocated in main/startup → pinned to socket 0
    AnyThread,      // Allocated by arbitrary worker thread → unpredictable
    Interleaved,    // mbind(MPOL_INTERLEAVE) or numa_alloc_interleaved
    Explicit,       // numa_alloc_onnode / mbind(MPOL_BIND)
    Unknown,        // Cannot determine
};

constexpr std::string_view numaPlacementName(NUMAPlacement p) {
    switch (p) {
        case NUMAPlacement::LocalInit:   return "local-init";
        case NUMAPlacement::MainThread:  return "main-thread";
        case NUMAPlacement::AnyThread:   return "any-thread";
        case NUMAPlacement::Interleaved: return "interleaved";
        case NUMAPlacement::Explicit:    return "explicit-bind";
        case NUMAPlacement::Unknown:     return "unknown";
    }
    return "unknown";
}

// NUMA hazard severity factor.
// Lower = less NUMA risk, higher = more risk.
constexpr double numaHazardFactor(NUMAPlacement p) {
    switch (p) {
        case NUMAPlacement::LocalInit:   return 0.3;
        case NUMAPlacement::MainThread:  return 0.8;
        case NUMAPlacement::AnyThread:   return 1.0;
        case NUMAPlacement::Interleaved: return 0.4;
        case NUMAPlacement::Explicit:    return 0.1;
        case NUMAPlacement::Unknown:     return 1.0;
    }
    return 1.0;
}

class NUMATopology {
public:
    // Infer NUMA placement for a global/static variable declaration.
    static NUMAPlacement classifyGlobalVar(const clang::VarDecl *VD,
                                            clang::ASTContext &Ctx);

    // Infer NUMA placement for a struct based on how it's typically
    // allocated (heap vs stack vs global).
    static NUMAPlacement classifyStruct(const clang::RecordDecl *RD,
                                         clang::ASTContext &Ctx);

    // Check if a function is a main-thread-only initializer.
    static bool isMainThreadInitializer(const clang::FunctionDecl *FD);

    // Check if a declaration has NUMA-aware allocation hints
    // (numa_alloc_*, mbind, annotations).
    static bool hasNUMAPlacementHint(const clang::VarDecl *VD,
                                     clang::ASTContext &Ctx);
};

} // namespace lshaz
