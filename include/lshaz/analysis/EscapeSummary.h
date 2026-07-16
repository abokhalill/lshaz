// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace lshaz {

// Per-type escape signals collected from a single TU.
// Structural signals (atomics, sync, volatile, shared_ptr)
// are derivable from the type definition alone; they're identical across
// all TUs that include the header. Publication signals (global store,
// thread-creation arg) are TU-specific and must be aggregated.
struct TypeEscapeSignals {
    bool hasAtomics      = false;
    bool hasSyncPrims    = false;
    bool hasSharedOwner  = false;
    bool hasVolatile     = false;
    bool hasPublication  = false;  // TU-local: passed to thread/stored globally
    // Explicit line alignment or trailing pad-to-line: the author reasons
    // in cache lines. Feeds the FL092 precedent join; a codebase-level
    // "the mitigation idiom is known here" index.
    bool hasDeliberateLayout = false;
    unsigned accessorCount = 0;   // distinct functions touching this type in TU

    // Merge another TU's signals into this aggregate.
    void merge(const TypeEscapeSignals &other) {
        hasAtomics     |= other.hasAtomics;
        hasSyncPrims   |= other.hasSyncPrims;
        hasSharedOwner |= other.hasSharedOwner;
        hasVolatile    |= other.hasVolatile;
        hasPublication |= other.hasPublication;
        hasDeliberateLayout |= other.hasDeliberateLayout;
        accessorCount  += other.accessorCount;
    }

    // Structural signals only — no TU-specific publication evidence.
    bool hasStructuralEscape() const {
        return hasAtomics || hasSyncPrims || hasSharedOwner || hasVolatile;
    }

    bool hasAnyEscape() const {
        return hasStructuralEscape() || hasPublication;
    }
};

// Per-TU escape summary. Keyed by canonical qualified type name.
// Emitted by LshazASTConsumer, serialized through fork IPC,
// aggregated in ScanPipeline reduce phase.
using EscapeSummary = std::unordered_map<std::string, TypeEscapeSignals>;

// Merge src into dst. For each type, merge signals.
inline void mergeEscapeSummaries(EscapeSummary &dst, const EscapeSummary &src) {
    for (const auto &[name, signals] : src)
        dst[name].merge(signals);
}

} // namespace lshaz
