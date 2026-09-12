// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>

namespace lshaz {

// One mutable field's place in its record. Enough to redo the co-residency
// test exactly in the reduce phase; the pairs themselves are quadratic in
// field count and would be shipped for the same answer.
struct FieldExtent {
    uint64_t offsetBytes = 0;
    uint64_t sizeBytes   = 0;   // 0 means two TUs disagreed, see merge
    bool isAtomic = false;
    // A plain scalar: no write of it can happen except through an assignment
    // the field-write tracker sees. A mutex, an array or a nested aggregate
    // is routinely mutated through its address (pthread_mutex_lock(&m),
    // memcpy) with no assignment anywhere, so "no writer in the program" is
    // a statement about the tracker rather than about the program.
    bool plainScalar = false;

    // Where the field was declared. Without it every finding about any field
    // of a record reports at the record's own line, and the dedup key
    // (rule, file, line, column, function) collapses them all into one.
    unsigned declLine = 0;
};

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
    // Written from >=2 functions, one of them spawned as a thread.
    // Publication requires an address to cross a thread boundary; a
    // file-scope object written directly from two thread bodies never
    // does, and is invisible without this.
    bool hasThreadWriters = false;
    // A file-scope instance exists in SOME TU. Per-TU this is nearly
    // useless -- the record lives in a header and the global lives in one
    // .c -- which is why the instance question has to be answered here
    // rather than at rule time.
    bool hasGlobalInstance = false;
    // Some TU saw a thread-borne writer touch it.
    bool hasThreadBorneWriter = false;
    // Some TU writes a field through a fixed nameable object rather than
    // one passed in. A handed-over object has one owner at a time.
    bool hasStandingWrites = false;
    // Explicit line alignment or trailing pad-to-line: the author reasons
    // in cache lines. Feeds the FL092 precedent join; a codebase-level
    // "the mitigation idiom is known here" index.
    bool hasDeliberateLayout = false;
    unsigned accessorCount = 0;   // distinct functions touching this type in TU

    // Layout of the mutable fields, plus where the definition lives. A store
    // to one field invalidates the whole line, so a core reading a different
    // field on it re-fetches; deciding that needs the two accesses joined,
    // and they routinely sit in different TUs. Carried here rather than in a
    // summary of its own because the reduce needs hasSharingRoute() on the
    // same key and two maps could disagree on which types exist.
    std::map<std::string, FieldExtent> fieldExtents;
    uint64_t recordAlignBytes = 0;
    std::string declFile;
    unsigned declLine = 0;

    // Merge another TU's signals into this aggregate.
    void merge(const TypeEscapeSignals &other) {
        hasAtomics     |= other.hasAtomics;
        hasSyncPrims   |= other.hasSyncPrims;
        hasSharedOwner |= other.hasSharedOwner;
        hasVolatile    |= other.hasVolatile;
        hasPublication |= other.hasPublication;
        hasThreadWriters |= other.hasThreadWriters;
        hasGlobalInstance |= other.hasGlobalInstance;
        hasThreadBorneWriter |= other.hasThreadBorneWriter;
        hasStandingWrites |= other.hasStandingWrites;
        hasDeliberateLayout |= other.hasDeliberateLayout;
        accessorCount  += other.accessorCount;

        for (const auto &[name, e] : other.fieldExtents) {
            auto [it, inserted] = fieldExtents.emplace(name, e);
            // The same header compiled under different -D can lay the record
            // out two ways. Then sharing a line is not a property of the
            // program and the field drops out, rather than the answer
            // depending on which shard reported last. Absorbing, so the
            // result does not depend on merge order either.
            if (!inserted && (it->second.offsetBytes != e.offsetBytes ||
                              it->second.sizeBytes != e.sizeBytes))
                it->second = FieldExtent{};
        }
        // Larger alignment admits fewer base shifts and so fewer pairs:
        // max is both the conservative choice and an order-free one.
        recordAlignBytes = std::max(recordAlignBytes, other.recordAlignBytes);
        if (declLine != 0 && other.declLine != 0) {
            // Canonical location tiebreak, same one dedup uses.
            const bool otherWins =
                other.declFile.size() < declFile.size() ||
                (other.declFile.size() == declFile.size() &&
                 (other.declFile < declFile ||
                  (other.declFile == declFile && other.declLine < declLine)));
            if (otherWins) { declFile = other.declFile; declLine = other.declLine; }
        } else if (other.declLine != 0) {
            declFile = other.declFile;
            declLine = other.declLine;
        }
    }

    // Structural signals only, no TU-specific publication evidence.
    bool hasStructuralEscape() const {
        return hasAtomics || hasSyncPrims || hasSharedOwner || hasVolatile;
    }

    // Two cores can reach one object: a shared instance somewhere, and a
    // thread that touches it. Answerable only after every TU has reported.
    bool hasSharingRoute() const {
        // Standing access is the conjunct that separates sharing from a
        // handoff. Without it, a request object queued between a producer
        // and a consumer looks identical to a shared counter block: both
        // are written from several functions, one of them thread-borne.
        if (!hasStandingWrites)
            return false;
        return hasPublication || hasThreadWriters ||
               (hasGlobalInstance && hasThreadBorneWriter);
    }

    // Whether "no writer anywhere" says something about the program. A mutex
    // or a nested aggregate is mutated through its address with no assignment
    // to find, so for those the silence is the tracker's.
    bool writesObservable() const {
        if (fieldExtents.empty())
            return false;
        for (const auto &[name, e] : fieldExtents)
            if (!e.plainScalar && !e.isAtomic)
                return false;
        return true;
    }

    // No thread reaches a shared instance, and the reason holds of the
    // program. Seeing a standing write proves the tracker worked here, so
    // what remains is structural; without one the verdict rests on an absence
    // and needs writesObservable() to mean anything.
    bool sharingRouteRefuted() const {
        if (hasSharingRoute())
            return false;
        return hasStandingWrites || writesObservable();
    }

    // Over every type in a scan, a positive control on thread detection.
    bool hasThreadRoute() const {
        return hasPublication || hasThreadWriters || hasThreadBorneWriter;
    }

    bool hasAnyEscape() const {
        // hasGlobalInstance belongs here. Splitting it out of hasPublication
        // and forgetting this suppressed every type whose only evidence is
        // that a global instance exists -- which is most file-local hot
        // structs in C. Such a type fires when its defining TU is scanned
        // alone and vanishes in a corpus run, which is the bug this prevents.
        return hasStructuralEscape() || hasPublication || hasThreadWriters ||
               hasGlobalInstance;
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
