// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace lshaz {

// What the machine did to the storage the analyzer reasoned about.
//
// Keyed by ObjectId, the same identity points-to assigns, rather than by
// file:line. A file:line key does not survive inlining and cannot name the
// byte within a record; storage identity does both, because storage is what
// the hardware addresses. That is the whole reason this exists next to
// CoherenceProfile rather than inside it.
//
// The producer is `lshaz sample`, which reads PEBS data addresses and
// resolves them through the target's memory map and symbol tables. Any
// producer emitting the same shape works.

// One byte offset within one object, as the hardware saw it.
struct OffsetCoherence {
    uint64_t offset = 0;
    uint64_t samples = 0;        // cross-core hit-modified at this offset
    std::set<unsigned> cpus;     // cores that took them
    uint64_t weightSum = 0;      // load latency in cycles, summed
    uint64_t weightCount = 0;

    // Mean measured latency of the coherence miss, or 0 when unweighted.
    unsigned meanCycles() const {
        return weightCount ? static_cast<unsigned>(weightSum / weightCount) : 0;
    }
};

struct ObjectCoherence {
    std::string objectId;               
    uint64_t samples = 0;
    std::map<uint64_t, OffsetCoherence> byOffset;
    std::set<unsigned> cpus;

    // Offsets grouped into the lines they fall on, for a given line size.
    // The record's own base alignment is unknown here, so this is the line
    // grid relative to the object, which is what the static side reasons in.
    std::map<uint64_t, std::vector<const OffsetCoherence *>>
    linesOf(uint64_t lineBytes) const;

    // A line carrying hit-modified traffic from more than one core, with more
    // than one distinct byte offset on it. One offset from many cores is
    // contention on a field; several offsets is the line being shared by
    // things that did not need to share it.
    std::vector<uint64_t> falseSharedLines(uint64_t lineBytes) const;

    unsigned meanCycles() const;
};

struct MemoryProfile {
    std::string origin;      // where it came from, for reporting
    std::string machine;
    std::string workload;

    uint64_t totalSamples = 0;
    uint64_t samplePeriod = 0;    // events per sample, for scaling to a count
    uint64_t wallNanos = 0;
    uint64_t unresolvedSamples = 0;   // hardware saw them, we could not name them

    std::map<std::string, ObjectCoherence> objects;

    // Estimated hardware events behind the samples, not the sample count.
    uint64_t estimatedEvents() const {
        return totalSamples * (samplePeriod ? samplePeriod : 1);
    }

    // An instrument that recorded no coherence traffic anywhere is
    // indistinguishable from one pointed at the wrong event, run without
    // permission, or aimed at a workload that was idle. It must not be
    // allowed to refute anything. Same rule bench/accept.sh applies to
    // perf c2c and applySharingRouteVerdict applies to thread routes.
    bool live() const { return totalSamples > 0 && !objects.empty(); }

    // Share of what the hardware saw that this build could name. Absence of
    // an object from a profile that named 16% of its samples says nothing
    // about that object; absence from one that named 95% is evidence. Any
    // verdict that turns on absence has to read this first.
    double resolutionRate() const {
        const uint64_t all = totalSamples + unresolvedSamples;
        return all ? static_cast<double>(totalSamples) / all : 0.0;
    }

    // Share of all measured coherence traffic that landed on one object.
    // The quantity to rank by, and deliberately not a cost: converting it
    // needs a cycles-per-transfer figure and the run's own cycle count.
    double shareOf(const std::string &objectId) const;

    const ObjectCoherence *find(const std::string &objectId) const;
};

// Parse the JSON `lshaz sample` emits. Returns false and fills err on a
// document that is not one, rather than yielding an empty profile that reads
// like a clean machine.
bool parseMemoryProfile(const std::string &json, MemoryProfile &out,
                        std::string &err);

} // namespace lshaz
