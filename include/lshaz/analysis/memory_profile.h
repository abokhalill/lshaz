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

// Another named object sharing a cache line with this one, and where it sits
// relative to this one's start. Negative when it comes first.
struct LineNeighbour {
    std::string objectId;
    int64_t at = 0;

    // Offset within THIS object of a sample on the shared line. An object is
    // not line-aligned, so a line grid taken from its start can put a
    // neighbour outside every line. Match on this, never on `at`.
    uint64_t witness = 0;
};

struct ObjectCoherence {
    std::string objectId;
    std::string symbol;   // ELF name when it differs from the source-level one
    uint64_t samples = 0;

    // More than one symbol in the binary carries this name, so the samples are
    // a sum over several objects and belong to none of them in particular.
    bool ambiguous = false;
    std::map<uint64_t, OffsetCoherence> byOffset;
    std::set<unsigned> cpus;

    // Objects the linker put on the same line as this one. Nothing in the
    // source says two globals share storage, so this cannot be derived from an
    // AST at any precision; it comes from the symbol table of the binary that
    // actually ran.
    std::vector<LineNeighbour> neighbours;

    // Neighbours whose bytes fall on the given line of this object.
    std::vector<const LineNeighbour *> neighboursOnLine(uint64_t lineBase,
                                                        uint64_t lineBytes) const;

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

// A field the static side claims is part of a sharing pair, in the coordinates
// the hardware reports: byte offset from the start of the object.
struct ClaimedField {
    std::string name;
    uint64_t offset = 0;
    uint64_t size = 0;

    bool contains(uint64_t byteOffset) const {
        return byteOffset >= offset && byteOffset < offset + (size ? size : 1);
    }
};

// False and true sharing give the same object-level count and take different
// fixes. Separating them needs the measured offsets checked against the fields
// the rule named.
enum class SharingVerdict {
    NoTraffic,        // nothing measured on this object
    OffClaimedLines,  // the object moved, but not on the lines the rule named
    TooFewSamples,    // traffic on a claimed line, not enough to tell which kind
    SingleField,      // concentrated on one claimed field: true sharing
    MultiField,       // two or more claimed fields of one line: false sharing
    CrossObjectLine,  // the line is shared with a different object entirely
};

const char *sharingVerdictName(SharingVerdict v);

struct SharingEvidence {
    SharingVerdict verdict = SharingVerdict::NoTraffic;
    uint64_t lineBase = 0;          // claimed line carrying the most traffic
    uint64_t samplesOnLine = 0;
    uint64_t samplesOnObject = 0;
    std::vector<std::string> fieldsHit;      // claimed fields with traffic
    std::vector<uint64_t> unclaimedOffsets;  // traffic on that line, no claimed field
    std::set<unsigned> cores;                // cores that took the line's samples
    std::vector<std::string> lineNeighbours; // other objects on the same line
};

// Each sample independently proves the line was dirty in another core, so this
// rules out a stray. Counting distinct sampling cores instead would miss a
// pinned producer/consumer pair.
inline constexpr uint64_t kMinSamplesToEstablish = 8;

// Refuting asserts a second field on the line was quiet. A field taking a
// fifth of its transfers goes unsampled with probability 0.8^n.
inline constexpr uint64_t kMinSamplesToDiscriminate = 64;

SharingEvidence discriminateSharing(const ObjectCoherence &oc,
                                    const std::vector<ClaimedField> &claimed,
                                    uint64_t lineBytes);

struct MemoryProfile {
    std::string origin;      // where it came from, for reporting
    std::string machine;
    std::string workload;

    // PERF_TYPE_RAW accepts any config, so a wrong encoding yields real samples
    // with a different meaning. Without a passing self-test a profile may rank
    // findings but must not settle a claim.
    std::string event;              // raw PMU config, as written
    std::string cpuModel;           // vendor-family-model of the machine
    std::string selfTest;           // pass | fail | skipped, empty if older
    uint64_t selfTestSamples = 0;   // hits on a known-positive victim line

    // Whether the instrument can see a line shared by stores alone. A load
    // event reports nothing for that pattern, which is what an unshared line
    // reports, and single-writer-per-slot striping produces exactly it. Do not
    // refute on silence unless this is "visible".
    // See reports/instrument-characterization.md.
    std::string storeOnlySharing;   // visible | blind | unknown

    bool coherenceVerified() const { return selfTest == "pass"; }
    bool seesStoreOnlySharing() const { return storeOnlySharing == "visible"; }

    std::string provenanceProblem() const {
        if (selfTest == "pass")    return {};
        if (selfTest == "fail")
            return "the known-positive self-test saw no cross-core traffic on a "
                   "line two pinned threads were fighting over, so event " +
                   (event.empty() ? std::string("(unrecorded)") : event) +
                   " does not measure coherence on " +
                   (cpuModel.empty() ? std::string("that machine") : cpuModel);
        if (selfTest == "skipped")
            return "the self-test was skipped, so event " +
                   (event.empty() ? std::string("(unrecorded)") : event) +
                   " is unverified on " +
                   (cpuModel.empty() ? std::string("that machine") : cpuModel);
        return "this profile predates instrument verification and carries no "
               "self-test result";
    }

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
