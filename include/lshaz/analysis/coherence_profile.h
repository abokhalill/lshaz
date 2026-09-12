// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace lshaz {

// What a machine actually did with the lines the analyzer reasoned about:
// shared lines, the source locations that touched them, and the coherence
// transfers each one cost. Every cost term is an estimate of a hardware
// event, and this is the event coming back.
//
// Nothing here knows about the producer beyond the one parse function named
// for its format.
struct CoherenceAccess {
    std::string file;
    unsigned line = 0;
    std::string symbol;
    std::string object;

    // Byte offset into the line. Two offsets on one line with different
    // writers is the false-sharing signature, and it is the only field that
    // distinguishes that from ordinary contention on a single field.
    unsigned offset = 0;

    uint64_t hitmSamples = 0;

    // Load latency the hardware reported for the HITM loads at this site, in
    // cycles. A measured figure for what the model calls hitm_cycles, from
    // the machine being scanned for rather than from a table.
    unsigned hitmCycles = 0;

    uint64_t records = 0;
};

struct CoherenceLine {
    uint64_t address = 0;
    uint64_t localHitm = 0;
    uint64_t remoteHitm = 0;
    uint64_t storeL1Hit = 0;
    uint64_t storeL1Miss = 0;
    std::vector<CoherenceAccess> accesses;

    uint64_t hitm() const { return localHitm + remoteHitm; }

    // Distinct byte offsets carrying HITM. More than one means separate
    // fields are fighting over the line rather than one field being hot.
    unsigned contendedOffsets() const;
};

struct CoherenceProfile {
    std::string origin;

    uint64_t loadOps = 0;
    uint64_t storeOps = 0;
    uint64_t localHitmSamples = 0;
    uint64_t remoteHitmSamples = 0;
    uint64_t sharedLines = 0;

    std::vector<CoherenceLine> lines;

    // Rows the parser recognised as access rows and could not read. Reported
    // rather than dropped: a format change that silently halves the measured
    // total would move every correction learned from it, and look like a
    // quieter machine.
    unsigned unparsedRows = 0;

    uint64_t totalHitmSamples() const {
        return localHitmSamples + remoteHitmSamples;
    }

    // Sampled HITM weighted mean of the per-site load latency. The machine's
    // own answer for hitm_cycles under this workload.
    unsigned meanHitmCycles() const;
};

// Parses the text of `perf c2c report --stdio`. Returns false only when the
// input is not that format at all; a profile that parsed with zero shared
// lines is a valid measurement of a machine that had none.
bool parsePerfC2CReport(const std::string &text, CoherenceProfile &out,
                        std::string &err);

} // namespace lshaz
