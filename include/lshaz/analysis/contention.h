// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/analysis/escape_summary.h"
#include "lshaz/analysis/rate_model.h"
#include "lshaz/analysis/thread_role.h"
#include "lshaz/core/cost.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace lshaz {

class ThreadRoleVerdicts;

// One cache line of one statically nameable region.
//
// Six places used to derive "who touches this memory, how often, from which
// thread" separately, each with its own gates, and every new hazard shape
// needed a seventh. The machine has one model: a line, an access set, a rate.
struct ContentionNode {
    std::string owner;      // record type, or file-scope global
    uint64_t lineIndex = 0; // which line of the region

    struct Resident {
        std::string field;
        uint64_t offsetBytes = 0;
        uint64_t sizeBytes = 0;
        bool isAtomic = false;
        bool plainScalar = false;
        unsigned declLine = 0;

        std::set<std::string> writers;
        std::set<std::string> readers;
        // basename:line of the stores. Survives inlining, where the writer's
        // symbol does not.
        std::set<std::string> writeSites;
        ThreadRoleSummary::FieldAccessFacts access;

        // A mutex, an array or a nested aggregate is mutated through its
        // address with no assignment anywhere, so for those "no writer"
        // describes the tracker rather than the program.
        bool writesObservable() const { return plainScalar || isAtomic; }

        bool written() const { return !writers.empty(); }
        bool read() const { return !readers.empty(); }

        // Site count is not recurrence: server.unixtime has one write site in
        // all of redis and was the most contended line in the program. The
        // other route is the writer's rate, which this node cannot see, so
        // the query supplies it.
        bool loopWritten() const { return access.loopWriteSites > 0; }
    };
    std::vector<Resident> residents;

    // Coherence invalidates a line, not a field, so the union is what the
    // protocol acts on.
    std::set<std::string> writers() const;
    std::set<std::string> readers() const;

    std::string declFile;
    unsigned declLine = 0;
};

// Every contended line in the program, keyed so iteration order is a
// property of the source and not of the scheduler.
struct ContentionGraph {
    std::map<std::pair<std::string, uint64_t>, ContentionNode> nodes;

    unsigned linesConsidered = 0;
    unsigned linesWithTraffic = 0;

    const ContentionNode *find(const std::string &owner,
                               uint64_t lineIndex) const;
};

// Built once, in the reduce phase, from merged layout and merged access
// facts. Never per TU: a TU that compiles the writer and not the reader
// would answer differently from one that compiles both, and the answer would
// then depend on how the sources were sharded.
ContentionGraph buildContentionGraph(const EscapeSummary &escape,
                                     const ThreadRoleSummary &facts,
                                     uint64_t lineBytes);

} // namespace lshaz
