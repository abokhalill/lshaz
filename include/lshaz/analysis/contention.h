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

// One cache line of one statically nameable region, with everything the
// coherence protocol charges for.
//
// Six places in this codebase used to derive "who touches this memory, how
// often, from which thread" independently: the layout rule walking the AST
// per TU, the cross-TU join redoing it from field extents, the global write
// counter, the atomic rule, the striped-array summary, and the cost model
// re-parsing a semicolon-separated string of field pairs to recover the
// access sets it needed. Six views of one fact, each with its own gates, and
// a seventh required for every new shape.
//
// The machine has one model. A line, an access set, a rate. This is that.
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

        // A field the tracker can see every write of. A mutex, an array or a
        // nested aggregate is routinely mutated through its address with no
        // assignment anywhere, so "no writer" says something about the
        // tracker rather than about the program, and a rule that concludes
        // from silence there is concluding from its own blind spot.
        bool writesObservable() const { return plainScalar || isAtomic; }

        bool written() const { return !writers.empty(); }
        bool read() const { return !readers.empty(); }

        // A store inside a loop recurs on its own evidence. The other route
        // to recurrence is the writing function's own rate on the merged
        // call graph, which this node cannot see, so the query supplies it.
        //
        // Site count is not recurrence and must not be used as it. One store
        // statement inside an event loop is the case that matters:
        // server.unixtime has exactly one write site in all of redis and the
        // machine measured it as the most contended line in the program.
        bool loopWritten() const { return access.loopWriteSites > 0; }
    };
    std::vector<Resident> residents;

    // Union across residents, which is what the coherence protocol sees: it
    // invalidates a line, not a field.
    std::set<std::string> writers() const;
    std::set<std::string> readers() const;

    // Residents that carry traffic at all, in declaration order.
    std::vector<const Resident *> active() const;

    // Distinct fields on the line that are written, which is what separates
    // two fields colliding from one field genuinely shared.
    unsigned writtenFields() const;

    bool anyAtomic() const;
    bool spansFields() const { return residents.size() > 1; }

    // Where the region was declared, for reporting.
    std::string declFile;
    unsigned declLine = 0;

    // Priced once. Two findings on one line quoting two independently built
    // estimates of the same transfers is how the model contradicted itself.
    CostEstimate cost;
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
