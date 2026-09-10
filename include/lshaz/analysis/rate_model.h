// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/analysis/thread_role.h"
#include "lshaz/core/cost.h"

#include <map>
#include <string>
#include <vector>

namespace lshaz {

// Expected executions of each function per unit of the target's work.
//
// A hotness enum answers "does this run often", which is not the question a
// cost model asks. It asks "how many times", and the difference is the
// whole gap between a hazard existing and a hazard mattering: on redis a
// store executing 1.05 times per operation and the same store executing
// once per connection differ by four orders of magnitude and grade
// identically today.
//
// Rates are relative, normalised so the busiest function in the program is
// 1.0. Absolute counts would need a workload; relative ones need only the
// call graph, and every term in the cost expression is a ratio anyway.
//
// The apex form of this reads LLVM BlockFrequencyInfo, which carries real
// branch probabilities. This propagates over the merged call graph with a
// fixed multiplier per loop level instead, which is wrong by a bounded
// factor rather than unboundedly, and needs no IR.
struct RateModel {
    std::map<std::string, Milli> perOp;

    // 0 for a function the graph never reached. Absent is not cold: a
    // function reached only through a pointer table has no recorded caller,
    // and the caller must decide whether that is a dismissal or a gap.
    Milli rateOf(const std::string &fn) const {
        auto it = perOp.find(fn);
        return it == perOp.end() ? 0 : it->second;
    }
    bool known(const std::string &fn) const { return perOp.count(fn) != 0; }

    // Highest rate over a set, which is what a field's access rate is: the
    // busiest of the functions that touch it.
    Milli maxRateOf(const std::set<std::string> &fns) const {
        Milli best = 0;
        for (const auto &f : fns) best = std::max(best, rateOf(f));
        return best;
    }
    // Functions the merged call graph reaches through at least one loop, so
    // they run more than once per program entry. Startup code is absent.
    //
    // Deliberately not derived from perOp. That is normalised against the
    // busiest function so it can be read as a share of an operation, and a
    // function six decades below the peak floors to the minimum whatever its
    // structure. Recurrence is a structural yes or no and must not depend on
    // what else the program happens to contain: a store in an event loop
    // recurs whether or not some unrelated startup routine sweeps a million
    // element array.
    std::set<std::string> repeated;

    bool recurrent(const std::set<std::string> &fns) const {
        for (const auto &f : fns)
            if (repeated.count(f)) return true;
        return false;
    }

    bool anyKnown(const std::set<std::string> &fns) const {
        for (const auto &f : fns)
            if (known(f)) return true;
        return false;
    }
};

// Seeds every entry point at 1 and propagates along call edges, multiplying
// by the loop nesting recorded at each edge. Ordered containers and fixed
// point throughout, and a bounded round count, so the result does not depend
// on shard arrival order or on how long a cycle takes to settle.
RateModel computeRateModel(const ThreadRoleSummary &facts,
                           const std::vector<std::string> &mainPatterns);

} // namespace lshaz
