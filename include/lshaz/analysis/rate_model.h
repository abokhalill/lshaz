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
// A hotness enum answers "does this run often"; a cost model needs "how many
// times". A store on the per-operation path and the same store on the
// per-connection path differ by orders of magnitude and both read as hot.
//
// Rates are relative, normalised so the busiest function is 1.0. Absolute
// counts would need a workload; relative ones need only the call graph, and
// every term in the cost expression is a ratio anyway. Loop levels supply a
// fixed multiplier in place of real branch probabilities, which bounds the
// error rather than eliminating it.
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
    // Not derived from perOp: that is normalised against the busiest
    // function, so anything far below the peak floors to the minimum whatever
    // its structure. Recurrence is structural and must not depend on what
    // else the program happens to contain.
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
