// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/rate_model.h"

#include <fnmatch.h>

#include <algorithm>

namespace lshaz {

namespace {

// Executions attributed to one loop level with no known trip count. The
// Ball and Larus backedge heuristic puts a loop backedge at about 88%
// taken, which is roughly eight iterations; ten is the same order and
// rounder. Being wrong here scales every rate by the same factor, and every
// term the cost model consumes is a ratio, so a uniform error cancels.
constexpr Milli kLoopTrips = 10;

// Nesting past this contributes nothing a bounded model can defend, and
// without a clamp a five-deep loop nest multiplies a rate by 100,000 and
// makes every other function round to zero.
constexpr unsigned kMaxLoopDepth = 3;

// Enough rounds for the deepest call chain in the corpora, and a hard stop
// so a recursive cycle settles at a bounded number rather than running to
// saturation.
constexpr int kRounds = 12;

bool matchesAny(const std::string &name,
                const std::vector<std::string> &patterns) {
    for (const auto &p : patterns)
        if (fnmatch(p.c_str(), name.c_str(), 0) == 0)
            return true;
    return false;
}

Milli loopMultiplier(unsigned depth) {
    Milli m = kMilli;
    for (unsigned i = 0; i < std::min(depth, kMaxLoopDepth); ++i)
        m = milliMul(m, toMilli(kLoopTrips));
    return m;
}

} // namespace

RateModel computeRateModel(const ThreadRoleSummary &facts,
                           const std::vector<std::string> &mainPatterns) {
    RateModel rm;

    // Same seed set the hotness relaxation uses: thread entries, main, and
    // the configured main globs. A program that spawns no threads still has
    // main, and dropping it there leaves every rate at zero.
    std::set<std::string> seeds = facts.threadEntries;
    for (const auto &[caller, callees] : facts.callEdges) {
        (void)callees;
        if (caller == "main" || matchesAny(caller, mainPatterns))
            seeds.insert(caller);
    }
    for (const auto &fn : facts.definedFunctions)
        if (fn == "main" || matchesAny(fn, mainPatterns))
            seeds.insert(fn);
    if (seeds.empty())
        return rm;

    std::map<std::string, Milli> rate;
    for (const auto &s : seeds)
        rate[s] = kMilli;

    for (int round = 0; round < kRounds; ++round) {
        std::map<std::string, Milli> next = rate;
        bool changed = false;
        for (const auto &[caller, callees] : facts.callEdges) {
            auto cit = rate.find(caller);
            if (cit == rate.end() || cit->second == 0)
                continue;
            auto depths = facts.edgeLoopDepth.find(caller);
            for (const auto &callee : callees) {
                unsigned depth = 0;
                if (depths != facts.edgeLoopDepth.end()) {
                    auto d = depths->second.find(callee);
                    if (d != depths->second.end()) depth = d->second;
                }
                const Milli contributed =
                    milliMul(cit->second, loopMultiplier(depth));
                // Max, not sum. Summing over callers double counts a helper
                // called from twenty places at the same rate, and the term
                // the cost model wants is how often this runs relative to
                // the busiest thing in the program, not a total.
                Milli &slot = next[callee];
                if (contributed > slot) {
                    slot = contributed;
                    changed = true;
                }
            }
        }
        rate.swap(next);
        if (!changed)
            break;
    }

    // Normalise so the busiest function is 1.0. Every consumer wants a
    // ratio, and an absolute count would need a workload the analyzer does
    // not have.
    Milli peak = 0;
    for (const auto &[fn, r] : rate) {
        (void)fn;
        peak = std::max(peak, r);
    }
    if (peak <= 0)
        return rm;

    for (const auto &[fn, r] : rate) {
        // Integer divide after scaling, so the result is exact and does not
        // depend on evaluation order across shards.
        rm.perOp[fn] = static_cast<Milli>(
            (static_cast<__int128>(r) * kMilli) / peak);
    }
    return rm;
}

} // namespace lshaz
