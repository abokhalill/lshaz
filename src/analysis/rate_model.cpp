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

Milli rateForDepth(unsigned depth) {
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

    // Accumulated loop nesting, not a per-edge multiplier. Multiplying at
    // every edge compounds along the chain: a twelve-deep path through
    // loops reaches 10^36, the normaliser divides by that, and every other
    // function in the program rounds to zero. Capping total depth instead
    // bounds the range to four buckets, which is the resolution loop depth
    // actually supports. Claiming more would be invented precision.
    std::map<std::string, unsigned> depth;
    for (const auto &s2 : seeds)
        depth[s2] = 0;

    for (int round = 0; round < kRounds; ++round) {
        bool changed = false;
        for (const auto &[caller, callees] : facts.callEdges) {
            auto cit = depth.find(caller);
            if (cit == depth.end())
                continue;
            auto depths = facts.edgeLoopDepth.find(caller);
            for (const auto &callee : callees) {
                unsigned edge = 0;
                if (depths != facts.edgeLoopDepth.end()) {
                    auto d = depths->second.find(callee);
                    if (d != depths->second.end()) edge = d->second;
                }
                const unsigned reached =
                    std::min(cit->second + edge, kMaxLoopDepth);
                auto it = depth.find(callee);
                if (it == depth.end() || reached > it->second) {
                    depth[callee] = reached;
                    changed = true;
                }
            }
        }
        if (!changed)
            break;
    }

    // A function's own loops make it busy even when nothing calls it in one.
    for (const auto &[fn, own] : facts.ownLoopDepth) {
        auto it = depth.find(fn);
        if (it != depth.end())
            it->second = std::min(it->second + own, kMaxLoopDepth);
    }

    const Milli peak = rateForDepth(kMaxLoopDepth);
    for (const auto &[fn, d] : depth)
        rm.perOp[fn] = static_cast<Milli>(
            (static_cast<__int128>(rateForDepth(d)) * kMilli) / peak);

    return rm;
}

} // namespace lshaz
