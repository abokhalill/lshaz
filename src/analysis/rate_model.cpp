// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/rate_model.h"
#include "lshaz/analysis/loop_shape.h"

#include <fnmatch.h>

#include <algorithm>

namespace lshaz {

namespace {

// Ceiling on an accumulated frequency. A chain of loops whose bounds the
// source all states reaches numbers no downstream term can use, and the
// normaliser would divide every other function to zero against it. Six
// decades is more range than the cost ladder resolves.
constexpr Milli kFreqCeiling = toMilli(1000000);

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

// Nesting depth read as a frequency, for edges reported by a producer that
// did not carry one.
Milli frequencyForDepth(unsigned depth) {
    Milli m = kMilli;
    for (unsigned i = 0; i < depth && m < kFreqCeiling; ++i)
        m = milliMul(m, toMilli(static_cast<int64_t>(kDefaultTripCount)));
    return m > kFreqCeiling ? kFreqCeiling : m;
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

    // Executions per program entry, propagated as a product of per-edge
    // frequencies. Each edge carries the source's own trip count where the
    // source states one, so a loop over sixteen elements contributes sixteen
    // and a loop over a runtime bound contributes the default.
    //
    // The previous form accumulated nesting depth and capped it at three,
    // giving four possible rates for the whole program. That is why a cost
    // model built on it could not rank: 87 of redis's 161 single-field
    // findings priced identically while the machine measured twenty to one
    // between the top contended line and the next. Depth is still merged for
    // hotness, which grades on nesting rather than on rate.
    //
    // Saturating at kFreqCeiling. Multiplying at every edge otherwise
    // compounds along a deep chain until the normaliser crushes everything
    // else to zero against it, which is the failure the depth cap was
    // avoiding by giving up the resolution entirely.
    std::map<std::string, Milli> freq;
    for (const auto &s2 : seeds)
        freq[s2] = kMilli;

    for (int round = 0; round < kRounds; ++round) {
        bool changed = false;
        for (const auto &[caller, callees] : facts.callEdges) {
            auto cit = freq.find(caller);
            if (cit == freq.end())
                continue;
            auto edges = facts.edgeFrequency.find(caller);
            auto depths = facts.edgeLoopDepth.find(caller);
            for (const auto &callee : callees) {
                Milli edge = kMilli;
                bool haveEdge = false;
                if (edges != facts.edgeFrequency.end()) {
                    auto f = edges->second.find(callee);
                    if (f != edges->second.end()) {
                        edge = f->second;
                        haveEdge = true;
                    }
                }
                // A shard built before edge frequencies existed, or an edge
                // whose caller was compiled by one, still reports depth. Fall
                // back rather than silently rating those call sites as though
                // they sat outside every loop.
                if (!haveEdge && depths != facts.edgeLoopDepth.end()) {
                    auto d = depths->second.find(callee);
                    if (d != depths->second.end())
                        edge = frequencyForDepth(d->second);
                }
                Milli reached = milliMul(cit->second, edge);
                if (reached > kFreqCeiling) reached = kFreqCeiling;
                auto it = freq.find(callee);
                if (it == freq.end() || reached > it->second) {
                    freq[callee] = reached;
                    changed = true;
                }
            }
        }
        if (!changed)
            break;
    }

    // A function's own loops make it busy even when nothing calls it in one.
    for (const auto &[fn, own] : facts.ownFrequency) {
        auto it = freq.find(fn);
        if (it == freq.end()) continue;
        Milli scaled = milliMul(it->second, own);
        it->second = scaled > kFreqCeiling ? kFreqCeiling : scaled;
    }
    for (const auto &[fn, own] : facts.ownLoopDepth) {
        if (facts.ownFrequency.count(fn)) continue;
        auto it = freq.find(fn);
        if (it == freq.end()) continue;
        Milli scaled = milliMul(it->second, frequencyForDepth(own));
        it->second = scaled > kFreqCeiling ? kFreqCeiling : scaled;
    }

    Milli peak = 0;
    for (const auto &[fn, f] : freq)
        peak = std::max(peak, f);
    if (peak <= 0)
        return rm;

    // Normalised so the busiest function runs about once per operation, with
    // a floor of one milli. Three decades of range, and below that the cost
    // ladder dismisses anyway, so the floor costs nothing and keeps a rarely
    // reached function distinguishable from one the model never rated.
    for (const auto &[fn, f] : freq) {
        Milli r = static_cast<Milli>(
            (static_cast<__int128>(f) * kMilli) / peak);
        rm.perOp[fn] = r < 1 ? 1 : r;
        if (f > kMilli)
            rm.repeated.insert(fn);
    }

    return rm;
}

} // namespace lshaz
