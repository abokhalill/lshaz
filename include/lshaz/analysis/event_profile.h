// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace lshaz {

// Per-symbol counts for one hardware event.
//
// Coherence was the only mechanism we could check against a machine, so the
// branch, TLB and cache rules had never been compared to a counter at all.
// This is the missing half: point it at a perf report and ask whether the
// effect a rule accuses a function of actually happens there.
struct EventProfile {
    std::string event;
    std::string origin;

    // Shares, not raw counts, so a longer run or a different sample rate
    // doesn't change the answer.
    std::map<std::string, uint64_t> bySymbol;
    uint64_t total = 0;

    uint64_t samplesFor(const std::string &symbol) const {
        auto it = bySymbol.find(symbol);
        return it == bySymbol.end() ? 0 : it->second;
    }

    // Present at zero still means it ran. Absent means we never saw it.
    bool ran(const std::string &symbol) const {
        return bySymbol.count(symbol) != 0;
    }
};

// Reads `perf report --stdio --no-children -F overhead,symbol`.
//
// A file with no symbols in it fails rather than yielding an empty profile,
// because an empty profile reads as a machine that did nothing.
bool parsePerfReport(const std::string &text, EventProfile &out,
                     std::string &err);

} // namespace lshaz
