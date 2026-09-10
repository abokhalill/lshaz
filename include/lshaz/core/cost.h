// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/severity.h"

#include <cstdint>
#include <string>
#include <vector>

namespace lshaz {

// Everything a finding costs is a product of estimated terms, in fixed
// point. Never floating point: the terms are summed and multiplied across
// shards whose arrival order changes with --jobs, and float addition is not
// associative, so the determinism contract would fail in a way no test on
// one machine reliably catches.
//
// Milli-units throughout. A rate of 1.05 executions per operation is 1050;
// a cost of 60 cycles is 60000.
using Milli = int64_t;
constexpr Milli kMilli = 1000;

constexpr Milli toMilli(int64_t whole) { return whole * kMilli; }

// Rounded product of two milli-quantities, back in milli. Rounds half away
// from zero so the result does not depend on the sign, and saturates rather
// than wrapping: an unestimated term multiplied by a large one must not
// produce a small number by overflow.
constexpr Milli milliMul(Milli a, Milli b) {
    if (a == 0 || b == 0) return 0;
    const __int128 p = static_cast<__int128>(a) * static_cast<__int128>(b);
    const __int128 half = (p < 0 ? -kMilli : kMilli) / 2;
    const __int128 r = (p + half) / kMilli;
    constexpr __int128 lim = INT64_MAX;
    if (r > lim) return INT64_MAX;
    if (r < -lim) return -INT64_MAX;
    return static_cast<Milli>(r);
}

// Fixed point rendered by hand rather than streamed as a double, because
// under a European locale a stream prints a comma and the output contract
// says a dot. Three copies of this had already appeared; the fourth caller
// is what made it a function.
inline std::string milliToText(Milli v) {
    const bool neg = v < 0;
    const int64_t a = neg ? -v : v;
    std::string out = (neg ? "-" : "") + std::to_string(a / kMilli) + ".";
    const int64_t frac = a % kMilli;
    if (frac < 100) out += "0";
    if (frac < 10) out += "0";
    return out + std::to_string(frac);
}

// A named factor in a finding's cost, with where it came from and whether
// it is a measurement or a stand-in. An unestablished term still
// participates in the product, because an optimistic bound that lands below
// the dismissal threshold is a sound dismissal; it just cannot raise a
// grade.
struct CostTerm {
    std::string name;
    Milli value = 0;
    bool established = false;
    std::string source;
};

struct CostEstimate {
    // Which hardware effect the product is an estimate of. Measurement comes
    // back keyed by this, so a residual learned from a contended field is
    // never applied to a sequential sweep. Without it on the finding the
    // key exists only inside the pipeline and no external measurement can
    // name what it corrected.
    std::string mechanism;

    // The specific line this estimate is of, in a form measurement can key
    // back to. Empty when the finding does not identify one.
    std::string site;

    std::vector<CostTerm> terms;
    Milli cyclesPerOp = 0;
    // Every term came from a measurement or a structural fact. False means
    // the number is an upper bound built on at least one stand-in.
    bool complete = false;

    bool empty() const { return terms.empty(); }

    void add(std::string name, Milli value, bool established,
             std::string source) {
        terms.push_back({std::move(name), value, established,
                         std::move(source)});
    }

    // Product of every term. Called once, after all terms are in.
    void settle() {
        Milli acc = kMilli;
        complete = !terms.empty();
        for (const auto &t : terms) {
            acc = milliMul(acc, t.value);
            complete = complete && t.established;
        }
        cyclesPerOp = terms.empty() ? 0 : acc;
    }
};

// Hardware the cost model reads. Every field is supplied by configuration,
// measured on the machine being scanned for. No part is named in this
// source and none is built in: a table of one vendor's numbers compiled
// into the analyzer makes every other target wrong by default, and makes
// adding a second machine a code change.
//
// A zero field is not a default, it is "unmeasured here". Any term that
// consumes one reports itself unestablished instead of substituting a
// plausible number, which is the ran-versus-never-ran property applied to
// the cost model.
struct MachineModel {
    std::string name;

    uint32_t lineBytes = 64;
    uint32_t l1dBytes = 32768;
    uint32_t llcBytes = 0;

    uint32_t cyclesL1 = 4;
    uint32_t cyclesL2 = 12;
    uint32_t cyclesLLC = 40;
    uint32_t cyclesHitmLocal = 0;
    uint32_t cyclesHitmRemote = 0;
    uint32_t cyclesDram = 0;
    uint32_t cyclesMispredict = 0;

    // Share of a miss hidden by other outstanding misses, in percent. The
    // term that explains why coherence findings on a syscall-bound server
    // measure zero: a miss overlapped with work already in flight costs
    // close to nothing, and no amount of structural evidence distinguishes
    // that from one on the critical path.
    uint32_t mlpOverlapPct = 0;

    bool hasCoherenceCost() const { return cyclesHitmLocal != 0; }
    bool hasOverlap() const { return mlpOverlapPct != 0; }
};

// Cycles the target spends per unit of its own work. This is a property of
// the workload, not of the hardware: redis at 2.4M operations per second
// across four 3.6GHz cores spends about 6000, and the same silicon running
// something else spends something else entirely. Keeping it in the machine
// struct conflated the two and would have shipped one benchmark's number as
// a hardware constant.
//
// Zero means unknown, and then no cost can be expressed as a share of an
// operation, so the ladder below declines to grade rather than borrowing a
// figure from elsewhere.
struct WorkloadModel {
    uint32_t cyclesPerOp = 0;

    // Cores that actually touch shared state under this deployment. Source
    // cannot know it: redis with io-threads 1 produced exactly zero HITM in
    // a fifteen second window while the analyzer, seeing the same code,
    // still predicted a cost. A runtime setting can remove the mechanism
    // outright and nothing in the AST says so. Zero means unconfigured, and
    // the sharer term stays a stand-in.
    uint32_t sharers = 0;

    bool known() const { return cyclesPerOp != 0; }
    bool sharersKnown() const { return sharers != 0; }
};

// Severity a cost supports, as a share of the workload's own per-operation
// budget. Fractions rather than absolute cycles, so the ladder holds on a
// target whose operations are ten times heavier.
Severity severityForCost(Milli cyclesPerOp, const WorkloadModel &w);

} // namespace lshaz
