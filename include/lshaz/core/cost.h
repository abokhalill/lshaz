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

// Hardware the cost model reads. Values come from reports/measured-constants
// and are keyed to a named machine, rather than living inside rule prose
// where nothing can compose them.
//
// A zero field is not a default, it is "unmeasured on this machine". Any
// term that consumes one reports itself unestablished instead of
// substituting a plausible number, which is the ran-versus-never-ran
// property applied to the cost model.
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

    // Total cycles the target spends per unit of work, which is what makes
    // cycles-per-op readable as a percentage without the analyzer knowing
    // anything about the workload.
    uint32_t cyclesPerOpBudget = 0;

    bool hasCoherenceCost() const { return cyclesHitmLocal != 0; }
    bool hasOverlap() const { return mlpOverlapPct != 0; }
    bool hasBudget() const { return cyclesPerOpBudget != 0; }
};

// The default is deliberately thin. Line size and the cache latencies are
// architectural and hold across x86-64 parts; the coherence and overlap
// figures are not, and are left unmeasured so a scan on an unknown machine
// reports its cost terms as estimates rather than inventing them.
const MachineModel &defaultMachine();

// Named model, or nullptr. Callers report the miss rather than falling back,
// since silently scanning under the wrong machine is worse than not
// costing at all.
const MachineModel *machineByName(const std::string &name);

// Severity a cost supports. Anchored to the per-op budget: on redis at 2.4M
// ops/s over four 3.6GHz cores the budget is about 6000 cycles, so 60
// cycles per operation is one percent of it.
Severity severityForCost(Milli cyclesPerOp, const MachineModel &m);

} // namespace lshaz
