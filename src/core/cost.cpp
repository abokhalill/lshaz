// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/cost.h"

namespace lshaz {

namespace {

// Only what holds across x86-64 parts. Coherence and overlap are properties
// of a specific machine and are left at zero so a scan on an unnamed target
// says its cost is an estimate instead of asserting a figure it never saw.
const MachineModel kGeneric = [] {
    MachineModel m;
    m.name = "generic-x86-64";
    return m;
}();

// reports/measured-constants.md, 2026-09-07/08. Turbo off, performance
// governor, Linux 6.12.67. The coherence figure is the local HITM cost the
// c2c runs on this part attributed; the overlap figure is the residual that
// reconciles the predicted and measured cost of the server.unixtime store,
// which came out 10.4 predicted against 10.8 measured.
const MachineModel kCoffeeLake = [] {
    MachineModel m;
    m.name = "i9-9900K";
    m.llcBytes = 16u << 20;
    m.cyclesHitmLocal = 60;
    m.cyclesDram = 200;
    m.cyclesMispredict = 26;
    m.mlpOverlapPct = 80;
    // 2.4M ops/s over four 3.6GHz cores.
    m.cyclesPerOpBudget = 6000;
    return m;
}();

} // namespace

const MachineModel &defaultMachine() { return kGeneric; }

const MachineModel *machineByName(const std::string &name) {
    if (name == kCoffeeLake.name) return &kCoffeeLake;
    if (name == kGeneric.name) return &kGeneric;
    return nullptr;
}

Severity severityForCost(Milli cyclesPerOp, const MachineModel &m) {
    // Thresholds are fractions of the per-op budget, not absolute cycles, so
    // the same ladder holds on a target whose operations are ten times
    // heavier. Without a budget the ladder cannot be anchored and everything
    // grades Informational, which is the honest answer rather than reusing
    // one machine's numbers on another.
    if (!m.hasBudget()) return Severity::Informational;
    const Milli budget = toMilli(m.cyclesPerOpBudget);
    const Milli pct = budget / 100;
    if (cyclesPerOp >= milliMul(pct, toMilli(3))) return Severity::Critical;
    if (cyclesPerOp >= pct) return Severity::High;
    if (cyclesPerOp >= pct / 6) return Severity::Medium;
    return Severity::Informational;
}

} // namespace lshaz
