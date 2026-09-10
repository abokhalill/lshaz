// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/cost.h"

namespace lshaz {

Severity severityForCost(Milli cyclesPerOp, const WorkloadModel &w) {
    if (!w.known()) return Severity::Informational;
    const Milli pct = toMilli(w.cyclesPerOp) / 100;
    if (cyclesPerOp >= milliMul(pct, toMilli(3))) return Severity::Critical;
    if (cyclesPerOp >= pct) return Severity::High;
    if (cyclesPerOp >= pct / 6) return Severity::Medium;
    return Severity::Informational;
}

} // namespace lshaz
