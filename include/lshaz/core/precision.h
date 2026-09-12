// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/diagnostic.h"
#include "lshaz/core/severity.h"

#include <string>
#include <unordered_map>
#include <vector>

namespace lshaz {

// Per-rule precision policy, applied to the post-dedup diagnostic vector.
// Over budget demotes to Informational; under the confidence floor
// suppresses.
struct RulePrecisionPolicy {
    std::string ruleID;
    unsigned maxEmissions      = 0;      // 0 = unlimited (global, post-dedup)
    double minConfidence       = 0.0;    // suppress below this
    Severity maxSeverity       = Severity::Critical; // cap severity
};

class PrecisionBudget {
public:
    // Load default policies for all known rules.
    PrecisionBudget();

    // Apply precision governance to diagnostics.
    // - Suppress diagnostics below rule's confidence floor
    // - Cap severity to rule's max severity
    // - Enforce per-rule global emission limits
    // - Track emission counts for budget enforcement
    void apply(std::vector<Diagnostic> &diagnostics) const;

    const RulePrecisionPolicy *getPolicy(const std::string &ruleID) const;

private:
    std::unordered_map<std::string, RulePrecisionPolicy> policies_;
};

} // namespace lshaz
