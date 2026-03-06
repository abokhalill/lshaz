#include "lshaz/core/PrecisionBudget.h"

#include <algorithm>
#include <unordered_map>

namespace lshaz {

PrecisionBudget::PrecisionBudget() {
    // Default policies: struct-level rules are high-confidence, allow unlimited.
    // Function-level heuristic rules get tighter budgets.
    auto add = [&](const char *id, unsigned maxEmit, double minConf,
                   Severity maxSev) {
        policies_[id] = {id, maxEmit, minConf, maxSev, 0.30};
    };

    // Struct-level rules: proven by layout, unlimited emission.
    add("FL001", 0, 0.40, Severity::Critical);
    add("FL002", 0, 0.50, Severity::Critical);

    // Atomic/ordering rules: moderate confidence needed.
    add("FL010", 50, 0.45, Severity::Critical);
    add("FL011", 50, 0.45, Severity::Critical);
    add("FL012", 50, 0.45, Severity::Critical);

    // Allocation/stack rules.
    add("FL020", 100, 0.40, Severity::Critical);
    add("FL021", 30, 0.35, Severity::High);

    // Indirect dispatch rules: higher FP risk, tighter budget.
    add("FL030", 30, 0.45, Severity::Critical);
    add("FL031", 30, 0.45, Severity::High);

    // Global state / queue rules.
    add("FL040", 0, 0.50, Severity::Critical);
    add("FL041", 0, 0.50, Severity::Critical);

    // Branch depth: speculative, cap at Medium unless IR-confirmed.
    add("FL050", 20, 0.30, Severity::High);

    // NUMA rules: highly speculative without runtime data.
    add("FL060", 20, 0.35, Severity::High);
    add("FL061", 20, 0.40, Severity::High);

    // Compound hazard: requires multiple signals (native structural).
    add("FL090", 0, 0.55, Severity::Critical);

    // Synthesized interaction: post-hoc correlation, tighter confidence floor.
    add("FL091", 0, 0.60, Severity::Critical);
}

void PrecisionBudget::setPolicy(const RulePrecisionPolicy &policy) {
    policies_[policy.ruleID] = policy;
}

const RulePrecisionPolicy *PrecisionBudget::getPolicy(
    const std::string &ruleID) const {
    auto it = policies_.find(ruleID);
    return it != policies_.end() ? &it->second : nullptr;
}

void PrecisionBudget::apply(std::vector<Diagnostic> &diagnostics) const {
    // Track per-rule emission counts for budget enforcement.
    std::unordered_map<std::string, unsigned> emissionCounts;

    for (auto &diag : diagnostics) {
        const auto *policy = getPolicy(diag.ruleID);
        if (!policy)
            continue;

        // Suppress below confidence floor.
        if (diag.confidence < policy->minConfidence && !diag.suppressed) {
            diag.suppressed = true;
            diag.escalations.push_back(
                "precision-budget: suppressed (confidence " +
                std::to_string(diag.confidence) + " < floor " +
                std::to_string(policy->minConfidence) + ")");
            continue;
        }

        // Cap severity.
        if (static_cast<uint8_t>(diag.severity) >
            static_cast<uint8_t>(policy->maxSeverity)) {
            diag.severity = policy->maxSeverity;
            diag.escalations.push_back(
                "precision-budget: severity capped to " +
                std::string(severityToString(policy->maxSeverity)));
        }

        // Emission budget enforcement.
        if (policy->maxEmissionsPerTU > 0) {
            unsigned &count = emissionCounts[diag.ruleID];
            if (count >= policy->maxEmissionsPerTU) {
                diag.severity = Severity::Informational;
                diag.escalations.push_back(
                    "precision-budget: demoted (emission limit " +
                    std::to_string(policy->maxEmissionsPerTU) + " exceeded)");
            }
            ++count;
        }
    }
}

} // namespace lshaz
