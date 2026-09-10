// SPDX-License-Identifier: Apache-2.0
#include "lshaz/output/formatter.h"

#include <sstream>

namespace lshaz {

std::string CLIOutputFormatter::format(const std::vector<Diagnostic> &diagnostics) {
    std::ostringstream os;

    for (const auto &d : diagnostics) {
        os << d.location.file << ":" << d.location.line << ":"
           << d.location.column << ": ";

        os << "[" << severityToString(d.severity) << "] "
           << d.ruleID << ", " << d.title << "\n";

        os << "  Hardware: " << d.hardwareReasoning << "\n";
        os << "  Evidence: " << d.serializeEvidence() << "\n";

        if (!d.mitigation.empty())
            os << "  Mitigation: " << d.mitigation << "\n";

        os << "  Confidence: " << static_cast<int>(d.confidence * 100) << "%"
           << " [" << evidenceTierName(d.evidenceTier) << "]\n";

        if (!d.cost.empty()) {
            os << "  Cost: ~" << milliToText(d.cost.cyclesPerOp)
               << " cycles per operation"
               << (d.cost.complete ? "" : " (upper bound, some terms estimated)")
               << "\n";
        }

        for (const auto &esc : d.escalations)
            os << "  Escalation: " << esc << "\n";

        os << "\n";
    }

    if (diagnostics.empty())
        os << "lshaz: no hazards detected.\n";
    else
        os << "lshaz: " << diagnostics.size() << " hazard(s) detected.\n";

    return os.str();
}

} // namespace lshaz
