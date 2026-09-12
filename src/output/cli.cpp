// SPDX-License-Identifier: Apache-2.0
#include "lshaz/output/formatter.h"

#include <algorithm>
#include <map>
#include <sstream>

namespace lshaz {

namespace {

// One evidence value, bounded. Some keys carry every symbol that touched a
// type: on redis that is a 150-name line no terminal can show and no reader
// can use. The whole set is still in --format json.
constexpr size_t kMaxValue = 72;
constexpr size_t kMaxPairs = 8;

std::string clipValue(const std::string &v) {
    if (v.size() <= kMaxValue) return v;
    // Prefer cutting at a separator so a truncated list ends on a whole name.
    size_t cut = v.rfind(',', kMaxValue);
    if (cut == std::string::npos || cut < kMaxValue / 2) cut = kMaxValue;
    return v.substr(0, cut) + " ... +" +
           std::to_string(v.size() - cut) + " chars";
}

std::string evidenceLine(const Diagnostic &d) {
    std::ostringstream os;
    size_t shown = 0;
    for (const auto &[k, v] : d.structuralEvidence) {
        if (shown == kMaxPairs) break;
        if (shown) os << "; ";
        os << k << '=' << clipValue(v);
        ++shown;
    }
    if (d.structuralEvidence.size() > shown)
        os << "; +" << (d.structuralEvidence.size() - shown)
           << " more (--format json)";
    return os.str();
}

void summarize(std::ostringstream &os,
               const std::vector<Diagnostic> &diagnostics) {
    std::map<Severity, unsigned, std::greater<>> bySeverity;
    std::map<std::string, unsigned> byRule, byFile;
    for (const auto &d : diagnostics) {
        ++bySeverity[d.severity];
        ++byRule[d.ruleID];
        ++byFile[d.location.file];
    }

    os << "\nlshaz: " << diagnostics.size() << " finding(s)";
    for (const auto &[sev, n] : bySeverity)
        os << "  " << severityToString(sev) << ' ' << n;
    os << "\n";

    auto topN = [&](const char *label, const std::map<std::string, unsigned> &m,
                    size_t n) {
        if (m.size() < 2) return;
        std::vector<std::pair<std::string, unsigned>> v(m.begin(), m.end());
        // Count first, then name, so equal counts do not reorder run to run.
        std::sort(v.begin(), v.end(), [](const auto &a, const auto &b) {
            return a.second != b.second ? a.second > b.second
                                        : a.first < b.first;
        });
        os << "lshaz: " << label;
        for (size_t i = 0; i < v.size() && i < n; ++i)
            os << "  " << v[i].first << ' ' << v[i].second;
        if (v.size() > n) os << "  (+" << (v.size() - n) << " more)";
        os << "\n";
    };
    topN("by rule ", byRule, 5);
    topN("by file ", byFile, 5);
}

} // namespace

std::string CLIOutputFormatter::format(const std::vector<Diagnostic> &diagnostics) {
    std::ostringstream os;

    for (const auto &d : diagnostics) {
        os << d.location.file << ":" << d.location.line << ":"
           << d.location.column << ": ";

        os << "[" << severityToString(d.severity) << "] "
           << d.ruleID << ", " << d.title << "\n";

        os << "  Hardware: " << d.hardwareReasoning << "\n";
        os << "  Evidence: " << evidenceLine(d) << "\n";

        if (!d.mitigation.empty())
            os << "  Mitigation: " << d.mitigation << "\n";

        // Tier, not a percentage. Confidence orders findings inside one rule
        // and is not a probability, so rendering it as one invited a reading
        // the number cannot support. It stays in the JSON for tooling.
        os << "  Evidence tier: " << evidenceTierName(d.evidenceTier) << "\n";

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
        summarize(os, diagnostics);

    return os.str();
}

} // namespace lshaz
