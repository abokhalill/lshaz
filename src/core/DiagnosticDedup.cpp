#include "lshaz/core/DiagnosticDedup.h"

#include <algorithm>
#include <string>
#include <unordered_map>

namespace lshaz {

namespace {

// Struct-level rules emit diagnostics keyed by declaration location.
bool isStructLevelRule(const std::string &ruleID) {
    return ruleID == "FL001" || ruleID == "FL002" || ruleID == "FL040" ||
           ruleID == "FL041" || ruleID == "FL060" || ruleID == "FL061" ||
           ruleID == "FL090" || ruleID == "FL091";
}

std::string makeKey(const Diagnostic &d) {
    if (isStructLevelRule(d.ruleID)) {
        // Struct rules: keyed by declaration site.
        return d.ruleID + "\0" + d.location.file + "\0" +
               std::to_string(d.location.line);
    }
    // Function rules: keyed by qualified function name.
    if (!d.functionName.empty())
        return d.ruleID + "\0" + d.functionName + "\0" +
               std::to_string(d.location.line);
    // Fallback: full location.
    return d.ruleID + "\0" + d.location.file + "\0" +
           std::to_string(d.location.line) + "\0" +
           std::to_string(d.location.column);
}

} // anonymous namespace

void deduplicateDiagnostics(std::vector<Diagnostic> &diagnostics) {
    if (diagnostics.size() <= 1)
        return;

    // First pass: group by key, keep index of highest-confidence instance.
    std::unordered_map<std::string, size_t> bestIdx;
    std::vector<std::vector<size_t>> groups;
    std::unordered_map<std::string, size_t> keyToGroup;

    for (size_t i = 0; i < diagnostics.size(); ++i) {
        std::string key = makeKey(diagnostics[i]);
        auto it = keyToGroup.find(key);
        if (it == keyToGroup.end()) {
            keyToGroup[key] = groups.size();
            groups.push_back({i});
            bestIdx[key] = i;
        } else {
            groups[it->second].push_back(i);
            size_t prev = bestIdx[key];
            if (diagnostics[i].confidence > diagnostics[prev].confidence ||
                (diagnostics[i].confidence == diagnostics[prev].confidence &&
                 static_cast<uint8_t>(diagnostics[i].evidenceTier) <
                     static_cast<uint8_t>(diagnostics[prev].evidenceTier))) {
                bestIdx[key] = i;
            }
        }
    }

    // No duplicates found.
    if (groups.size() == diagnostics.size())
        return;

    // Second pass: merge escalations from duplicates into the best instance.
    std::vector<Diagnostic> deduped;
    deduped.reserve(groups.size());

    for (const auto &group : groups) {
        std::string key = makeKey(diagnostics[group[0]]);
        size_t best = bestIdx[key];
        Diagnostic merged = std::move(diagnostics[best]);

        // Collect unique escalation messages from all duplicates.
        for (size_t idx : group) {
            if (idx == best)
                continue;
            for (const auto &esc : diagnostics[idx].escalations) {
                bool exists = false;
                for (const auto &existing : merged.escalations) {
                    if (existing == esc) { exists = true; break; }
                }
                if (!exists)
                    merged.escalations.push_back(esc);
            }
        }

        if (group.size() > 1) {
            merged.escalations.push_back(
                "cross-TU: deduplicated from " +
                std::to_string(group.size()) + " translation unit(s)");
        }

        deduped.push_back(std::move(merged));
    }

    diagnostics = std::move(deduped);
}

} // namespace lshaz
