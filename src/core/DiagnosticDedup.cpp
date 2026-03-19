// SPDX-License-Identifier: Apache-2.0
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

// FL040 diagnostics carry the variable name in structuralEvidence["var"].
// The same global can be declared in different headers across TUs, so
// file+line is not a stable key. Use the variable identity instead.
bool isGlobalVarRule(const std::string &ruleID) {
    return ruleID == "FL040";
}

std::string makeKey(const Diagnostic &d) {
    if (isGlobalVarRule(d.ruleID)) {
        auto varIt = d.structuralEvidence.find("var");
        auto typeIt = d.structuralEvidence.find("type");
        if (varIt != d.structuralEvidence.end()) {
            std::string key = d.ruleID + "|" + varIt->second;
            if (typeIt != d.structuralEvidence.end())
                key += "|" + typeIt->second;
            return key;
        }
    }
    if (isStructLevelRule(d.ruleID)) {
        return d.ruleID + "|" + d.location.file + "|" +
               std::to_string(d.location.line);
    }
    if (!d.functionName.empty())
        return d.ruleID + "|" + d.functionName + "|" +
               std::to_string(d.location.line);
    return d.ruleID + "|" + d.location.file + "|" +
           std::to_string(d.location.line) + "|" +
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
            const auto &cur = diagnostics[i];
            const auto &prv = diagnostics[prev];
            bool better = false;
            if (cur.confidence > prv.confidence)
                better = true;
            else if (cur.confidence == prv.confidence) {
                if (static_cast<uint8_t>(cur.evidenceTier) <
                    static_cast<uint8_t>(prv.evidenceTier))
                    better = true;
                else if (cur.evidenceTier == prv.evidenceTier) {
                    // Stable tiebreaker: shortest file path, then
                    // lowest line. Guarantees deterministic canonical
                    // location regardless of shard arrival order.
                    if (cur.location.file.size() < prv.location.file.size())
                        better = true;
                    else if (cur.location.file.size() == prv.location.file.size()) {
                        if (cur.location.file < prv.location.file)
                            better = true;
                        else if (cur.location.file == prv.location.file &&
                                 cur.location.line < prv.location.line)
                            better = true;
                    }
                }
            }
            if (better)
                bestIdx[key] = i;
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
