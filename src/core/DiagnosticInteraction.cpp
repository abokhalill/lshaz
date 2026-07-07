// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/DiagnosticInteraction.h"
#include "lshaz/hypothesis/InteractionModel.h"

#include <algorithm>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace lshaz {

std::optional<HazardClass> ruleToHazardClass(const std::string &ruleID) {
    if (ruleID == "FL001") return HazardClass::CacheGeometry;
    if (ruleID == "FL002") return HazardClass::FalseSharing;
    if (ruleID == "FL010") return HazardClass::AtomicOrdering;
    if (ruleID == "FL011") return HazardClass::AtomicContention;
    if (ruleID == "FL012") return HazardClass::LockContention;
    if (ruleID == "FL020") return HazardClass::HeapAllocation;
    if (ruleID == "FL021") return HazardClass::StackPressure;
    if (ruleID == "FL030") return HazardClass::VirtualDispatch;
    if (ruleID == "FL031") return HazardClass::StdFunction;
    if (ruleID == "FL040") return HazardClass::GlobalState;
    if (ruleID == "FL041") return HazardClass::ContendedQueue;
    if (ruleID == "FL050") return HazardClass::DeepConditional;
    if (ruleID == "FL060") return HazardClass::NUMALocality;
    if (ruleID == "FL061") return HazardClass::CentralizedDispatch;
    if (ruleID == "FL090") return HazardClass::HazardAmplification;
    if (ruleID == "FL091") return HazardClass::SynthesizedInteraction;
    return std::nullopt;
}

std::string diagnosticSiteKey(const Diagnostic &d) {
    /* file:line preferred; fall back to functionName. */
    if (!d.location.file.empty() && d.location.line > 0) {
        return d.location.file + ":" + std::to_string(d.location.line);
    }
    if (!d.functionName.empty())
        return "fn:" + d.functionName;
    return d.ruleID + ":" + d.title;
}

void synthesizeInteractions(std::vector<Diagnostic> &diagnostics) {
    const auto &matrix = InteractionEligibilityMatrix::instance();

    // entity keys, not just file:line.
    std::unordered_map<std::string, std::vector<size_t>> siteGroups;
    auto addKeys = [&](const Diagnostic &d, size_t i) {
        if (!d.location.file.empty() && d.location.line > 0)
            siteGroups[d.location.file + ":" +
                       std::to_string(d.location.line)].push_back(i);
        auto tit = d.structuralEvidence.find("type_name");
        if (tit != d.structuralEvidence.end() && !tit->second.empty()) {
            const std::string &ts = tit->second; /* ';'-separated */
            size_t start = 0;
            while (start < ts.size()) {
                auto end = ts.find(';', start);
                auto len = (end == std::string::npos) ? std::string::npos
                                                      : end - start;
                std::string t = ts.substr(start, len);
                if (!t.empty())
                    siteGroups["type:" + t].push_back(i);
                if (end == std::string::npos) break;
                start = end + 1;
            }
        }
        if (!d.functionName.empty())
            siteGroups["fn:" + d.functionName].push_back(i);
    };

    for (size_t i = 0; i < diagnostics.size(); ++i) {
        /* Skip FL090/FL091 to avoid recursive synthesis. */
        if (diagnostics[i].ruleID == "FL090" || diagnostics[i].ruleID == "FL091")
            continue;
        if (diagnostics[i].suppressed)
            continue;
        if (!ruleToHazardClass(diagnostics[i].ruleID))
            continue;
        addKeys(diagnostics[i], i);
    }

    std::vector<Diagnostic> synthesized;

    /* one compound per (template, participant set): multi-key membership
       (site + type + fn) must not multiply findings. */
    std::unordered_set<std::string> emitted;
    auto participantKey = [&](const Diagnostic &d) {
        return d.ruleID + "@" + d.location.file + ":" +
               std::to_string(d.location.line);
    };

    std::vector<std::string> sortedKeys; /* deterministic iteration */
    sortedKeys.reserve(siteGroups.size());
    for (const auto &[key, _] : siteGroups)
        sortedKeys.push_back(key);
    std::sort(sortedKeys.begin(), sortedKeys.end());

    for (const auto &siteKey : sortedKeys) {
        const auto &indices = siteGroups.at(siteKey);
        if (indices.size() < 2)
            continue;

        struct HazardEntry {
            HazardClass hc;
            size_t diagIdx;
        };
        std::vector<HazardEntry> entries;
        for (auto idx : indices) {
            auto hc = ruleToHazardClass(diagnostics[idx].ruleID);
            if (!hc) continue;
            /* Dedup by class; keep highest confidence. */
            bool merged = false;
            for (auto &e : entries) {
                if (e.hc == *hc) {
                    if (diagnostics[idx].confidence >
                        diagnostics[e.diagIdx].confidence)
                        e.diagIdx = idx;
                    merged = true;
                    break;
                }
            }
            if (!merged)
                entries.push_back({*hc, idx});
        }

        if (entries.size() < 2)
            continue;

        for (size_t i = 0; i < entries.size(); ++i) {
            for (size_t j = i + 1; j < entries.size(); ++j) {
                const auto *tmpl = matrix.findTemplate(
                    entries[i].hc, entries[j].hc);
                if (!tmpl)
                    continue;

                const auto &dA = diagnostics[entries[i].diagIdx];
                const auto &dB = diagnostics[entries[j].diagIdx];

                std::string pk = participantKey(dA), pkB = participantKey(dB);
                if (pkB < pk) std::swap(pk, pkB);
                if (!emitted.insert(tmpl->id + "|" + pk + "|" + pkB).second)
                    continue;

                Diagnostic compound;
                compound.ruleID = "FL091";
                compound.title = "Synthesized Interaction: " +
                    std::string(hazardClassName(entries[i].hc)) + " × " +
                    std::string(hazardClassName(entries[j].hc));
                compound.severity = std::max(dA.severity, dB.severity);
                compound.confidence = std::min(dA.confidence, dB.confidence)
                                       * (1.0 + tmpl->interactionThreshold);
                if (compound.confidence > 1.0)
                    compound.confidence = 1.0;
                compound.evidenceTier = std::min(dA.evidenceTier,
                                                  dB.evidenceTier);

                compound.location = dA.location;
                compound.functionName = dA.functionName.empty()
                    ? dB.functionName : dA.functionName;

                std::ostringstream hw;
                hw << "Compound hazard at site '" << siteKey << "': "
                   << tmpl->amplificationMechanism
                   << " Contributing rules: " << dA.ruleID
                   << " (" << hazardClassName(entries[i].hc) << ") and "
                   << dB.ruleID << " (" << hazardClassName(entries[j].hc)
                   << "). Individual effects compound super-additively "
                   << "under concurrent access.";
                compound.hardwareReasoning = hw.str();

                compound.structuralEvidence = {
                    {"interaction", tmpl->id},
                    {"components", dA.ruleID + "+" + dB.ruleID},
                    {"site", siteKey},
                    {"threshold", std::to_string(tmpl->interactionThreshold)},
                    {"evidence_A", dA.serializeEvidence()},
                    {"evidence_B", dB.serializeEvidence()},
                };

                compound.mitigation =
                    "Address both contributing hazards. Interaction effects "
                    "are super-additive: fixing either one reduces the "
                    "compound impact disproportionately. Prioritize the "
                    "higher-severity contributor first.";

                compound.escalations.push_back(
                    "Contributing: " + dA.ruleID + " — " + dA.title);
                compound.escalations.push_back(
                    "Contributing: " + dB.ruleID + " — " + dB.title);
                compound.escalations.push_back(
                    "Interaction template: " + tmpl->id + " — " +
                    tmpl->amplificationMechanism);

                synthesized.push_back(std::move(compound));
            }
        }

        /* 3-way interaction templates. */
        if (entries.size() >= 3) {
            for (const auto &tmpl : matrix.templates()) {
                if (tmpl.components.size() != 3)
                    continue;

                bool allPresent = true;
                std::vector<size_t> matchedIndices;
                for (auto comp : tmpl.components) {
                    bool found = false;
                    for (size_t k = 0; k < entries.size(); ++k) {
                        if (entries[k].hc == comp) {
                            matchedIndices.push_back(entries[k].diagIdx);
                            found = true;
                            break;
                        }
                    }
                    if (!found) { allPresent = false; break; }
                }

                if (!allPresent || matchedIndices.size() < 3)
                    continue;

                const auto &dA = diagnostics[matchedIndices[0]];
                const auto &dB = diagnostics[matchedIndices[1]];
                const auto &dC = diagnostics[matchedIndices[2]];

                std::vector<std::string> pks = {participantKey(dA),
                                                participantKey(dB),
                                                participantKey(dC)};
                std::sort(pks.begin(), pks.end());
                if (!emitted.insert(tmpl.id + "|" + pks[0] + "|" + pks[1] +
                                    "|" + pks[2]).second)
                    continue;

                Diagnostic compound;
                compound.ruleID = "FL091";
                compound.title = "Synthesized Interaction: " +
                    std::string(hazardClassName(tmpl.components[0])) + " × " +
                    std::string(hazardClassName(tmpl.components[1])) + " × " +
                    std::string(hazardClassName(tmpl.components[2]));
                compound.severity = Severity::Critical;
                compound.confidence = std::min({dA.confidence, dB.confidence,
                                                 dC.confidence})
                                       * (1.0 + tmpl.interactionThreshold);
                if (compound.confidence > 1.0)
                    compound.confidence = 1.0;
                compound.evidenceTier = std::min({dA.evidenceTier,
                                                   dB.evidenceTier,
                                                   dC.evidenceTier});
                compound.location = dA.location;
                compound.functionName = dA.functionName;

                std::ostringstream hw;
                hw << "Triple compound hazard at site '" << siteKey << "': "
                   << tmpl.amplificationMechanism
                   << " Contributing rules: " << dA.ruleID << ", "
                   << dB.ruleID << ", " << dC.ruleID << ".";
                compound.hardwareReasoning = hw.str();

                compound.structuralEvidence = {
                    {"interaction", tmpl.id},
                    {"components", dA.ruleID + "+" + dB.ruleID + "+" + dC.ruleID},
                    {"site", siteKey},
                };

                compound.mitigation =
                    "Critical compound hazard. Address all three contributing "
                    "hazards. The interaction is super-additive: the combined "
                    "latency impact exceeds the sum of individual effects.";

                compound.escalations.push_back(
                    "Contributing: " + dA.ruleID + " — " + dA.title);
                compound.escalations.push_back(
                    "Contributing: " + dB.ruleID + " — " + dB.title);
                compound.escalations.push_back(
                    "Contributing: " + dC.ruleID + " — " + dC.title);
                compound.escalations.push_back(
                    "Interaction template: " + tmpl.id);

                synthesized.push_back(std::move(compound));
            }
        }
    }

    for (auto &d : synthesized)
        diagnostics.push_back(std::move(d));
}

} // namespace lshaz
