#include "lshaz/core/DiagnosticInteraction.h"
#include "lshaz/hypothesis/InteractionModel.h"

#include <algorithm>
#include <sstream>
#include <unordered_map>

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
    // Struct-level rules (FL001, FL002, FL060, FL090): group by file:line.
    // Function-level rules: group by functionName.
    // Hybrid: use file:line if available, fall back to functionName.
    if (!d.location.file.empty() && d.location.line > 0) {
        return d.location.file + ":" + std::to_string(d.location.line);
    }
    if (!d.functionName.empty())
        return "fn:" + d.functionName;
    return d.ruleID + ":" + d.title;
}

void synthesizeInteractions(std::vector<Diagnostic> &diagnostics) {
    const auto &matrix = InteractionEligibilityMatrix::instance();

    // Group diagnostics by site key.
    std::unordered_map<std::string, std::vector<size_t>> siteGroups;
    for (size_t i = 0; i < diagnostics.size(); ++i) {
        // Skip native compound (FL090) and synthesized interaction (FL091) diagnostics.
        if (diagnostics[i].ruleID == "FL090" || diagnostics[i].ruleID == "FL091")
            continue;
        auto hc = ruleToHazardClass(diagnostics[i].ruleID);
        if (!hc)
            continue;
        siteGroups[diagnosticSiteKey(diagnostics[i])].push_back(i);
    }

    // Also group struct-level diagnostics by struct name extracted
    // from structural evidence (struct=Name pattern).
    std::unordered_map<std::string, std::vector<size_t>> structGroups;
    for (size_t i = 0; i < diagnostics.size(); ++i) {
        if (diagnostics[i].ruleID == "FL090" || diagnostics[i].ruleID == "FL091")
            continue;
        const auto &ev = diagnostics[i].structuralEvidence;
        auto pos = ev.find("struct=");
        if (pos != std::string::npos) {
            auto start = pos + 7;
            auto end = ev.find(';', start);
            std::string structName = (end != std::string::npos)
                ? ev.substr(start, end - start)
                : ev.substr(start);
            if (!structName.empty())
                structGroups["struct:" + structName].push_back(i);
        }
    }

    // Merge struct groups into site groups (struct-level correlation
    // catches diagnostics at different lines but same struct).
    for (auto &[key, indices] : structGroups) {
        auto &merged = siteGroups[key];
        for (auto idx : indices) {
            bool dup = false;
            for (auto existing : merged)
                if (existing == idx) { dup = true; break; }
            if (!dup)
                merged.push_back(idx);
        }
    }

    std::vector<Diagnostic> synthesized;

    // Deterministic iteration: sort site keys to avoid unordered_map
    // iteration order nondeterminism.
    std::vector<std::string> sortedKeys;
    sortedKeys.reserve(siteGroups.size());
    for (const auto &[key, _] : siteGroups)
        sortedKeys.push_back(key);
    std::sort(sortedKeys.begin(), sortedKeys.end());

    for (const auto &siteKey : sortedKeys) {
        const auto &indices = siteGroups.at(siteKey);
        if (indices.size() < 2)
            continue;

        // Collect unique hazard classes at this site.
        struct HazardEntry {
            HazardClass hc;
            size_t diagIdx;
        };
        std::vector<HazardEntry> entries;
        for (auto idx : indices) {
            auto hc = ruleToHazardClass(diagnostics[idx].ruleID);
            if (!hc) continue;
            // Deduplicate by hazard class (keep highest confidence).
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

        // Check all pairs for eligible interactions.
        for (size_t i = 0; i < entries.size(); ++i) {
            for (size_t j = i + 1; j < entries.size(); ++j) {
                const auto *tmpl = matrix.findTemplate(
                    entries[i].hc, entries[j].hc);
                if (!tmpl)
                    continue;

                const auto &dA = diagnostics[entries[i].diagIdx];
                const auto &dB = diagnostics[entries[j].diagIdx];

                // Synthesize compound hazard diagnostic.
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

                // Location: use the first diagnostic's location.
                compound.location = dA.location;
                compound.functionName = dA.functionName.empty()
                    ? dB.functionName : dA.functionName;

                // Hardware reasoning: interaction mechanism.
                std::ostringstream hw;
                hw << "Compound hazard at site '" << siteKey << "': "
                   << tmpl->amplificationMechanism
                   << " Contributing rules: " << dA.ruleID
                   << " (" << hazardClassName(entries[i].hc) << ") and "
                   << dB.ruleID << " (" << hazardClassName(entries[j].hc)
                   << "). Individual effects compound super-additively "
                   << "under concurrent access.";
                compound.hardwareReasoning = hw.str();

                // Structural evidence: merge from both diagnostics.
                std::ostringstream ev;
                ev << "interaction=" << tmpl->id
                   << "; components=" << dA.ruleID << "+" << dB.ruleID
                   << "; site=" << siteKey
                   << "; threshold=" << tmpl->interactionThreshold
                   << "; evidence_A={" << dA.structuralEvidence << "}"
                   << "; evidence_B={" << dB.structuralEvidence << "}";
                compound.structuralEvidence = ev.str();

                compound.mitigation =
                    "Address both contributing hazards. Interaction effects "
                    "are super-additive: fixing either one reduces the "
                    "compound impact disproportionately. Prioritize the "
                    "higher-severity contributor first.";

                // Escalations: cite both contributing diagnostics.
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

        // Check triples for 3-way interaction templates.
        if (entries.size() >= 3) {
            for (const auto &tmpl : matrix.templates()) {
                if (tmpl.components.size() != 3)
                    continue;

                // Check if all 3 components are present at this site.
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

                std::ostringstream ev;
                ev << "interaction=" << tmpl.id
                   << "; components=" << dA.ruleID << "+"
                   << dB.ruleID << "+" << dC.ruleID
                   << "; site=" << siteKey;
                compound.structuralEvidence = ev.str();

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

    // Append synthesized interactions to diagnostics.
    for (auto &d : synthesized)
        diagnostics.push_back(std::move(d));
}

} // namespace lshaz
