// SPDX-License-Identifier: Apache-2.0
#include "lshaz/hypothesis/HypothesisConstructor.h"
#include "lshaz/hypothesis/HypothesisTemplate.h"

#include <functional>
#include <sstream>

namespace lshaz {

HazardClass HypothesisConstructor::mapRuleToHazardClass(std::string_view ruleID) {
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
    return HazardClass::CacheGeometry;
}

EvidenceTier HypothesisConstructor::inferEvidenceTier(const Diagnostic &finding) {
    const auto &ev = finding.structuralEvidence;
    auto has = [&](const char *k) { return ev.count(k) > 0; };
    auto eq  = [&](const char *k, const char *v) {
        auto it = ev.find(k);
        return it != ev.end() && it->second == v;
    };

    /* Provable from AST layout alone */
    if (has("sizeof") || has("cache_lines") || has("estimated_frame")) {
        if (eq("thread_escape", "true") || eq("atomics", "yes"))
            return EvidenceTier::Likely;
        return EvidenceTier::Proven;
    }

    if (eq("ordering", "seq_cst"))
        return EvidenceTier::Proven;

    if (has("atomic_writes"))
        return EvidenceTier::Likely;

    if (has("virtual_call"))
        return EvidenceTier::Likely;

    return EvidenceTier::Speculative;
}

std::vector<double> HypothesisConstructor::extractFeatures(const Diagnostic &finding) {
    std::vector<double> features;

    features.push_back(static_cast<double>(finding.severity));
    features.push_back(finding.confidence);
    features.push_back(static_cast<double>(finding.escalations.size()));

    /* Strip trailing 'B' suffix, parse to double, zero on failure. */
    auto extract = [&](const std::string &key) -> double {
        auto it = finding.structuralEvidence.find(key);
        if (it == finding.structuralEvidence.end()) return 0.0;
        std::string val = it->second;
        if (!val.empty() && val.back() == 'B') val.pop_back();
        try { return std::stod(val); } catch (...) { return 0.0; }
    };

    features.push_back(extract("sizeof"));
    features.push_back(extract("cache_lines"));
    features.push_back(extract("atomic_writes"));
    features.push_back(extract("mutable_fields"));
    features.push_back(extract("estimated_frame"));
    features.push_back(extract("depth"));
    features.push_back(extract("callees"));

    return features;
}

std::string HypothesisConstructor::generateHypothesisId(const Diagnostic &finding) {
    std::ostringstream os;
    os << "H-" << finding.ruleID << "-"
       << std::hash<std::string>{}(
              finding.location.file + ":" +
              std::to_string(finding.location.line));
    return os.str();
}

std::optional<LatencyHypothesis> HypothesisConstructor::construct(
    const Diagnostic &finding) {

    HazardClass hc = mapRuleToHazardClass(finding.ruleID);
    const auto *tmpl = HypothesisTemplateRegistry::instance().lookup(hc);
    if (!tmpl)
        return std::nullopt;

    LatencyHypothesis hyp;
    hyp.findingId = finding.ruleID + "-" + finding.location.file + ":" +
                    std::to_string(finding.location.line);
    hyp.hypothesisId = generateHypothesisId(finding);
    hyp.hazardClass = hc;
    hyp.H0 = tmpl->H0Template;
    hyp.H1 = tmpl->H1Template;
    hyp.primaryMetric = tmpl->primaryMetric;
    hyp.counterSet = tmpl->counterSet;
    hyp.minimumDetectableEffect = tmpl->defaultMDE;
    hyp.significanceLevel = 0.01;
    hyp.power = 0.90;
    hyp.requiredRuns = 0; /* computed from pilot variance */
    hyp.confoundControls = tmpl->confoundRequirements;
    hyp.structuralFeatures = extractFeatures(finding);
    hyp.structuralEvidence = finding.structuralEvidence;
    hyp.evidenceTier = inferEvidenceTier(finding);
    hyp.verdict = ExperimentVerdict::Pending;

    hyp.controlDescription =
        "Mitigated variant with structural hazard removed (see EXPERIMENT_SYNTHESIS.md §4.1)";
    hyp.treatmentDescription =
        "Original code preserving the structural hazard as detected";

    return hyp;
}

} // namespace lshaz
