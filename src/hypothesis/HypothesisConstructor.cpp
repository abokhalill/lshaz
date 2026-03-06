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
    auto ev = finding.structuralEvidence;

    // Structural facts that are provable from AST alone.
    if (ev.find("sizeof=") != std::string::npos ||
        ev.find("cache_lines=") != std::string::npos ||
        ev.find("estimated_frame=") != std::string::npos) {
        // Size-based properties are provable.
        if (ev.find("thread_escape=true") != std::string::npos ||
            ev.find("atomics=yes") != std::string::npos) {
            return EvidenceTier::Likely;
        }
        return EvidenceTier::Proven;
    }

    if (ev.find("ordering=seq_cst") != std::string::npos)
        return EvidenceTier::Proven;

    if (ev.find("atomic_writes=") != std::string::npos)
        return EvidenceTier::Likely;

    if (ev.find("virtual_call=") != std::string::npos)
        return EvidenceTier::Likely;

    return EvidenceTier::Speculative;
}

std::vector<double> HypothesisConstructor::extractFeatures(const Diagnostic &finding) {
    std::vector<double> features;

    features.push_back(static_cast<double>(finding.severity));
    features.push_back(finding.confidence);
    features.push_back(static_cast<double>(finding.escalations.size()));

    // Parse numeric values from structural evidence where available.
    auto extract = [&](const std::string &key) -> double {
        auto pos = finding.structuralEvidence.find(key + "=");
        if (pos == std::string::npos) return 0.0;
        pos += key.size() + 1;
        auto end = finding.structuralEvidence.find_first_of(";, ", pos);
        std::string val = finding.structuralEvidence.substr(
            pos, end == std::string::npos ? std::string::npos : end - pos);
        // Strip trailing 'B' for byte values.
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
    hyp.requiredRuns = 0; // Determined by pilot run.
    hyp.confoundControls = tmpl->confoundRequirements;
    hyp.structuralFeatures = extractFeatures(finding);
    hyp.evidenceTier = inferEvidenceTier(finding);
    hyp.verdict = ExperimentVerdict::Pending;

    hyp.controlDescription =
        "Mitigated variant with structural hazard removed (see EXPERIMENT_SYNTHESIS.md §4.1)";
    hyp.treatmentDescription =
        "Original code preserving the structural hazard as detected";

    return hyp;
}

} // namespace lshaz
