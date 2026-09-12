// SPDX-License-Identifier: Apache-2.0
#include "lshaz/hypothesis/hypothesis.h"
#include "lshaz/hypothesis/template.h"

#include <cmath>
#include <functional>
#include <sstream>

namespace lshaz {

HazardClass HypothesisConstructor::mapRuleToHazardClass(std::string_view ruleID) {
    if (ruleID == "FL001") return HazardClass::CacheGeometry;
    if (ruleID == "FL002") return HazardClass::FalseSharing;
    if (ruleID == "FL003") return HazardClass::StripedArray;
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

// Every dimension lands in [0,1], so the Euclidean distance between two
// findings is bounded by sqrt(D) and no dimension can dominate by virtue of
// its unit. Raw values cannot: a byte count and a nesting depth in the same
// sum means the byte count *is* the metric, and a radius that looks small is
// then narrower than a one-byte difference in struct size.
//
// Counts compress logarithmically because similarity here is a matter of
// order of magnitude. Two 300B records are alike; 300B and 300KB are not, and
// the gap between 300B and 301B is noise.
static double magnitude(double v, double scale) {
    if (v <= 0.0) return 0.0;
    const double x = std::log1p(v) / std::log1p(scale);
    return x > 1.0 ? 1.0 : x;
}

std::vector<double> HypothesisConstructor::extractFeatures(const Diagnostic &finding) {
    /* Strip trailing 'B' suffix, parse to double, zero on failure. */
    auto extract = [&](const std::string &key) -> double {
        auto it = finding.structuralEvidence.find(key);
        if (it == finding.structuralEvidence.end()) return 0.0;
        std::string val = it->second;
        if (!val.empty() && val.back() == 'B') val.pop_back();
        try { return std::stod(val); } catch (...) { return 0.0; }
    };

    // Confidence is deliberately absent. It is a per-rule ranking prior, so
    // its values are not comparable across rules, and feeding the number that
    // suppression reads back in as a feature that decides suppression closes
    // a loop nothing measures.
    return {
        static_cast<double>(finding.severity) /
            static_cast<double>(Severity::Critical),
        magnitude(static_cast<double>(finding.escalations.size()), 32),
        magnitude(extract("sizeof"), 1 << 16),
        magnitude(extract("cache_lines"), 64),
        magnitude(extract("atomic_writes"), 32),
        magnitude(extract("mutable_fields"), 64),
        magnitude(extract("estimated_frame"), 1 << 20),
        magnitude(extract("depth"), 16),
        magnitude(extract("callees"), 64),
    };
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
        "Mitigated variant with the structural hazard removed";
    hyp.treatmentDescription =
        "Original code preserving the structural hazard as detected";

    return hyp;
}

} // namespace lshaz
