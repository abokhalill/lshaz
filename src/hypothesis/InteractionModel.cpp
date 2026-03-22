// SPDX-License-Identifier: Apache-2.0
#include "lshaz/hypothesis/InteractionModel.h"
#include "lshaz/hypothesis/HypothesisTemplate.h"

#include <algorithm>
#include <sstream>
#include <unordered_map>

namespace lshaz {

const InteractionEligibilityMatrix &InteractionEligibilityMatrix::instance() {
    static InteractionEligibilityMatrix mat;
    return mat;
}

InteractionEligibilityMatrix::InteractionEligibilityMatrix() {
    auto safeCounters = [](HazardClass hc) -> PMUCounterSet {
        const auto *tmpl = HypothesisTemplateRegistry::instance().lookup(hc);
        return tmpl ? tmpl->counterSet : PMUCounterSet{};
    };

    auto fsCounters   = safeCounters(HazardClass::FalseSharing);
    auto acCounters   = safeCounters(HazardClass::AtomicContention);
    auto aoCounters   = safeCounters(HazardClass::AtomicOrdering);
    auto numaCounters = safeCounters(HazardClass::NUMALocality);
    auto lockCounters = safeCounters(HazardClass::LockContention);
    auto heapCounters = safeCounters(HazardClass::HeapAllocation);
    auto cgCounters   = safeCounters(HazardClass::CacheGeometry);
    auto vdCounters   = safeCounters(HazardClass::VirtualDispatch);
    auto dcCounters   = safeCounters(HazardClass::DeepConditional);

    templates_ = {
        {
            "IX-001",
            {HazardClass::CacheGeometry, HazardClass::AtomicContention},
            "Multi-line RFO amplification: RFO traffic spans multiple cache "
            "lines, each requiring separate ownership transfer",
            cgCounters.merged(acCounters),
            0.20,
        },
        {
            "IX-002",
            {HazardClass::FalseSharing, HazardClass::AtomicContention},
            "Same-line invalidation + atomic write serialization: every write "
            "invalidates the line for all other cores, atomics prevent batching",
            fsCounters.merged(acCounters),
            0.20,
        },
        {
            "IX-003",
            {HazardClass::AtomicOrdering, HazardClass::AtomicContention},
            "Fence serialization + ownership transfer: seq_cst fence extends "
            "the window during which the line is exclusively held",
            aoCounters.merged(acCounters),
            0.20,
        },
        {
            "IX-004",
            {HazardClass::AtomicContention, HazardClass::NUMALocality},
            "Cross-socket RFO: remote RFO is 3-5x more expensive than "
            "intra-socket, compounding contention cost",
            acCounters.merged(numaCounters),
            0.20,
        },
        {
            "IX-005",
            {HazardClass::LockContention, HazardClass::HeapAllocation},
            "Allocation under lock: allocation latency extends critical "
            "section, increasing contention probability",
            lockCounters.merged(heapCounters),
            0.20,
        },
        {
            "IX-006",
            {HazardClass::VirtualDispatch, HazardClass::DeepConditional},
            "Compounding branch misprediction surface: virtual dispatch + "
            "deep conditionals exhaust BTB and pattern history",
            vdCounters.merged(dcCounters),
            0.20,
        },
        {
            "IX-007",
            {HazardClass::CacheGeometry, HazardClass::AtomicContention,
             HazardClass::NUMALocality},
            "Full compound hazard: large struct + atomics + NUMA produces "
            "multi-line cross-socket RFO storm",
            cgCounters.merged(acCounters).merged(numaCounters),
            0.20,
        },
    };
}

bool InteractionEligibilityMatrix::isEligible(HazardClass a,
                                               HazardClass b) const {
    for (const auto &t : templates_) {
        if (t.components.size() != 2) continue;
        if ((t.components[0] == a && t.components[1] == b) ||
            (t.components[0] == b && t.components[1] == a))
            return true;
    }
    return false;
}

const InteractionTemplate *InteractionEligibilityMatrix::findTemplate(
    HazardClass a, HazardClass b) const {

    for (const auto &t : templates_) {
        if (t.components.size() != 2) continue;
        if ((t.components[0] == a && t.components[1] == b) ||
            (t.components[0] == b && t.components[1] == a))
            return &t;
    }
    return nullptr;
}

std::vector<InteractionCandidate> InteractionDetector::detect(
    const std::vector<LatencyHypothesis> &hypotheses) {

    /* Group by file prefix from findingId ("FL0XX-/path:line"). */
    std::unordered_map<std::string, std::vector<size_t>> scopeGroups;

    for (size_t i = 0; i < hypotheses.size(); ++i) {
        const auto &id = hypotheses[i].findingId;
        auto dashPos = id.find('-');
        std::string scope = (dashPos != std::string::npos)
                                ? id.substr(dashPos + 1)
                                : id;
        auto colonPos = scope.rfind(':');
        if (colonPos != std::string::npos)
            scope = scope.substr(0, colonPos);
        scopeGroups[scope].push_back(i);
    }

    const auto &matrix = InteractionEligibilityMatrix::instance();
    std::vector<InteractionCandidate> candidates;

    for (const auto &[scope, indices] : scopeGroups) {
        if (indices.size() < 2) continue;

        for (size_t i = 0; i < indices.size(); ++i) {
            for (size_t j = i + 1; j < indices.size(); ++j) {
                HazardClass a = hypotheses[indices[i]].hazardClass;
                HazardClass b = hypotheses[indices[j]].hazardClass;

                if (!matrix.isEligible(a, b)) continue;

                InteractionCandidate cand;
                cand.declarationScope = scope;
                cand.findingIds = {
                    hypotheses[indices[i]].findingId,
                    hypotheses[indices[j]].findingId,
                };
                cand.hazardClasses = {a, b};
                cand.matchedTemplate = matrix.findTemplate(a, b);
                candidates.push_back(std::move(cand));
            }
        }
    }

    return candidates;
}

std::optional<LatencyHypothesis> InteractionDetector::constructInteractionHypothesis(
    const InteractionCandidate &candidate) {

    if (!candidate.matchedTemplate)
        return std::nullopt;
    if (candidate.hazardClasses.size() < 2)
        return std::nullopt;

    const auto &tmpl = *candidate.matchedTemplate;

    LatencyHypothesis hyp;

    std::ostringstream idStream;
    idStream << "H-" << tmpl.id;
    for (const auto &fid : candidate.findingIds)
        idStream << "-" << std::hash<std::string>{}(fid);
    hyp.hypothesisId = idStream.str();

    hyp.findingId = candidate.findingIds[0] + "+" + candidate.findingIds[1];
    hyp.hazardClass = HazardClass::HazardAmplification;

    std::ostringstream h0;
    h0 << "The combined effect of " << hazardClassName(candidate.hazardClasses[0])
       << " and " << hazardClassName(candidate.hazardClasses[1])
       << " on tail latency is <= sum of individual effects.";
    hyp.H0 = h0.str();

    std::ostringstream h1;
    h1 << "The combined effect of " << hazardClassName(candidate.hazardClasses[0])
       << " and " << hazardClassName(candidate.hazardClasses[1])
       << " on tail latency is > sum of individual effects by >= "
       << (tmpl.interactionThreshold * 100) << "% (interaction threshold). "
       << "Mechanism: " << tmpl.amplificationMechanism;
    hyp.H1 = h1.str();

    hyp.primaryMetric = {"p99.99_operation_latency_ns", "nanoseconds", "p99.99"};
    hyp.counterSet = tmpl.counterSet;
    hyp.minimumDetectableEffect = 0.05;
    hyp.significanceLevel = 0.01;
    hyp.power = 0.90;
    hyp.requiredRuns = 0;
    hyp.evidenceTier = EvidenceTier::Likely;
    hyp.verdict = ExperimentVerdict::Pending;

    hyp.controlDescription =
        "Both hazards mitigated (baseline)";
    hyp.treatmentDescription =
        "Both hazards present simultaneously";

    return hyp;
}

void InteractionCatalog::addResult(const std::string &templateId,
                                   const InteractionResult &result) {
    for (auto &entry : entries_) {
        if (entry.tmpl.id == templateId) {
            entry.results.push_back(result);
            double sum = 0.0;
            uint32_t count = 0;
            bool anySuperAdditive = false;
            for (const auto &r : entry.results) {
                sum += r.interactionD;
                ++count;
                if (r.superAdditive) anySuperAdditive = true;
            }
            entry.meanInteractionD = (count > 0) ? sum / count : 0.0;
            entry.confirmedSuperAdditive = anySuperAdditive;
            return;
        }
    }

    const auto &matrix = InteractionEligibilityMatrix::instance();
    for (const auto &t : matrix.templates()) {
        if (t.id == templateId) {
            InteractionCatalogEntry entry;
            entry.tmpl = t;
            entry.results.push_back(result);
            entry.meanInteractionD = result.interactionD;
            entry.confirmedSuperAdditive = result.superAdditive;
            entries_.push_back(std::move(entry));
            return;
        }
    }
}

std::optional<InteractionCatalogEntry> InteractionCatalog::lookup(
    const std::string &templateId) const {

    for (const auto &entry : entries_) {
        if (entry.tmpl.id == templateId)
            return entry;
    }
    return std::nullopt;
}

} // namespace lshaz
