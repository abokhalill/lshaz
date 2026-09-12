// SPDX-License-Identifier: Apache-2.0
#include "lshaz/hypothesis/interaction.h"
#include "lshaz/hypothesis/template.h"

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

} // namespace lshaz
