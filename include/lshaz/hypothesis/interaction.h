// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/hypothesis/hazard.h"
#include "lshaz/hypothesis/pmu_counter.h"

#include <string>
#include <vector>

namespace lshaz {

struct InteractionTemplate {
    std::string id;                        // e.g., "IX-001"
    std::vector<HazardClass> components;
    std::string amplificationMechanism;
    PMUCounterSet counterSet;              // union of component counter sets
    // Excess over the sum of the individual effects, as a fraction of it.
    double interactionThreshold = 0.20;
};

// Which hazard-class pairs and triples are known to compound, and by what
// mechanism. Consulted by the FL091 synthesis pass.
class InteractionEligibilityMatrix {
public:
    static const InteractionEligibilityMatrix &instance();

    const InteractionTemplate *findTemplate(HazardClass a, HazardClass b) const;
    const std::vector<InteractionTemplate> &templates() const { return templates_; }

private:
    InteractionEligibilityMatrix();
    std::vector<InteractionTemplate> templates_;
};

} // namespace lshaz
