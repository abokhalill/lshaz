#pragma once

#include "faultline/core/Diagnostic.h"
#include "faultline/hypothesis/HazardClass.h"

#include <optional>
#include <string>
#include <vector>

namespace faultline {

// Maps rule IDs to hazard classes for interaction detection.
std::optional<HazardClass> ruleToHazardClass(const std::string &ruleID);

// Site key for grouping diagnostics by location entity.
// Struct-level rules group by (file, line).
// Function-level rules group by functionName.
std::string diagnosticSiteKey(const Diagnostic &d);

// Post-analysis pass: correlate diagnostics from different rules at
// the same site. When eligible interaction pairs/triples are found,
// synthesize compound hazard diagnostics with site-specific evidence
// drawn from the participating diagnostics.
//
// This replaces the static 3-signal check in FL090 with a dynamic
// model driven by the InteractionEligibilityMatrix.
void synthesizeInteractions(std::vector<Diagnostic> &diagnostics);

} // namespace faultline
