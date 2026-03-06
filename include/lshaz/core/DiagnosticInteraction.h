#pragma once

#include "lshaz/core/Diagnostic.h"
#include "lshaz/hypothesis/HazardClass.h"

#include <optional>
#include <string>
#include <vector>

namespace lshaz {

// Maps rule IDs to hazard classes for interaction detection.
std::optional<HazardClass> ruleToHazardClass(const std::string &ruleID);

// Site key for grouping diagnostics by location entity.
// Struct-level rules group by (file, line).
// Function-level rules group by functionName.
std::string diagnosticSiteKey(const Diagnostic &d);

// Post-analysis pass: correlate diagnostics from different rules at
// the same site. When eligible interaction pairs/triples are found,
// synthesize compound hazard diagnostics (FL091) with site-specific
// evidence drawn from the participating diagnostics.
//
// FL091 is distinct from FL090 (native structural compound hazard).
// FL090 fires from AST analysis on a single struct; FL091 is
// synthesized post-hoc from the InteractionEligibilityMatrix.
void synthesizeInteractions(std::vector<Diagnostic> &diagnostics);

} // namespace lshaz
