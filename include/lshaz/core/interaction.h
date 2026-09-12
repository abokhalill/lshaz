// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/diagnostic.h"
#include "lshaz/hypothesis/hazard.h"

#include <optional>
#include <string>
#include <vector>

namespace lshaz {

// Maps rule IDs to hazard classes for interaction detection.
std::optional<HazardClass> ruleToHazardClass(const std::string &ruleID);

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
