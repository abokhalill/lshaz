// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/diagnostic.h"

#include <vector>

namespace lshaz {

// Cross-TU diagnostic deduplication. A header included by N translation units
// produces N identical struct-level findings, and inline or template
// functions duplicate the same way.
//
// Key: (ruleID, file, line), falling back to (ruleID, functionName) where the
// location is unavailable. The survivor is the highest-confidence instance
// and inherits every duplicate's escalations.
void deduplicateDiagnostics(std::vector<Diagnostic> &diagnostics);

} // namespace lshaz
