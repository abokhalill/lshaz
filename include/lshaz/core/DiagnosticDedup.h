#pragma once

#include "lshaz/core/Diagnostic.h"

#include <vector>

namespace lshaz {

// Cross-TU diagnostic deduplication.
//
// When multiple TUs include the same header, struct-level rules (FL001,
// FL002, FL040, FL041, FL060, FL090, FL091) emit identical diagnostics per TU.
// Function-level rules may also duplicate if inline/template functions
// appear in multiple TUs.
//
// Deduplication key: (ruleID, location.file, location.line) for struct
// rules; (ruleID, functionName) for function rules when location is
// unavailable or differs across TUs.
//
// When duplicates exist, keeps the instance with highest confidence.
// Merges escalation traces from all instances.
void deduplicateDiagnostics(std::vector<Diagnostic> &diagnostics);

} // namespace lshaz
