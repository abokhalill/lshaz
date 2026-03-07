#pragma once

#include "lshaz/core/Diagnostic.h"
#include "lshaz/core/ExecutionMetadata.h"

#include <cstdint>
#include <string>
#include <vector>

namespace lshaz {

enum class ScanStatus : uint8_t {
    Clean       = 0,  // No findings
    Findings    = 1,  // Analysis succeeded, diagnostics emitted
    ParseError  = 2,  // Compilation/parse errors in source
    ToolError   = 3,  // Infrastructure failure
};

struct ScanResult {
    ScanStatus status = ScanStatus::Clean;
    std::vector<Diagnostic> diagnostics;
    ExecutionMetadata metadata;

    // Per-TU parse failure tracking.
    std::vector<std::string> failedTUs;

    // Counts for summary reporting.
    unsigned suppressedByCalibration = 0;
    unsigned suppressedByFilter      = 0;
    unsigned totalTUsAnalyzed        = 0;
    unsigned totalTUsFailed          = 0;
};

} // namespace lshaz
