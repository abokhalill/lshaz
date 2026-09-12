// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/diagnostic.h"
#include "lshaz/core/metadata.h"
#include "lshaz/analysis/escape_summary.h"
#include "lshaz/analysis/thread_role.h"
#include "lshaz/analysis/striped_array_summary.h"
#include "lshaz/analysis/coverage.h"

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

    // Per-TU parse failure tracking. Parallel arrays: a path with no
    // reason is a failure we could not explain, which is itself a defect.
    std::vector<std::string> failedTUs;
    std::vector<std::string> failedTUErrors;

    // Cross-TU aggregated escape summary. Merged from all per-TU summaries.
    EscapeSummary escapeSummary;

    // Cross-TU thread-attribution facts and the roles reduced from them.
    ThreadRoleSummary threadRoleFacts;
    ThreadRoleVerdicts threadRoles;

    // Per-thread striped arrays, merged across TUs.
    StripedArraySummary stripedArrays;

    // What the scan examined, so a partially-analyzed codebase is
    // distinguishable from a clean one.
    ScanCoverage coverage;

    // Counts for summary reporting.
    unsigned suppressedByCalibration = 0;
    unsigned suppressedByFilter      = 0;
    unsigned totalTUsAnalyzed        = 0;
    unsigned vendoredTUsSkipped      = 0;
    unsigned outOfTreeSuppressed     = 0;
    unsigned totalTUsFailed          = 0;

    // Findings retired because an evidence source refuted a precondition,
    // which is a different outcome from a filter dropping them and has to
    // stay countable: it is the only number that says evidence disagreed
    // with the analysis rather than the analysis finding nothing.
    unsigned withdrawnByRefutation   = 0;
};

} // namespace lshaz
