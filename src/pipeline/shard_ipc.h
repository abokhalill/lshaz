// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/analysis/action.h"
#include "lshaz/analysis/coverage.h"
#include "lshaz/analysis/escape_summary.h"
#include "lshaz/analysis/striped_array_summary.h"
#include "lshaz/analysis/thread_role.h"
#include "lshaz/core/diagnostic.h"
#include "lshaz/pipeline/scan_result.h"

#include <string>
#include <vector>

namespace lshaz {

// The wire between a forked child and the parent. Everything a
// post-processing pass consumes has to appear on both sides, and the failure
// mode when it does not is the worst available: correct at --jobs 1, silently
// incomplete in parallel, and green whenever the scheduler happens to put the
// writer and the reader in one shard.
//
// Declared here rather than in the pipeline's anonymous namespace so the
// round-trip test can call the real functions instead of reimplementing the
// format.
struct ShardIPC {
    std::string src;   // TU this record covers; empty in whole-shard form
    int exitCode = -1;
    std::vector<FailedTU> failedTUs;
    std::vector<Diagnostic> diagnostics;
    EscapeSummary escapeSummary;
    ThreadRoleSummary threadRoles;
    StripedArraySummary striped;
    ScanCoverage coverage;
};

// Child exit status reserved for "analysis ran, IPC handoff failed". Distinct
// from 1 (analysis itself reported an error) so the parent does not blame the
// source when the temp filesystem is at fault.
constexpr int kShardIPCWriteFailed = 42;

// Shard hit its address-space cap. Distinct from a crash because the operator
// action differs: raise --memory-limit-mb or lower --jobs.
constexpr int kShardMemoryExhausted = 43;

std::string serializeShardResult(int exitCode,
                                 const std::vector<FailedTU> &failedTUs,
                                 const std::vector<Diagnostic> &diagnostics,
                                 const EscapeSummary &escapeSummary,
                                 const ThreadRoleSummary &threadRoles,
                                 const StripedArraySummary &striped,
                                 const ScanCoverage &coverage,
                                 const std::string &src = {});

bool deserializeShardResult(const std::string &json, ShardIPC &out);

} // namespace lshaz
