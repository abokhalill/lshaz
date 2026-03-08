// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/pipeline/ScanRequest.h"
#include "lshaz/pipeline/ScanResult.h"

#include <functional>
#include <string>
#include <vector>

namespace clang { namespace tooling { class CompilationDatabase; } }

namespace lshaz {

using ProgressCallback = std::function<void(const std::string &stage,
                                            const std::string &detail)>;

class ScanPipeline {
public:
    explicit ScanPipeline(ProgressCallback progress = nullptr);

    // Primary entry point: loads compile DB from request.compileDBPath.
    ScanResult execute(const ScanRequest &request);

    // Execute with a caller-provided CompilationDatabase.
    // Used for single-file analysis with explicit compiler flags.
    ScanResult executeWithDB(
        const ScanRequest &request,
        const clang::tooling::CompilationDatabase &compDB,
        const std::vector<std::string> &sources);

private:
    ProgressCallback progress_;

    void report(const std::string &stage, const std::string &detail) const;

    // Shared implementation: both execute() and executeWithDB() converge here.
    ScanResult run(const ScanRequest &request,
                   const clang::tooling::CompilationDatabase &compDB,
                   const std::vector<std::string> &sources);
};

} // namespace lshaz
