// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/config.h"
#include "lshaz/core/diagnostic.h"
#include "lshaz/core/hot_path.h"
#include "lshaz/analysis/escape_summary.h"
#include "lshaz/analysis/thread_role.h"
#include "lshaz/analysis/striped_array_summary.h"
#include "lshaz/analysis/coverage.h"
#include "lshaz/analysis/memory.h"

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>

#include <string>
#include <unordered_set>
#include <vector>

namespace lshaz {

class LshazASTConsumer : public clang::ASTConsumer {
public:
    LshazASTConsumer(const Config &cfg,
                         std::vector<Diagnostic> &diagnostics,
                         EscapeSummary &escapeSummary,
                         ThreadRoleSummary &threadRoles,
                         StripedArraySummary &stripedArrays,
                         ScanCoverage &coverage,
                         MemorySummary &memory,
                         const std::unordered_set<std::string> &profileHotFuncs = {});

    void HandleTranslationUnit(clang::ASTContext &Ctx) override;

private:
    const Config &config_;
    HotPathOracle oracle_;
    std::vector<Diagnostic> &diagnostics_;
    EscapeSummary &escapeSummary_;
    ThreadRoleSummary &threadRoles_;
    StripedArraySummary &stripedArrays_;
    ScanCoverage &coverage_;
    MemorySummary &memory_;
};

} // namespace lshaz
