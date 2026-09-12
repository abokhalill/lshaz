// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/config.h"
#include "lshaz/core/diagnostic.h"
#include "lshaz/analysis/escape_summary.h"
#include "lshaz/analysis/thread_role.h"
#include "lshaz/analysis/striped_array_summary.h"
#include "lshaz/analysis/coverage.h"
#include "lshaz/analysis/memory.h"

#include <clang/Basic/Diagnostic.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Tooling/Tooling.h>

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace lshaz {

struct FailedTU {
    std::string file;
    std::string error; // e.g., "'generated.h' file not found"
    // Name from the missing-include diagnostic's own argument, not parsed
    // back out of the rendered message. Empty when the TU failed for any
    // other reason.
    std::string missingHeader;
};

class LshazAction : public clang::ASTFrontendAction {
public:
    LshazAction(const Config &cfg,
                    std::vector<Diagnostic> &diagnostics,
                    EscapeSummary &escapeSummary,
                    ThreadRoleSummary &threadRoles,
                    StripedArraySummary &stripedArrays,
                    ScanCoverage &coverage,
                    MemorySummary &memory,
                    const std::unordered_set<std::string> &profileHotFuncs,
                    std::vector<FailedTU> &failedTUs,
                    std::vector<std::string> *deps);

    bool BeginSourceFileAction(clang::CompilerInstance &CI) override;

    std::unique_ptr<clang::ASTConsumer>
    CreateASTConsumer(clang::CompilerInstance &CI,
                      llvm::StringRef file) override;

    void EndSourceFileAction() override;

private:
    const Config &config_;
    std::vector<Diagnostic> &diagnostics_;
    EscapeSummary &escapeSummary_;
    ThreadRoleSummary &threadRoles_;
    StripedArraySummary &stripedArrays_;
    ScanCoverage &coverage_;
    MemorySummary &memory_;
    const std::unordered_set<std::string> &profileHotFuncs_;
    std::vector<FailedTU> &failedTUs_;
    std::vector<std::string> *deps_;
    std::string currentFile_;
    std::string firstError_;
    std::string missingHeader_;
};

class LshazActionFactory : public clang::tooling::FrontendActionFactory {
public:
    LshazActionFactory(const Config &cfg,
                           std::vector<Diagnostic> &diagnostics,
                           std::unordered_set<std::string> profileHotFuncs = {});

    std::unique_ptr<clang::FrontendAction> create() override;

    const std::vector<FailedTU> &failedTUs() const { return failedTUs_; }
    const EscapeSummary &escapeSummary() const { return escapeSummary_; }
    const ThreadRoleSummary &threadRoles() const { return threadRoles_; }
    const StripedArraySummary &stripedArrays() const { return stripedArrays_; }
    const ScanCoverage &coverage() const { return coverage_; }
    const MemorySummary &memory() const { return memory_; }
    // Files the TU read, for keying a cached result against later edits.
    const std::vector<std::string> &deps() const { return deps_; }

private:
    const Config &config_;
    std::vector<Diagnostic> &diagnostics_;
    EscapeSummary escapeSummary_;
    ThreadRoleSummary threadRoles_;
    StripedArraySummary stripedArrays_;
    ScanCoverage coverage_;
    MemorySummary memory_;
    std::vector<std::string> deps_;
    std::unordered_set<std::string> profileHotFuncs_;
    std::vector<FailedTU> failedTUs_;
};

} // namespace lshaz
