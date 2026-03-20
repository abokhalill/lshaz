// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/Config.h"
#include "lshaz/core/Diagnostic.h"
#include "lshaz/analysis/EscapeSummary.h"

#include <clang/Frontend/FrontendAction.h>
#include <clang/Tooling/Tooling.h>

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace lshaz {

class LshazAction : public clang::ASTFrontendAction {
public:
    LshazAction(const Config &cfg,
                    std::vector<Diagnostic> &diagnostics,
                    EscapeSummary &escapeSummary,
                    const std::unordered_set<std::string> &profileHotFuncs,
                    std::vector<std::string> &failedTUs);

    std::unique_ptr<clang::ASTConsumer>
    CreateASTConsumer(clang::CompilerInstance &CI,
                      llvm::StringRef file) override;

    void EndSourceFileAction() override;

private:
    const Config &config_;
    std::vector<Diagnostic> &diagnostics_;
    EscapeSummary &escapeSummary_;
    const std::unordered_set<std::string> &profileHotFuncs_;
    std::vector<std::string> &failedTUs_;
    std::string currentFile_;
};

class LshazActionFactory : public clang::tooling::FrontendActionFactory {
public:
    LshazActionFactory(const Config &cfg,
                           std::vector<Diagnostic> &diagnostics,
                           std::unordered_set<std::string> profileHotFuncs = {});

    std::unique_ptr<clang::FrontendAction> create() override;

    const std::vector<std::string> &failedTUs() const { return failedTUs_; }
    const EscapeSummary &escapeSummary() const { return escapeSummary_; }

private:
    const Config &config_;
    std::vector<Diagnostic> &diagnostics_;
    EscapeSummary escapeSummary_;
    std::unordered_set<std::string> profileHotFuncs_;
    std::vector<std::string> failedTUs_;
};

} // namespace lshaz
