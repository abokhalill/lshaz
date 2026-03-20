// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/LshazAction.h"
#include "lshaz/analysis/LshazASTConsumer.h"

#include <clang/Frontend/CompilerInstance.h>

namespace lshaz {

LshazAction::LshazAction(
    const Config &cfg,
    std::vector<Diagnostic> &diagnostics,
    EscapeSummary &escapeSummary,
    const std::unordered_set<std::string> &profileHotFuncs,
    std::vector<std::string> &failedTUs)
    : config_(cfg), diagnostics_(diagnostics), escapeSummary_(escapeSummary),
      profileHotFuncs_(profileHotFuncs), failedTUs_(failedTUs) {}

std::unique_ptr<clang::ASTConsumer>
LshazAction::CreateASTConsumer(clang::CompilerInstance & /*CI*/,
                                   llvm::StringRef file) {
    currentFile_ = file.str();
    return std::make_unique<LshazASTConsumer>(
        config_, diagnostics_, escapeSummary_, profileHotFuncs_);
}

void LshazAction::EndSourceFileAction() {
    auto &diags = getCompilerInstance().getDiagnostics();
    if (diags.hasFatalErrorOccurred() || diags.hasUncompilableErrorOccurred())
        failedTUs_.push_back(currentFile_);
}

// --- Factory ---

LshazActionFactory::LshazActionFactory(
    const Config &cfg, std::vector<Diagnostic> &diagnostics,
    std::unordered_set<std::string> profileHotFuncs)
    : config_(cfg), diagnostics_(diagnostics),
      profileHotFuncs_(std::move(profileHotFuncs)) {}

std::unique_ptr<clang::FrontendAction> LshazActionFactory::create() {
    return std::make_unique<LshazAction>(
        config_, diagnostics_, escapeSummary_, profileHotFuncs_, failedTUs_);
}

} // namespace lshaz
