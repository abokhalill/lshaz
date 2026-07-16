// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/LshazAction.h"
#include "lshaz/analysis/LshazASTConsumer.h"

#include <clang/Basic/Diagnostic.h>
#include <clang/Frontend/CompilerInstance.h>
#include <llvm/ADT/SmallString.h>

namespace lshaz {

namespace {

// Forwarding consumer that captures the first error/fatal diagnostic message
// while delegating everything to the original consumer. Takes ownership of
// the original to prevent use-after-free when DiagnosticsEngine::setClient
// releases the previous Owner.
class ErrorCapture : public clang::DiagnosticConsumer {
public:
    ErrorCapture(std::unique_ptr<clang::DiagnosticConsumer> target,
                 std::string &out)
        : target_(std::move(target)), out_(out) {}

    void HandleDiagnostic(clang::DiagnosticsEngine::Level level,
                          const clang::Diagnostic &info) override {
        if (out_.empty() && level >= clang::DiagnosticsEngine::Error) {
            llvm::SmallString<256> buf;
            info.FormatDiagnostic(buf);
            out_ = std::string(buf.str());
        }
        target_->HandleDiagnostic(level, info);
    }

    void clear() override { target_->clear(); }
    void BeginSourceFile(const clang::LangOptions &lo,
                         const clang::Preprocessor *pp) override {
        target_->BeginSourceFile(lo, pp);
    }
    void EndSourceFile() override { target_->EndSourceFile(); }

private:
    std::unique_ptr<clang::DiagnosticConsumer> target_;
    std::string &out_;
};

} // anonymous namespace

LshazAction::LshazAction(
    const Config &cfg,
    std::vector<Diagnostic> &diagnostics,
    EscapeSummary &escapeSummary,
    ThreadRoleSummary &threadRoles,
    const std::unordered_set<std::string> &profileHotFuncs,
    std::vector<FailedTU> &failedTUs)
    : config_(cfg), diagnostics_(diagnostics), escapeSummary_(escapeSummary),
      threadRoles_(threadRoles),
      profileHotFuncs_(profileHotFuncs), failedTUs_(failedTUs) {}

bool LshazAction::BeginSourceFileAction(clang::CompilerInstance &CI) {
    firstError_.clear();
    auto &diags = CI.getDiagnostics();
    // takeClient() transfers ownership so setClient() won't destroy it.
    auto orig = diags.takeClient();
    if (!orig)
        return true;
    diags.setClient(new ErrorCapture(std::move(orig), firstError_),
                    /*ShouldOwnClient=*/true);
    return true;
}

std::unique_ptr<clang::ASTConsumer>
LshazAction::CreateASTConsumer(clang::CompilerInstance & /*CI*/,
                                   llvm::StringRef file) {
    currentFile_ = file.str();
    return std::make_unique<LshazASTConsumer>(
        config_, diagnostics_, escapeSummary_, threadRoles_, profileHotFuncs_);
}

void LshazAction::EndSourceFileAction() {
    auto &diags = getCompilerInstance().getDiagnostics();
    if (diags.hasFatalErrorOccurred() || diags.hasUncompilableErrorOccurred()) {
        FailedTU ftu;
        ftu.file = currentFile_;
        ftu.error = firstError_.empty() ? "compilation error" : firstError_;
        failedTUs_.push_back(std::move(ftu));
    }
}

// --- Factory ---

LshazActionFactory::LshazActionFactory(
    const Config &cfg, std::vector<Diagnostic> &diagnostics,
    std::unordered_set<std::string> profileHotFuncs)
    : config_(cfg), diagnostics_(diagnostics),
      profileHotFuncs_(std::move(profileHotFuncs)) {}

std::unique_ptr<clang::FrontendAction> LshazActionFactory::create() {
    return std::make_unique<LshazAction>(
        config_, diagnostics_, escapeSummary_, threadRoles_, profileHotFuncs_,
        failedTUs_);
}

} // namespace lshaz
