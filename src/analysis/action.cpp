// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/action.h"
#include "lshaz/analysis/ast_consumer.h"
#include "lshaz/analysis/vocabulary.h"

#include <clang/Basic/Diagnostic.h>
#include <clang/Basic/DiagnosticLex.h>
#include <clang/Frontend/CompilerInstance.h>
#include <llvm/ADT/SmallString.h>

namespace lshaz {

namespace {

// The include Clang could not resolve, taken from the diagnostic's own ID
// and argument. The rendered message carries no "fatal error:" prefix, so
// B001 spent its whole life matching text FormatDiagnostic never produces.
bool missingIncludeName(const clang::Diagnostic &info, std::string &out) {
    switch (info.getID()) {
    case clang::diag::err_pp_file_not_found:
    case clang::diag::err_pp_file_not_found_angled_include_not_fatal:
    case clang::diag::err_pp_file_not_found_typo_not_fatal:
        break;
    default:
        return false;
    }
    // getArgStdStr asserts on any other kind. All three spell the filename
    // as argument 0 today; checking keeps a future respelling a miss rather
    // than an abort inside a shard.
    if (info.getNumArgs() == 0 ||
        info.getArgKind(0) != clang::DiagnosticsEngine::ak_std_string)
        return false;
    out = info.getArgStdStr(0);
    return !out.empty();
}

// Forwarding consumer that captures the first error/fatal diagnostic message
// while delegating everything to the original consumer. Takes ownership of
// the original to prevent use-after-free when DiagnosticsEngine::setClient
// releases the previous Owner.
class ErrorCapture : public clang::DiagnosticConsumer {
public:
    ErrorCapture(std::unique_ptr<clang::DiagnosticConsumer> target,
                 std::string &out, std::string &missingHeader)
        : target_(std::move(target)), out_(out),
          missingHeader_(missingHeader) {}

    void HandleDiagnostic(clang::DiagnosticsEngine::Level level,
                          const clang::Diagnostic &info) override {
        if (level >= clang::DiagnosticsEngine::Error) {
            if (out_.empty()) {
                llvm::SmallString<256> buf;
                info.FormatDiagnostic(buf);
                out_ = std::string(buf.str());
            }
            if (missingHeader_.empty())
                missingIncludeName(info, missingHeader_);
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
    std::string &missingHeader_;
};

} // anonymous namespace

LshazAction::LshazAction(
    const Config &cfg,
    std::vector<Diagnostic> &diagnostics,
    EscapeSummary &escapeSummary,
    ThreadRoleSummary &threadRoles,
    StripedArraySummary &stripedArrays,
    ScanCoverage &coverage,
    MemorySummary &memory,
    const std::unordered_set<std::string> &profileHotFuncs,
    std::vector<FailedTU> &failedTUs,
    std::vector<std::string> *deps)
    : config_(cfg), diagnostics_(diagnostics), escapeSummary_(escapeSummary),
      threadRoles_(threadRoles), stripedArrays_(stripedArrays),
      coverage_(coverage), memory_(memory), profileHotFuncs_(profileHotFuncs),
      failedTUs_(failedTUs), deps_(deps) {}

bool LshazAction::BeginSourceFileAction(clang::CompilerInstance &CI) {
    firstError_.clear();
    missingHeader_.clear();
    auto &diags = CI.getDiagnostics();
    // takeClient() transfers ownership so setClient() won't destroy it.
    auto orig = diags.takeClient();
    if (!orig)
        return true;
    diags.setClient(
        new ErrorCapture(std::move(orig), firstError_, missingHeader_),
        /*ShouldOwnClient=*/true);
    return true;
}

std::unique_ptr<clang::ASTConsumer>
LshazAction::CreateASTConsumer(clang::CompilerInstance & /*CI*/,
                                   llvm::StringRef file) {
    currentFile_ = file.str();
    return std::make_unique<LshazASTConsumer>(
        config_, diagnostics_, escapeSummary_, threadRoles_, stripedArrays_,
        coverage_, memory_, profileHotFuncs_);
}

void LshazAction::EndSourceFileAction() {
    if (deps_)
        collectReadFiles(getCompilerInstance(), *deps_);
    auto &diags = getCompilerInstance().getDiagnostics();
    if (diags.hasFatalErrorOccurred() || diags.hasUncompilableErrorOccurred()) {
        FailedTU ftu;
        ftu.file = currentFile_;
        ftu.error = firstError_.empty() ? "compilation error" : firstError_;
        ftu.missingHeader = missingHeader_;
        failedTUs_.push_back(std::move(ftu));
    }
}

LshazActionFactory::LshazActionFactory(
    const Config &cfg, std::vector<Diagnostic> &diagnostics,
    std::unordered_set<std::string> profileHotFuncs)
    : config_(cfg), diagnostics_(diagnostics),
      profileHotFuncs_(std::move(profileHotFuncs)) {}

std::unique_ptr<clang::FrontendAction> LshazActionFactory::create() {
    return std::make_unique<LshazAction>(
        config_, diagnostics_, escapeSummary_, threadRoles_, stripedArrays_,
        coverage_, memory_, profileHotFuncs_, failedTUs_, &deps_);
}

} // namespace lshaz
