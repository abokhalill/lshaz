#include "faultline/analysis/FaultlineASTConsumer.h"
#include "faultline/analysis/StructLayoutVisitor.h"
#include "faultline/core/RuleRegistry.h"

#include <clang/AST/Decl.h>
#include <clang/AST/DeclGroup.h>
#include <clang/Basic/SourceManager.h>

#include <unordered_set>

namespace faultline {

namespace {

bool isInSystemHeader(const clang::Decl *D, const clang::SourceManager &SM) {
    auto loc = D->getLocation();
    if (loc.isInvalid())
        return true;
    return SM.isInSystemHeader(SM.getSpellingLoc(loc));
}

} // anonymous namespace

FaultlineASTConsumer::FaultlineASTConsumer(
    const Config &cfg,
    std::vector<Diagnostic> &diagnostics,
    const std::unordered_set<std::string> &profileHotFuncs)
    : config_(cfg), oracle_(cfg), diagnostics_(diagnostics) {
    if (!profileHotFuncs.empty())
        oracle_.loadProfileHotFunctions(profileHotFuncs);
}

void FaultlineASTConsumer::HandleTranslationUnit(clang::ASTContext &Ctx) {
    auto *TU = Ctx.getTranslationUnitDecl();
    const auto &SM = Ctx.getSourceManager();

    std::unordered_set<std::string> disabled(config_.disabledRules.begin(),
                                              config_.disabledRules.end());

    // First pass: collect hot-path annotations.
    for (auto *D : TU->decls()) {
        if (isInSystemHeader(D, SM))
            continue;
        if (auto *FD = llvm::dyn_cast<clang::FunctionDecl>(D))
            oracle_.isFunctionHot(FD);
    }

    // Second pass: run enabled rules on non-system decls.
    const auto &rules = RuleRegistry::instance().rules();
    for (auto *D : TU->decls()) {
        if (isInSystemHeader(D, SM))
            continue;
        for (const auto &rule : rules) {
            if (disabled.count(std::string(rule->getID())))
                continue;
            rule->analyze(D, Ctx, oracle_, config_, diagnostics_);
        }
    }
}

} // namespace faultline
