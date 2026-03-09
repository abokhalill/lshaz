// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/LshazASTConsumer.h"
#include "lshaz/analysis/CallGraph.h"
#include "lshaz/analysis/StructLayoutVisitor.h"
#include "lshaz/core/RuleRegistry.h"

#include <clang/AST/Decl.h>
#include <clang/AST/DeclGroup.h>
#include <clang/AST/DeclTemplate.h>
#include <clang/Basic/SourceManager.h>

#include <algorithm>
#include <unordered_set>

namespace lshaz {

namespace {

bool isInSystemHeader(const clang::Decl *D, const clang::SourceManager &SM) {
    auto loc = D->getLocation();
    if (loc.isInvalid())
        return true;
    return SM.isInSystemHeader(SM.getSpellingLoc(loc));
}

} // anonymous namespace

LshazASTConsumer::LshazASTConsumer(
    const Config &cfg,
    std::vector<Diagnostic> &diagnostics,
    const std::unordered_set<std::string> &profileHotFuncs)
    : config_(cfg), oracle_(cfg), diagnostics_(diagnostics) {
    if (!profileHotFuncs.empty())
        oracle_.loadProfileHotFunctions(profileHotFuncs);
}

void LshazASTConsumer::HandleTranslationUnit(clang::ASTContext &Ctx) {
    // Skip TUs that had fatal parse errors — partial ASTs contain
    // error-recovery types that crash Clang's layout computation.
    if (Ctx.getDiagnostics().hasFatalErrorOccurred())
        return;

    auto *TU = Ctx.getTranslationUnitDecl();
    const auto &SM = Ctx.getSourceManager();

    // Collect all non-system declarations, recursing into namespaces
    // and linkage-spec blocks (extern "C").
    std::vector<clang::Decl *> decls;
    std::function<void(clang::DeclContext *)> collect =
        [&](clang::DeclContext *DC) {
            for (auto *D : DC->decls()) {
                if (isInSystemHeader(D, SM))
                    continue;
                if (auto *NS = llvm::dyn_cast<clang::NamespaceDecl>(D)) {
                    collect(NS);
                    continue;
                }
                if (auto *LS = llvm::dyn_cast<clang::LinkageSpecDecl>(D)) {
                    collect(LS);
                    continue;
                }
                // Skip dependent or invalid decls — getASTRecordLayout
                // crashes on records with unresolved template parameters.
                if (D->isInvalidDecl())
                    continue;
                if (auto *RD = llvm::dyn_cast<clang::CXXRecordDecl>(D)) {
                    if (RD->isDependentType())
                        continue;
                }
                if (auto *FD = llvm::dyn_cast<clang::FunctionDecl>(D)) {
                    if (FD->isDependentContext())
                        continue;
                }

                decls.push_back(D);
                // Recurse into record decls for nested types.
                if (auto *RD = llvm::dyn_cast<clang::CXXRecordDecl>(D)) {
                    if (RD->isCompleteDefinition())
                        collect(RD);
                }
                // Recurse into class templates to visit implicit
                // specializations — without this, struct-level rules
                // never see instantiated template types.
                if (auto *CTD = llvm::dyn_cast<clang::ClassTemplateDecl>(D)) {
                    for (auto *Spec : CTD->specializations()) {
                        if (Spec->isCompleteDefinition() &&
                            !Spec->isInvalidDecl() &&
                            !isInSystemHeader(Spec, SM)) {
                            decls.push_back(Spec);
                            collect(Spec);
                        }
                    }
                }
            }
        };
    collect(TU);

    std::unordered_set<std::string> disabled(config_.disabledRules.begin(),
                                              config_.disabledRules.end());

    // First pass: seed hot-path oracle.
    for (auto *D : decls) {
        if (auto *FD = llvm::dyn_cast<clang::FunctionDecl>(D))
            oracle_.isFunctionHot(FD);
    }

    // Pass 1.5: build call graph and propagate hotness transitively.
    CallGraph cg(Ctx);
    cg.buildFromTU(TU);
    oracle_.propagateViaCallGraph(cg);

    // Second pass: run enabled rules.
    size_t diagsBefore = diagnostics_.size();
    const auto &rules = RuleRegistry::instance().rules();
    for (auto *D : decls) {
        for (const auto &rule : rules) {
            if (disabled.count(std::string(rule->getID())))
                continue;
            rule->analyze(D, Ctx, oracle_, config_, diagnostics_);
        }
    }

    // Inline suppression: remove diagnostics with lshaz-suppress on their line
    // or the preceding line.  Format: // lshaz-suppress FL001,FL002
    auto isSuppressed = [&SM](const Diagnostic &diag) -> bool {
        if (diag.location.file.empty() || diag.location.line == 0)
            return false;
        auto fileRef = SM.getFileManager().getFileRef(diag.location.file);
        if (!fileRef)
            return false;
        auto fid = SM.translateFile(*fileRef);
        bool invalid = false;
        llvm::StringRef buf = SM.getBufferData(fid, &invalid);
        if (invalid || buf.empty())
            return false;

        // Check the diagnostic line and the line above it.
        for (unsigned checkLine = diag.location.line;
             checkLine >= 1 && checkLine >= diag.location.line - 1;
             --checkLine) {
            auto loc = SM.translateLineCol(fid, checkLine, 1);
            if (loc.isInvalid()) continue;
            unsigned offset = SM.getFileOffset(loc);
            auto eol = buf.find('\n', offset);
            llvm::StringRef line = buf.slice(offset,
                eol == llvm::StringRef::npos ? buf.size() : eol);
            auto pos = line.find("lshaz-suppress");
            if (pos == llvm::StringRef::npos) continue;
            llvm::StringRef tail = line.substr(pos + 14).ltrim();
            if (tail.empty())
                return true;  // bare suppress = suppress all
            // Parse comma-separated rule IDs.
            while (!tail.empty()) {
                auto [tok, rest] = tail.split(',');
                if (tok.trim() == diag.ruleID)
                    return true;
                tail = rest;
            }
        }
        return false;
    };

    auto it = std::remove_if(
        diagnostics_.begin() + static_cast<long>(diagsBefore),
        diagnostics_.end(), isSuppressed);
    diagnostics_.erase(it, diagnostics_.end());
}

} // namespace lshaz
