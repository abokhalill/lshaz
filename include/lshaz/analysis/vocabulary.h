// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/analysis/thread_role.h"

#include <clang/AST/ASTContext.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Tooling/Tooling.h>

#include <memory>
#include <string>
#include <vector>

namespace lshaz {

// Pass one of the scan. Records structure only: which function forwards a
// call's result out, which hands a parameter onward, and which types those
// calls produced or consumed. No rules, no layout, no escape analysis, no IR.
//
// It exists because a project's allocator, lock and mapping vocabulary is not
// knowable inside one TU: a wrapper's body and its callers are in different
// files.

// The one implementation both passes use: pass one from its own consumer,
// pass two inline.
void collectAllocOwnership(clang::ASTContext &Ctx, ThreadRoleSummary &out);

// Every file the preprocessor opened for this TU, which is what decides
// whether a cached result is still the answer. Narrower and more exact than
// -MD, since it records what was read rather than what could be.
void collectReadFiles(clang::CompilerInstance &CI,
                      std::vector<std::string> &out);

class VocabularyAction : public clang::ASTFrontendAction {
public:
    VocabularyAction(ThreadRoleSummary &out, std::vector<std::string> *deps)
        : out_(out), deps_(deps) {}

    std::unique_ptr<clang::ASTConsumer>
    CreateASTConsumer(clang::CompilerInstance &CI,
                      llvm::StringRef file) override;
    void EndSourceFileAction() override;

private:
    ThreadRoleSummary &out_;
    std::vector<std::string> *deps_;
};

class VocabularyActionFactory : public clang::tooling::FrontendActionFactory {
public:
    std::unique_ptr<clang::FrontendAction> create() override {
        return std::make_unique<VocabularyAction>(facts_, &deps_);
    }
    const ThreadRoleSummary &facts() const { return facts_; }
    const std::vector<std::string> &deps() const { return deps_; }

private:
    ThreadRoleSummary facts_;
    std::vector<std::string> deps_;
};

} // namespace lshaz
