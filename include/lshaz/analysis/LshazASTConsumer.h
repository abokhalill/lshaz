// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/Config.h"
#include "lshaz/core/Diagnostic.h"
#include "lshaz/core/HotPathOracle.h"
#include "lshaz/analysis/EscapeSummary.h"

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
                         const std::unordered_set<std::string> &profileHotFuncs = {});

    void HandleTranslationUnit(clang::ASTContext &Ctx) override;

private:
    const Config &config_;
    HotPathOracle oracle_;
    std::vector<Diagnostic> &diagnostics_;
    EscapeSummary &escapeSummary_;
};

} // namespace lshaz
