#pragma once

#include "faultline/core/Config.h"
#include "faultline/core/Diagnostic.h"
#include "faultline/core/HotPathOracle.h"

#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>

#include <string>
#include <unordered_set>
#include <vector>

namespace faultline {

class FaultlineASTConsumer : public clang::ASTConsumer {
public:
    FaultlineASTConsumer(const Config &cfg,
                         std::vector<Diagnostic> &diagnostics,
                         const std::unordered_set<std::string> &profileHotFuncs = {});

    void HandleTranslationUnit(clang::ASTContext &Ctx) override;

private:
    const Config &config_;
    HotPathOracle oracle_;
    std::vector<Diagnostic> &diagnostics_;
};

} // namespace faultline
