// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <clang/AST/ASTContext.h>
#include <clang/AST/DeclCXX.h>
#include <clang/Basic/SourceManager.h>

#include <string>

namespace lshaz {

// Name-keyed thread-role facts need one naming convention shared by every
// producer (call edges, entries, field writers) or attribution silently
// misses joins. Lambdas are the hard case: every call operator in a
// function stringifies as "(anonymous class)::operator()", collapsing
// distinct lambdas into one node. Line:col disambiguates; source-stable,
// TU-local (lambdas never need cross-TU joining).
inline std::string threadRoleNodeName(const clang::FunctionDecl *FD,
                                      const clang::ASTContext &Ctx) {
    if (const auto *MD = llvm::dyn_cast<clang::CXXMethodDecl>(FD)) {
        const auto *RD = MD->getParent();
        if (RD && RD->isLambda()) {
            const auto &SM = Ctx.getSourceManager();
            auto ploc = SM.getPresumedLoc(SM.getFileLoc(RD->getLocation()));
            const clang::DeclContext *DC = RD->getDeclContext();
            while (DC && !llvm::isa<clang::FunctionDecl>(DC))
                DC = DC->getParent();
            std::string enc =
                DC ? llvm::cast<clang::FunctionDecl>(DC)
                         ->getQualifiedNameAsString()
                   : std::string("<toplevel>");
            std::string pos =
                ploc.isValid() ? std::to_string(ploc.getLine()) + ":" +
                                     std::to_string(ploc.getColumn())
                               : "0:0";
            return enc + "::lambda:" + pos;
        }
    }
    return FD->getQualifiedNameAsString();
}

} // namespace lshaz
