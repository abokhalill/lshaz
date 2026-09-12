// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <clang/AST/ASTContext.h>
#include <clang/AST/DeclCXX.h>
#include <clang/Basic/SourceManager.h>

#include <llvm/Support/raw_ostream.h>

#include <cstdlib>
#include <string>

namespace lshaz {

// One naming convention shared by every producer of thread-role facts (call
// edges, entries, field writers), or attribution silently misses joins.
// Lambdas are the hard case: every call operator stringifies as
// "(anonymous class)::operator()", collapsing distinct lambdas into one node.
// Line:col disambiguates, and is source-stable and TU-local.
//
// A use outside any function has no thread-role node. Callers must filter
// that: a placeholder would insert a bogus node and corrupt writer
// attribution rather than fail.
inline std::string threadRoleNodeName(const clang::FunctionDecl *FD,
                                      const clang::ASTContext &Ctx) {
    if (!FD) {
        llvm::errs() << "lshaz: FATAL: threadRoleNodeName(nullptr); a caller "
                        "failed to filter a use outside any function. This is "
                        "an analysis defect, not a bad input.\n";
        std::abort();
    }
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
