// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/HotPathOracle.h"
#include "lshaz/core/Config.h"
#include "lshaz/analysis/CallGraph.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Attr.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclCXX.h>
#include <clang/Basic/SourceManager.h>

#include <fnmatch.h>

namespace lshaz {

HotPathOracle::HotPathOracle(const Config &cfg) : config_(cfg) {}

bool HotPathOracle::isHot(const clang::Decl *D) const {
    if (const auto *FD = llvm::dyn_cast_or_null<clang::FunctionDecl>(D))
        return isFunctionHot(FD);
    return false;
}

bool HotPathOracle::isFunctionHot(const clang::FunctionDecl *FD) const {
    if (!FD)
        return false;

    if (hotCache_.count(FD))
        return true;

    if (hasHotAnnotation(FD) || matchesConfigPattern(FD) ||
        matchesProfileFunction(FD)) {
        hotCache_.insert(FD);
        return true;
    }

    return false;
}

void HotPathOracle::loadProfileHotFunctions(
    std::unordered_set<std::string> names) {
    profileHotFunctions_ = std::move(names);
}

bool HotPathOracle::matchesProfileFunction(
    const clang::FunctionDecl *FD) const {
    if (profileHotFunctions_.empty())
        return false;
    // Match by qualified name (demangled form).
    std::string qualName = FD->getQualifiedNameAsString();
    if (profileHotFunctions_.count(qualName))
        return true;
    // Match by bare name (perf symbols often lack namespace).
    std::string name = FD->getNameAsString();
    if (profileHotFunctions_.count(name))
        return true;
    return false;
}

void HotPathOracle::markHot(const clang::FunctionDecl *FD) {
    if (FD)
        hotCache_.insert(FD);
}

bool HotPathOracle::hasHotAnnotation(const clang::FunctionDecl *FD) const {
    for (const auto *A : FD->attrs()) {
        // [[clang::annotate("lshaz_hot")]]
        if (const auto *Ann = llvm::dyn_cast<clang::AnnotateAttr>(A)) {
            if (Ann->getAnnotation() == "lshaz_hot")
                return true;
        }
        // __attribute__((hot)) — GCC/Clang standard hot attribute
        if (llvm::isa<clang::HotAttr>(A))
            return true;
    }
    return false;
}

bool HotPathOracle::matchesConfigPattern(const clang::FunctionDecl *FD) const {
    std::string qualName = FD->getQualifiedNameAsString();

    for (const auto &pat : config_.hotFunctionPatterns) {
        if (fnmatch(pat.c_str(), qualName.c_str(), 0) == 0)
            return true;
    }

    const auto &SM = FD->getASTContext().getSourceManager();
    auto loc = FD->getLocation();
    if (loc.isValid()) {
        std::string filename = SM.getFilename(SM.getSpellingLoc(loc)).str();
        for (const auto &pat : config_.hotFilePatterns) {
            if (fnmatch(pat.c_str(), filename.c_str(), 0) == 0)
                return true;
        }
    }

    return false;
}

void HotPathOracle::propagateViaCallGraph(const CallGraph &cg,
                                           unsigned maxDepth) {
    // Snapshot current hot roots (avoid iterator invalidation).
    std::unordered_set<const clang::FunctionDecl *> roots(hotCache_);

    if (roots.empty())
        return;

    auto reachable = cg.transitiveCallees(roots, maxDepth);
    for (const auto *fn : reachable)
        hotCache_.insert(fn);
}

} // namespace lshaz
