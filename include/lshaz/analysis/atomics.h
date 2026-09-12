// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <clang/AST/Decl.h>
#include <clang/AST/Type.h>

#include <string>
#include <vector>

namespace lshaz {

// Codebases that wrap atomics in an opaque struct or typedef are invisible to
// the std::atomic and _Atomic tests, so `atomic_type_names` in config names
// them. Every rule that reasons about atomics goes through this one predicate,
// or the ones that never build a CacheLineMap silently ignore the option.
//
// Name-based and pre-canonicalization by necessity: the wrapper is opaque, so
// the spelling is the only evidence there is.
inline bool isConfiguredAtomic(clang::QualType QT,
                               const std::vector<std::string> &names) {
    if (QT.isNull() || names.empty())
        return false;

    auto matches = [&](const std::string &n) {
        if (n.empty()) return false;
        for (const auto &cand : names)
            if (cand == n) return true;
        return false;
    };

    // Spelled record name, then the typedef chain, then the canonical
    // record -- a typedef'd anonymous struct only has the last of these.
    if (const auto *RT = QT->getAs<clang::RecordType>())
        if (matches(RT->getDecl()->getNameAsString()))
            return true;

    clang::QualType walk = QT;
    while (const auto *TDT = walk->getAs<clang::TypedefType>()) {
        if (matches(TDT->getDecl()->getNameAsString()))
            return true;
        walk = TDT->desugar();
    }

    if (const auto *RT = QT.getCanonicalType()->getAs<clang::RecordType>())
        if (matches(RT->getDecl()->getNameAsString()))
            return true;

    return false;
}

} // namespace lshaz
